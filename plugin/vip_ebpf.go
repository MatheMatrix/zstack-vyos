//go:build linux && !loong64
// loong64 (LoongArch ABI-v1) is excluded because its toolchain (go1.19_la_abi1)
// predates Go 1.21 and cannot compile cilium/ebpf v0.16.0 (uses maps/slices stdlib).
// See plugin/vip_ebpf_stub_loong64.go for the no-op fallback that keeps the
// VIP counter working via conntrack mode on that architecture.

package plugin

import (
	"bytes"
	_ "embed"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	log "github.com/sirupsen/logrus"
)

// vip_counter.o is compiled on the build machine and embedded here.
// Compile command (requires clang-12+ and libbpf-devel on build machine):
//   clang -O2 -g -target bpf -I/usr/include/bpf \
//         -c plugin/ebpf/vip_counter.c -o plugin/ebpf/vip_counter.o
//
//go:embed ebpf/vip_counter.o
var vipCounterBPFObj []byte

// vipStat mirrors struct vip_stat in vip_counter.c.
// PERCPU_HASH lookup returns []vipStat, one element per possible CPU.
type vipStat struct {
	Packets uint64
	Bytes   uint64
}

// vipEbpfObjects holds all BPF programs and maps loaded from vip_counter.o.
type vipEbpfObjects struct {
	coll *ebpf.Collection

	// Programs
	tcIngress *ebpf.Program
	tcEgress  *ebpf.Program

	// IPv4 maps
	vipSet          *ebpf.Map
	vipIngressStats *ebpf.Map
	vipEgressStats  *ebpf.Map

	// IPv6 maps
	vipSet6          *ebpf.Map
	vipIngressStats6 *ebpf.Map
	vipEgressStats6  *ebpf.Map
}

var (
	ebpfObjs        *vipEbpfObjects
	ebpfAttached    = make(map[string]bool) // NIC name → TC filter attached
	ebpfAttachMu    sync.Mutex
	ebpfWatcherDone chan struct{}
)

// initEbpfVipCounter loads the BPF collection (programs + maps) into the kernel.
// Called once from initVipCounterChains on supported platforms (amd64, arm64).
// On unsupported architectures (e.g. loong64) the stub returns an error and
// vip.go falls back to conntrack mode transparently.
// TC filters are attached lazily per-NIC by ensureEbpfOnInterface.
func initEbpfVipCounter() error {
	log.Infof("eBPF VIP counter: loading vip_counter.o from embedded bytes (%d bytes)", len(vipCounterBPFObj))
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(vipCounterBPFObj))
	if err != nil {
		return fmt.Errorf("ebpf: load spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("ebpf: new collection: %w", err)
	}

	objs := &vipEbpfObjects{
		coll:             coll,
		tcIngress:        coll.Programs["vip_count_ingress"],
		tcEgress:         coll.Programs["vip_count_egress"],
		vipSet:           coll.Maps["vip_set"],
		vipIngressStats:  coll.Maps["vip_ingress_stats"],
		vipEgressStats:   coll.Maps["vip_egress_stats"],
		vipSet6:          coll.Maps["vip_set6"],
		vipIngressStats6: coll.Maps["vip_ingress_stats6"],
		vipEgressStats6:  coll.Maps["vip_egress_stats6"],
	}
	for name, p := range map[string]*ebpf.Program{
		"vip_count_ingress": objs.tcIngress,
		"vip_count_egress":  objs.tcEgress,
	} {
		if p == nil {
			coll.Close()
			return fmt.Errorf("ebpf: program %q not found in object", name)
		}
	}
	for name, m := range map[string]*ebpf.Map{
		"vip_set":            objs.vipSet,
		"vip_ingress_stats":  objs.vipIngressStats,
		"vip_egress_stats":   objs.vipEgressStats,
		"vip_set6":           objs.vipSet6,
		"vip_ingress_stats6": objs.vipIngressStats6,
		"vip_egress_stats6":  objs.vipEgressStats6,
	} {
		if m == nil {
			coll.Close()
			return fmt.Errorf("ebpf: map %q not found in object", name)
		}
	}

	ebpfObjs = objs
	log.Infof("eBPF VIP counter: collection loaded OK — tcIngress.FD=%d tcEgress.FD=%d; attaching to NICs",
		objs.tcIngress.FD(), objs.tcEgress.FD())

	// Attach to all current physical NICs and start watching for new ones.
	attachEbpfToAllLinks()
	ebpfWatcherDone = make(chan struct{})
	startLinkWatcher(ebpfWatcherDone)
	log.Infof("eBPF VIP counter: ready — TC filters attached, link watcher started")
	return nil
}

// ensureEbpfOnInterface attaches clsact qdisc and BPF TC filters to iface if
// not already done.  Safe to call multiple times (idempotent).
func ensureEbpfOnInterface(iface string) {
	if ebpfObjs == nil {
		return
	}
	ebpfAttachMu.Lock()
	defer ebpfAttachMu.Unlock()
	if ebpfAttached[iface] {
		log.Debugf("eBPF: TC filters already attached on %s, skipping", iface)
		return
	}
	if err := attachTCFilters(iface, ebpfObjs); err != nil {
		log.Warnf("eBPF: failed to attach TC filters on %s: %v", iface, err)
		return
	}
	ebpfAttached[iface] = true
	log.Infof("eBPF: TC filters attached on %s", iface)
}

// attachTCFilters attaches BPF ingress/egress filters to iface.
// Migrates from sch_ingress to clsact if needed; otherwise creates clsact fresh.
// FilterReplace makes attachment idempotent across zvr restarts.
func attachTCFilters(iface string, objs *vipEbpfObjects) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("link %q: %w", iface, err)
	}
	idx := link.Attrs().Index

	clsactOK, migrated := ensureClsactQdisc(link)

	var ingressParent, egressParent uint32
	if clsactOK {
		ingressParent = netlink.HANDLE_MIN_INGRESS // ffff:fff2
		egressParent = netlink.HANDLE_MIN_EGRESS   // ffff:fff3
	} else if migrated {
		// sch_ingress was deleted but clsact add failed — ingress qdisc is gone.
		// Falling back to ffff: would attach to a non-existent qdisc; abort instead.
		return fmt.Errorf("clsact migration failed on %s: sch_ingress removed but clsact unavailable", iface)
	} else {
		log.Warnf("ebpf: clsact unavailable on %s; falling back to existing sch_ingress/root qdiscs", iface)
		ingressParent = netlink.MakeHandle(0xffff, 0) // ffff: (sch_ingress)
		egressParent = findRootQdiscHandle(link)
	}

	type filterSpec struct {
		parent uint32
		prog   *ebpf.Program
		name   string
	}
	filters := []filterSpec{
		{ingressParent, objs.tcIngress, "vip_ingress"},
	}
	if egressParent != 0 {
		filters = append(filters, filterSpec{egressParent, objs.tcEgress, "vip_egress"})
	}

	for _, f := range filters {
		progFD := f.prog.FD()
		log.Infof("eBPF: attaching filter %s on %s parent=0x%x fd=%d", f.name, iface, f.parent, progFD)
		filter := &netlink.BpfFilter{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: idx,
				Parent:    f.parent,
				Handle:    netlink.MakeHandle(0, 1),
				Protocol:  syscall.ETH_P_ALL,
				Priority:  1,
			},
			Fd:           progFD,
			Name:         f.name,
			DirectAction: true,
		}
		if err := netlink.FilterReplace(filter); err != nil {
			if f.name == "vip_egress" {
				// Non-fatal: ingress counting still works.
				log.Warnf("eBPF: filter replace %s on %s failed (egress counting disabled): %v", f.name, iface, err)
				continue
			}
			return fmt.Errorf("filter replace %s: %w", f.name, err)
		}
		log.Infof("eBPF: filter %s on %s attached successfully", f.name, iface)
	}

	// Remove stale egress filter on root HTB left over from before clsact migration.
	if migrated && clsactOK {
		removeStaleEgressFilter(link)
	}

	return nil
}

// findRootQdiscHandle returns the TC handle of the egress root qdisc on link,
// or 0 if none can be found.
func findRootQdiscHandle(link netlink.Link) uint32 {
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return 0
	}
	for _, q := range qdiscs {
		if q.Attrs().Parent == netlink.HANDLE_ROOT {
			return q.Attrs().Handle
		}
	}
	return 0
}

// ensureClsactQdisc ensures clsact qdisc exists on link at handle ffff:.
// If sch_ingress already occupies ffff:, it is deleted first (migrated=true).
// Returns (ok=true, migrated) on success; (false, false) if clsact cannot be created.
func ensureClsactQdisc(link netlink.Link) (ok bool, migrated bool) {
	idx := link.Attrs().Index
	clsactHandle := netlink.MakeHandle(0xffff, 0)

	qdiscs, err := netlink.QdiscList(link)
	if err == nil {
		for _, q := range qdiscs {
			if q.Attrs().Handle != clsactHandle {
				continue
			}
			if q.Type() == "clsact" {
				return true, false // already present, nothing to do
			}
			if q.Type() == "ingress" {
				log.Infof("eBPF: migrating %s: replacing sch_ingress with clsact to support egress BPF filters", link.Attrs().Name)
				_ = netlink.QdiscDel(q)
				migrated = true
				break
			}
		}
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: idx,
			Handle:    clsactHandle,
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscAdd(qdisc); err != nil {
		log.Warnf("ebpf: add clsact on %s: %v", link.Attrs().Name, err)
		return false, migrated
	}
	return true, migrated
}

// removeStaleEgressFilter removes a vip_egress BPF filter at prio=1 from the
// root qdisc, left over from before clsact migration.
func removeStaleEgressFilter(link netlink.Link) {
	rootHandle := findRootQdiscHandle(link)
	if rootHandle == 0 {
		return
	}
	filters, err := netlink.FilterList(link, rootHandle)
	if err != nil {
		return
	}
	for _, f := range filters {
		bpf, ok := f.(*netlink.BpfFilter)
		if !ok {
			continue
		}
		if bpf.Name == "vip_egress" {
			_ = netlink.FilterDel(f)
			log.Infof("ebpf: removed stale vip_egress filter from root qdisc on %s", link.Attrs().Name)
		}
	}
}

// isMonitorableLink returns true for physical Ethernet NICs that should have
// eBPF TC filters attached.  Excludes loopback, virtual, and QoS-internal devices.
func isMonitorableLink(link netlink.Link) bool {
	attrs := link.Attrs()
	if attrs.Flags&net.FlagLoopback != 0 {
		return false
	}
	if attrs.EncapType != "ether" {
		return false
	}
	name := attrs.Name
	for _, prefix := range []string{
		"ifb", "dummy", "sit", "gre", "tun", "tap",
		"veth", "virbr", "docker", "br-",
	} {
		if strings.HasPrefix(name, prefix) {
			return false
		}
	}
	return true
}

// attachEbpfToAllLinks attaches eBPF TC filters to all current monitorable NICs.
func attachEbpfToAllLinks() {
	links, err := netlink.LinkList()
	if err != nil {
		log.Warnf("ebpf: LinkList: %v", err)
		return
	}
	for _, link := range links {
		if isMonitorableLink(link) {
			ensureEbpfOnInterface(link.Attrs().Name)
		}
	}
}

// startLinkWatcher subscribes to netlink link events and attaches eBPF filters
// on new NICs or cleans up state when NICs are removed.
func startLinkWatcher(done <-chan struct{}) {
	ch := make(chan netlink.LinkUpdate, 32)
	stopSub := make(chan struct{})
	if err := netlink.LinkSubscribe(ch, stopSub); err != nil {
		log.Warnf("ebpf: LinkSubscribe: %v", err)
		close(stopSub)
		return
	}
	go func() {
		defer close(stopSub)
		for {
			select {
			case <-done:
				return
			case update, ok := <-ch:
				if !ok {
					return
				}
				if !isMonitorableLink(update.Link) {
					continue
				}
				name := update.Link.Attrs().Name
				switch update.Header.Type {
				case syscall.RTM_NEWLINK:
					log.Debugf("eBPF: netlink RTM_NEWLINK for %s, ensuring TC filters", name)
					ensureEbpfOnInterface(name)
				case syscall.RTM_DELLINK:
					log.Debugf("eBPF: netlink RTM_DELLINK for %s, clearing attachment state", name)
					ebpfAttachMu.Lock()
					delete(ebpfAttached, name)
					ebpfAttachMu.Unlock()
				}
			}
		}
	}()
}

// HasClsact returns true if a clsact qdisc exists on the named interface.
// Called from vip.go QoS code to decide which TC path to take.
func HasClsact(iface string) bool {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return false
	}
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return false
	}
	clsactHandle := netlink.MakeHandle(0xffff, 0)
	for _, q := range qdiscs {
		if q.Type() == "clsact" && q.Attrs().Handle == clsactHandle {
			return true
		}
	}
	return false
}

// ResetEbpfAttachment clears the "already attached" flag for iface, so the next
// call to ensureEbpfOnInterface will re-attach the TC filters.
func ResetEbpfAttachment(iface string) {
	ebpfAttachMu.Lock()
	delete(ebpfAttached, iface)
	ebpfAttachMu.Unlock()
}

// ebpfAddVip registers a VIP address in the BPF vip_set / vip_set6 map.
func ebpfAddVip(vipIP net.IP) {
	if ebpfObjs == nil {
		log.Warnf("eBPF: ebpfAddVip called but eBPF not initialized, VIP %s will not be counted", vipIP)
		return
	}
	dummy := uint8(1)
	if ip4 := vipIP.To4(); ip4 != nil {
		var key [4]byte
		copy(key[:], ip4)
		if err := ebpfObjs.vipSet.Update(key, dummy, ebpf.UpdateAny); err != nil {
			log.Warnf("eBPF: failed to add IPv4 VIP %s to vip_set: %v", vipIP, err)
		} else {
			log.Debugf("eBPF: IPv4 VIP %s added to vip_set map", vipIP)
		}
	} else {
		ip6 := vipIP.To16()
		if ip6 == nil {
			return
		}
		var key [16]byte
		copy(key[:], ip6)
		if err := ebpfObjs.vipSet6.Update(key, dummy, ebpf.UpdateAny); err != nil {
			log.Warnf("eBPF: failed to add IPv6 VIP %s to vip_set6: %v", vipIP, err)
		} else {
			log.Debugf("eBPF: IPv6 VIP %s added to vip_set6 map", vipIP)
		}
	}
}

// ebpfDelVip removes a VIP address from the BPF vip_set / vip_set6 map,
// and also clears its accumulated stats so the map doesn't grow unboundedly.
func ebpfDelVip(vipIP net.IP) {
	if ebpfObjs == nil {
		return
	}
	if ip4 := vipIP.To4(); ip4 != nil {
		var key [4]byte
		copy(key[:], ip4)
		if err := ebpfObjs.vipSet.Delete(key); err != nil && !isNotFound(err) {
			log.Warnf("eBPF: failed to delete IPv4 VIP %s from vip_set: %v", vipIP, err)
		} else {
			log.Debugf("eBPF: IPv4 VIP %s removed from vip_set map", vipIP)
		}
		for _, m := range []*ebpf.Map{ebpfObjs.vipIngressStats, ebpfObjs.vipEgressStats} {
			if err := m.Delete(key); err != nil && !isNotFound(err) {
				log.Warnf("eBPF: failed to delete IPv4 stats for VIP %s: %v", vipIP, err)
			}
		}
	} else {
		ip6 := vipIP.To16()
		if ip6 == nil {
			return
		}
		var key [16]byte
		copy(key[:], ip6)
		if err := ebpfObjs.vipSet6.Delete(key); err != nil && !isNotFound(err) {
			log.Warnf("eBPF: failed to delete IPv6 VIP %s from vip_set6: %v", vipIP, err)
		} else {
			log.Debugf("eBPF: IPv6 VIP %s removed from vip_set6 map", vipIP)
		}
		for _, m := range []*ebpf.Map{ebpfObjs.vipIngressStats6, ebpfObjs.vipEgressStats6} {
			if err := m.Delete(key); err != nil && !isNotFound(err) {
				log.Warnf("eBPF: failed to delete IPv6 stats for VIP %s: %v", vipIP, err)
			}
		}
	}
}

// updateCountersByEbpf reads per-VIP traffic counters from BPF PERCPU_HASH maps
// and updates all four fields (InBytes, InPackets, OutBytes, OutPackets).
func updateCountersByEbpf(counters map[string]*VipCounter) {
	if ebpfObjs == nil {
		return
	}
	log.Debugf("eBPF: reading stats for %d tracked VIPs from BPF maps", len(counters))

	type dirMap struct {
		m      *ebpf.Map
		label  string
		isIPv6 bool
	}
	dirs := []dirMap{
		{ebpfObjs.vipIngressStats, "in", false},
		{ebpfObjs.vipEgressStats, "out", false},
		{ebpfObjs.vipIngressStats6, "in", true},
		{ebpfObjs.vipEgressStats6, "out", true},
	}

	for _, d := range dirs {
		if d.isIPv6 {
			readStatsIPv6(d.m, d.label, counters)
		} else {
			readStatsIPv4(d.m, d.label, counters)
		}
	}
}

func readStatsIPv4(m *ebpf.Map, label string, counters map[string]*VipCounter) {
	var key [4]byte
	var values []vipStat
	iter := m.Iterate()
	for iter.Next(&key, &values) {
		ip := net.IP(key[:]).String()
		vc, ok := counters[ip]
		if !ok {
			continue
		}
		var total vipStat
		for _, v := range values {
			total.Packets += v.Packets
			total.Bytes += v.Bytes
		}
		applyStats(vc, label, total)
	}
	if err := iter.Err(); err != nil {
		log.Warnf("ebpf: iterate IPv4 %s stats: %v", label, err)
	}
}

func readStatsIPv6(m *ebpf.Map, label string, counters map[string]*VipCounter) {
	var key [16]byte
	var values []vipStat
	iter := m.Iterate()
	for iter.Next(&key, &values) {
		ip := net.IP(key[:]).String()
		vc, ok := counters[ip]
		if !ok {
			continue
		}
		var total vipStat
		for _, v := range values {
			total.Packets += v.Packets
			total.Bytes += v.Bytes
		}
		applyStats(vc, label, total)
	}
	if err := iter.Err(); err != nil {
		log.Warnf("ebpf: iterate IPv6 %s stats: %v", label, err)
	}
}

func applyStats(vc *VipCounter, label string, s vipStat) {
	if label == "in" {
		vc.InPackets = s.Packets
		vc.InBytes = s.Bytes
	} else {
		vc.OutPackets = s.Packets
		vc.OutBytes = s.Bytes
	}
}

func isNotFound(err error) bool {
	return err == ebpf.ErrKeyNotExist
}

// closeEbpfVipCounter releases all BPF resources. Called on zvr shutdown.
func closeEbpfVipCounter() {
	log.Infof("eBPF VIP counter: shutting down")
	if ebpfWatcherDone != nil {
		close(ebpfWatcherDone)
		ebpfWatcherDone = nil
	}
	if ebpfObjs != nil {
		ebpfObjs.coll.Close()
		ebpfObjs = nil
	}
	log.Infof("eBPF VIP counter: shutdown complete")
}
