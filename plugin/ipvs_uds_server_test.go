package plugin

import (
	"fmt"
	"sync"
	"testing"

	"zstack.io/zstack-vyos/ipvshc"

	. "github.com/onsi/gomega"
)

// makeTestConf builds a minimal gIpvsConf fixture with one listener and
// optionally one backend.
func makeTestConf(listenerUuid, frontIp, frontPort, proto string, backends ...[3]string) *IpvsConf {
	fs := &IpvsFrontendService{
		ProtocolType:   proto,
		Scheduler:      "rr",
		FrontIp:        frontIp,
		FrontPort:      frontPort,
		BackendServers: map[string]*IpvsBackendServer{},
		LbInfo:         LbInfo{ListenerUuid: listenerUuid},
	}
	for _, b := range backends {
		bs := &IpvsBackendServer{
			BackendIp:           b[0],
			BackendPort:         b[1],
			Weight:              b[2],
			ConnectionType:      "-m",
			IpvsFrontendService: fs,
		}
		fs.BackendServers[bs.GetBackendKey()] = bs
	}
	return &IpvsConf{Services: map[string]*IpvsFrontendService{
		fs.getFrontendServiceKey(): fs,
	}}
}

// resetSeenSeq clears the module-level dedupe map so tests are independent.
func resetSeenSeq() {
	rsEventSeenSeq = sync.Map{}
}

func rsEvent(inc int64, listenerUuid, rsIp, rsPort string, op ipvshc.RsEventOp, seq uint64) *ipvshc.RsEvent {
	return &ipvshc.RsEvent{
		Seq:             seq,
		DaemonStartedAt: inc,
		ListenerUuid:    listenerUuid,
		RsIp:            rsIp,
		RsPort:          rsPort,
		Op:              op,
		Weight:          "1",
	}
}

// TestOnRsEvent_AddServiceBeforeAddBackend verifies that RsEventUp calls
// AddService idempotently BEFORE AddBackend (cold-start correctness).
func TestOnRsEvent_AddServiceBeforeAddBackend(t *testing.T) {
	g := NewGomegaWithT(t)
	resetSeenSeq()

	gIpvsConf = makeTestConf("lu-1", "10.0.0.1", "80", "udp", [3]string{"1.2.3.4", "8080", "1"})
	fa := NewFakeIpvsAdmin()
	ipvsAdmin = fa

	h := &ipvsServerHandler{}
	ack, err := h.OnRsEvent(rsEvent(1000, "lu-1", "1.2.3.4", "8080", ipvshc.RsEventUp, 1))
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(ack.Applied).To(BeTrue(), "expected Applied=true, got reason: %s", ack.Reason)

	log := fa.CallLog()
	g.Expect(log).To(HaveLen(2))
	// AddService must come first
	g.Expect(log[0]).To(HavePrefix("AddService:"))
	g.Expect(log[1]).To(HavePrefix("AddBackend:"))
}

// TestOnRsEvent_DeleteServiceWhenLastBackendGone verifies that after the
// last backend goes down the service is also deleted.
func TestOnRsEvent_DeleteServiceWhenLastBackendGone(t *testing.T) {
	g := NewGomegaWithT(t)
	resetSeenSeq()

	gIpvsConf = makeTestConf("lu-2", "10.0.0.1", "81", "udp", [3]string{"1.2.3.5", "9090", "1"})
	fa := NewFakeIpvsAdmin()
	ipvsAdmin = fa
	// Pre-populate fake admin with the service+backend so Save() can report it.
	_ = fa.AddService(*gIpvsConf.Services["udp-10.0.0.1-81"])
	_ = fa.AddBackend(*gIpvsConf.Services["udp-10.0.0.1-81"], IpvsBackendServer{BackendIp: "1.2.3.5", BackendPort: "9090", Weight: "1"})
	fa.addLog = nil // reset log after setup

	h := &ipvsServerHandler{}
	ack, err := h.OnRsEvent(rsEvent(1000, "lu-2", "1.2.3.5", "9090", ipvshc.RsEventDown, 1))
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(ack.Applied).To(BeTrue(), ack.Reason)

	cl := fa.CallLog()
	// Must have called DelBackend then DelService
	g.Expect(cl).To(ContainElement(HavePrefix("DelBackend:")))
	g.Expect(cl).To(ContainElement(HavePrefix("DelService:")))
}

// TestOnRsEvent_ListenerIsolation ensures that a down event for listener-A
// does not affect listener-B even if both share the same backend IP:port.
func TestOnRsEvent_ListenerIsolation_SameBackendUnderDifferentListeners(t *testing.T) {
	g := NewGomegaWithT(t)
	resetSeenSeq()

	fsA := &IpvsFrontendService{
		ProtocolType:   "udp",
		Scheduler:      "rr",
		FrontIp:        "10.0.0.1",
		FrontPort:      "80",
		BackendServers: map[string]*IpvsBackendServer{},
		LbInfo:         LbInfo{ListenerUuid: "lu-A"},
	}
	fsB := &IpvsFrontendService{
		ProtocolType:   "udp",
		Scheduler:      "rr",
		FrontIp:        "10.0.0.2",
		FrontPort:      "80",
		BackendServers: map[string]*IpvsBackendServer{},
		LbInfo:         LbInfo{ListenerUuid: "lu-B"},
	}
	sharedBs := func(fs *IpvsFrontendService) *IpvsBackendServer {
		return &IpvsBackendServer{BackendIp: "5.5.5.5", BackendPort: "9000", Weight: "1", IpvsFrontendService: fs}
	}
	bsA := sharedBs(fsA)
	bsB := sharedBs(fsB)
	fsA.BackendServers[bsA.GetBackendKey()] = bsA
	fsB.BackendServers[bsB.GetBackendKey()] = bsB

	gIpvsConf = &IpvsConf{Services: map[string]*IpvsFrontendService{
		fsA.getFrontendServiceKey(): fsA,
		fsB.getFrontendServiceKey(): fsB,
	}}
	fa := NewFakeIpvsAdmin()
	ipvsAdmin = fa
	_ = fa.AddService(*fsA)
	_ = fa.AddBackend(*fsA, *bsA)
	_ = fa.AddService(*fsB)
	_ = fa.AddBackend(*fsB, *bsB)
	fa.addLog = nil

	h := &ipvsServerHandler{}
	// Down event targeting only listener-A's backend.
	ack, err := h.OnRsEvent(rsEvent(1000, "lu-A", "5.5.5.5", "9000", ipvshc.RsEventDown, 1))
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(ack.Applied).To(BeTrue(), ack.Reason)

	// Listener-B must still have its backend.
	snap := fa.Snapshot()
	bKey := fsB.ProtocolType + "|" + fsB.FrontIp + "|" + fsB.FrontPort // fakeIpvsAdmin uses "|" separator
	g.Expect(snap).To(HaveKey(bKey))
	g.Expect(snap[bKey].BackendServers).To(HaveLen(1), "listener-B backend must survive listener-A down event")
}

// TestOnRsEvent_DaemonRestart_SeqResetAccepted verifies that after a daemon
// restart (new DaemonStartedAt), events with seq < previous are accepted.
func TestOnRsEvent_DaemonRestart_SeqResetAccepted(t *testing.T) {
	g := NewGomegaWithT(t)
	resetSeenSeq()

	gIpvsConf = makeTestConf("lu-3", "10.0.0.1", "82", "udp", [3]string{"7.7.7.7", "7777", "1"})
	fa := NewFakeIpvsAdmin()
	ipvsAdmin = fa

	h := &ipvsServerHandler{}

	// Incarnation 1: seq 10 processed successfully.
	ack, err := h.OnRsEvent(rsEvent(100, "lu-3", "7.7.7.7", "7777", ipvshc.RsEventUp, 10))
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(ack.Applied).To(BeTrue())

	// Reset fake admin for second incarnation.
	fa2 := NewFakeIpvsAdmin()
	ipvsAdmin = fa2

	// Incarnation 2 (daemon restarted): seq 1 — must NOT be dropped as stale.
	ack2, err := h.OnRsEvent(rsEvent(200, "lu-3", "7.7.7.7", "7777", ipvshc.RsEventUp, 1))
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(ack2.Applied).To(BeTrue(), "new incarnation seq=1 must be accepted after incarnation-100 seq=10")
	g.Expect(fa2.CallLog()).NotTo(BeEmpty(), "fa2 must have been called (not dropped as stale)")
}

// TestOnRsEvent_ApplyThenStore_RetryAfterFailure verifies that when ipvsAdmin
// fails, the seq is NOT stored and the next identical event is retried.
func TestOnRsEvent_ApplyThenStore_RetryAfterFailure(t *testing.T) {
	g := NewGomegaWithT(t)
	resetSeenSeq()

	gIpvsConf = makeTestConf("lu-4", "10.0.0.1", "83", "udp", [3]string{"8.8.8.8", "8888", "1"})

	// First attempt: use a fakeIpvsAdmin that has no pre-existing service,
	// so AddService succeeds but AddBackend would fail if we break it.
	// We simulate failure by pointing ipvsAdmin to a broken admin.
	brokenAdmin := &brokenIpvsAdmin{inner: NewFakeIpvsAdmin(), failAddBackend: true}
	ipvsAdmin = brokenAdmin

	h := &ipvsServerHandler{}
	ack, err := h.OnRsEvent(rsEvent(300, "lu-4", "8.8.8.8", "8888", ipvshc.RsEventUp, 5))
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(ack.Applied).To(BeFalse(), "apply failure must return Applied=false")

	// Now fix the admin and retry with the SAME seq — must be accepted.
	brokenAdmin.failAddBackend = false
	ack2, err := h.OnRsEvent(rsEvent(300, "lu-4", "8.8.8.8", "8888", ipvshc.RsEventUp, 5))
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(ack2.Applied).To(BeTrue(), "retry with same seq after failure must succeed (seq not pre-stored)")
}

// brokenIpvsAdmin wraps fakeIpvsAdmin and can fail AddBackend on demand.
type brokenIpvsAdmin struct {
	inner          *fakeIpvsAdmin
	failAddBackend bool
}

func (b *brokenIpvsAdmin) AddService(f IpvsFrontendService) error { return b.inner.AddService(f) }
func (b *brokenIpvsAdmin) DelService(f IpvsFrontendService) error { return b.inner.DelService(f) }
func (b *brokenIpvsAdmin) EditService(f IpvsFrontendService) error {
	return b.inner.EditService(f)
}
func (b *brokenIpvsAdmin) AddBackend(f IpvsFrontendService, bs IpvsBackendServer) error {
	if b.failAddBackend {
		return errInjected
	}
	return b.inner.AddBackend(f, bs)
}
func (b *brokenIpvsAdmin) DelBackend(f IpvsFrontendService, bs IpvsBackendServer) error {
	return b.inner.DelBackend(f, bs)
}
func (b *brokenIpvsAdmin) EditBackend(f IpvsFrontendService, bs IpvsBackendServer) error {
	return b.inner.EditBackend(f, bs)
}
func (b *brokenIpvsAdmin) Save() ([]IpvsFrontendService, error) { return b.inner.Save() }

var errInjected = fmt.Errorf("injected failure")
