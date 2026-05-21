package utils

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	POLICY_ROUTE_TABLE_FILE = "/etc/iproute2/rt_tables"

	ROUTETABLE_ID_MIN  = 1
	ROUTETABLE_ID_MAX  = 250
	ROUTETABLE_ID_MAIN = 254
)

func getPolicyRouterTableFileTemp() string {
	return filepath.Join(GetZvrRootPath(), ".zs_rt_tables")
}

type ZStackRouteTable struct {
	TableId int
	Alias   string
}

func (t ZStackRouteTable) toString() string {
	return fmt.Sprintf("%d %s", t.TableId, t.Alias)
}

func (t ZStackRouteTable) flushCommand() string {
	return fmt.Sprintf("sudo ip route flush table %d", t.TableId)
}

func GetZStackRouteTables() []ZStackRouteTable {
	var tables []ZStackRouteTable
	content, err := os.ReadFile(POLICY_ROUTE_TABLE_FILE)
	if err != nil {
		log.Debugf("read file: %s, failed: %s", POLICY_ROUTE_TABLE_FILE, err)
		return tables
	}

	// rt_tables may contain unexpected NUL (\x00) bytes or other junk; sanitize to avoid parsing issues.
	s := strings.ReplaceAll(string(content), "\x00", "")
	log.Debugf("%s contents (sanitized): %q", POLICY_ROUTE_TABLE_FILE, s)
	lines := strings.Split(strings.TrimSpace(s), "\n")

	for _, line := range lines {
		if line == "" {
			continue
		}

		if line[0] == '#' {
			continue
		}

		items := strings.Fields(line)
		if len(items) < 2 {
			// Malformed line (e.g., only a table id). Skip to avoid index out of range.
			log.Warnf("skip malformed rt_tables line: %q", line)
			continue
		}

		if strings.Contains(items[1], PolicyRouteChainPrefix) {
			tableId, err := strconv.Atoi(items[0])
			if err != nil {
				log.Warnf("skip rt_tables line with invalid table id: %q", line)
				continue
			}
			t := ZStackRouteTable{TableId: tableId, Alias: items[1]}
			tables = append(tables, t)
		}
	}

	return tables
}

func SyncZStackRouteTables(tables []ZStackRouteTable) error {
	bash := Bash{
		Command: fmt.Sprintf("cp %s %s; sed -i '/zs-rt-/d' %s", POLICY_ROUTE_TABLE_FILE, getPolicyRouterTableFileTemp(), getPolicyRouterTableFileTemp()),
	}
	ret, _, e, err := bash.RunWithReturn()
	if err != nil || ret != 0 {
		return fmt.Errorf("create temp route table file failed: %s", e)
	}

	var cmds []string
	for _, t := range tables {
		cmds = append(cmds, t.toString())
	}
	if len(cmds) > 0 {
		bash = Bash{
			Command: fmt.Sprintf("cat <<EOF >> %s \n%s \nEOF\n sudo mv %s %s", getPolicyRouterTableFileTemp(), strings.Join(cmds, "\n"),
				getPolicyRouterTableFileTemp(), POLICY_ROUTE_TABLE_FILE),
		}
	} else {
		bash = Bash{
			Command: fmt.Sprintf("sudo mv %s %s", getPolicyRouterTableFileTemp(), POLICY_ROUTE_TABLE_FILE),
		}
	}
	ret, _, e, err = bash.RunWithReturn()
	if err != nil || ret != 0 {
		return fmt.Errorf("copy temp route table file failed: %s", e)
	}

	if IsEuler2203() {
		// enable policy route, must disable rp_filter
		if len(tables) > 0 {
			bash = Bash{
				Command: "sysctl -a | grep -w \"rp_filter\" | awk '{print $1}' | xargs -I{} sysctl -w {}=0",
			}
			err := bash.Run()
			PanicOnError(err)
		} else {
			// disable policy route, restore rp_filter
			bash = Bash{
				Command: "sysctl -a | grep -w \"rp_filter\" | awk '{print $1}' | xargs -I{} sysctl -w {}=1",
			}
			err := bash.Run()
			PanicOnError(err)
		}
	}

	return nil
}

type ZStackRouteEntry struct {
	TableId         int
	Ipv6            bool
	DestinationCidr string
	NextHopIp       string
	NicName         string
	Distance        int
}

func (e ZStackRouteEntry) Equal(b ZStackRouteEntry) error {
	if e.TableId != b.TableId {
		return fmt.Errorf("tableId is different, %d:%d", e.TableId, b.TableId)
	}

	if e.DestinationCidr != b.DestinationCidr {
		return fmt.Errorf("destinationCidr is different, %s:%s", e.DestinationCidr, b.DestinationCidr)
	}

	if e.Distance != 0 && e.Distance != b.Distance {
		return fmt.Errorf("distance is different, %d:%d", e.Distance, b.Distance)
	}

	if e.NextHopIp != "" && e.NextHopIp != b.NextHopIp {
		return fmt.Errorf("nextHopIp is different, %s:%s", e.NextHopIp, b.NextHopIp)
	}

	if e.NicName != "" && e.NicName != b.NicName {
		return fmt.Errorf("nicName is different, %s:%s", e.NicName, b.NicName)
	}

	return nil
}

func (e ZStackRouteEntry) prefixEqual(b ZStackRouteEntry) error {
	if e.TableId != b.TableId {
		return fmt.Errorf("tableId is different, %d:%d", e.TableId, b.TableId)
	}

	if e.DestinationCidr != b.DestinationCidr {
		return fmt.Errorf("destinationCidr is different, %s:%s", e.DestinationCidr, b.DestinationCidr)
	}

	if e.Distance != 0 && e.Distance != b.Distance {
		return fmt.Errorf("distance is different, %d:%d", e.Distance, b.Distance)
	}

	return nil
}

func (e ZStackRouteEntry) addCommand() string {
	prefix := "ip"
	if e.Ipv6 {
		prefix = "ipv6"
	}
	if e.TableId == ROUTETABLE_ID_MAIN {
		if e.NextHopIp != "" {
			if e.Distance != 0 {
				return fmt.Sprintf("%s route %s %s %d", prefix, e.DestinationCidr, e.NextHopIp, e.Distance)
			} else {
				return fmt.Sprintf("%s route %s %s", prefix, e.DestinationCidr, e.NextHopIp)
			}
		} else if e.NicName != "" {
			if e.Distance != 0 {
				return fmt.Sprintf("%s route %s %s %d",
					prefix, e.DestinationCidr, e.NicName, e.Distance)
			} else {
				return fmt.Sprintf("%s route %s %s",
					prefix, e.DestinationCidr, e.NicName)
			}
		} else {
			log.Debugf("can not add route entry,because nexthopIp and nicName is null")
			return ""
		}
	}

	if e.NextHopIp != "" {
		if e.Distance != 0 {
			return fmt.Sprintf("%s route %s %s table %d %d",
				prefix, e.DestinationCidr, e.NextHopIp, e.TableId, e.Distance)
		} else {
			return fmt.Sprintf("%s route %s %s table %d",
				prefix, e.DestinationCidr, e.NextHopIp, e.TableId)
		}
	} else if e.NicName != "" {
		if e.Distance != 0 {
			return fmt.Sprintf("%s route %s %s table %d %d",
				prefix, e.DestinationCidr, e.NicName, e.TableId, e.Distance)
		} else {
			return fmt.Sprintf("%s route %s %s table %d",
				prefix, e.DestinationCidr, e.NicName, e.TableId)
		}
	} else {
		log.Debugf("can not add route entry,because nexthopIp and nicName is null")
		return ""
	}
}

func (e ZStackRouteEntry) deleteCommand() string {
	prefix := "ip"
	if e.Ipv6 {
		prefix = "ipv6"
	}

	if e.TableId == ROUTETABLE_ID_MAIN {
		if e.NextHopIp != "" {
			if e.Distance != 0 {
				return fmt.Sprintf("no %s route %s %s %d",
					prefix, e.DestinationCidr, e.NextHopIp, e.Distance)
			} else {
				return fmt.Sprintf("no %s route %s %s",
					prefix, e.DestinationCidr, e.NextHopIp)
			}
		} else if e.NicName != "" {
			if e.Distance != 0 {
				return fmt.Sprintf("no %s route %s %s %d",
					prefix, e.DestinationCidr, e.NicName, e.Distance)
			} else {
				return fmt.Sprintf("no %s route %s %s",
					prefix, e.DestinationCidr, e.NicName)
			}
		} else {
			log.Debugf("can not del route entry: %+v,because nexthopIp and nicName is null", e)
			return ""
		}
	}

	if e.NextHopIp != "" {
		if e.Distance != 0 {
			return fmt.Sprintf("no %s route %s %s table %d %d",
				prefix, e.DestinationCidr, e.NextHopIp, e.TableId, e.Distance)
		} else {
			return fmt.Sprintf("no %s route %s %s table %d",
				prefix, e.DestinationCidr, e.NextHopIp, e.TableId)
		}
	} else if e.NicName != "" {
		if e.Distance != 0 {
			return fmt.Sprintf("no %s route %s %s table %d %d",
				prefix, e.DestinationCidr, e.NicName, e.TableId, e.Distance)
		} else {
			return fmt.Sprintf("no %s route %s %s table %d",
				prefix, e.DestinationCidr, e.NicName, e.TableId)
		}
	} else {
		log.Debugf("can not del route entry: %+v,because nexthopIp and nicName is null", e)
		return ""
	}
}

func GetCurrentRouteEntriesEuler2203(tableId int) []ZStackRouteEntry {
	var entries []ZStackRouteEntry
	var cmd string
	if tableId == ROUTETABLE_ID_MAIN {
		cmd = fmt.Sprintf("vtysh -c 'show run' | grep  -E 'ip(v6)? route' | grep -v 'table'")
	} else {
		cmd = fmt.Sprintf("vtysh -c 'show run' | grep 'table %d'", tableId)
	}

	bash := Bash{
		Command: cmd,
		Sudo:    true,
	}
	/*
			# vtysh -c 'show run' | grep 'table 181'
			ip route 0.0.0.0/0 192.168.100.1 table 181
			ip route 192.168.1.0/24 eth3 table 181
			ip route 192.168.2.0/24 eth4 table 181
			ip route 192.168.100.0/24 192.168.100.109 table 181

			# vtysh -c 'show run' | grep  'ip route' | grep -v 'table'
			ip route 1.1.1.0/24 192.168.100.2 128
			ip route 1.1.2.0/24 192.168.100.3 128
			ip route 2.2.2.0/24 1.1.1.100 128
			ip route 3.3.3.0/24 Null0 128
		    ipv6 route ::/0 2025:5:14:1::1
	*/
	ret, result, _, err := bash.RunWithReturn()
	if err == nil && ret == 0 {
		result = strings.TrimSpace(result)
		lines := strings.Split(result, "\n")
		for _, line := range lines {
			if line == "" {
				continue
			}

			items := strings.Fields(line)
			dst := items[2]
			var nh, dev string
			var metric int
			if addr, err := netip.ParseAddr(items[3]); err == nil {
				nh = addr.String()
			} else {
				dev = items[3]
			}

			if len(items) == 5 {
				metric, _ = strconv.Atoi(items[4])
			}

			e := ZStackRouteEntry{
				TableId:         tableId,
				DestinationCidr: dst,
				NextHopIp:       nh,
				NicName:         dev,
				Distance:        metric,
			}
			entries = append(entries, e)
		}
	}

	return entries

}

func GetCurrentRouteEntries(tableId int) []ZStackRouteEntry {
	/* some table can not be operate
	vyos@vyos:~/vyos_ut/zstack-vyos$ vtysh -c 'show ip route table 0'
	% Unknown command.
	vyos@vyos:~/vyos_ut/zstack-vyos$ vtysh -c 'show ip route table 1'
	table 1:

	Codes: K - kernel route, C - connected, S - static, R - RIP, O - OSPF,
	       I - ISIS, B - BGP, > - selected route, * - FIB route

	S>* 1.1.1.0/24 [1/0] via 172.16.1.1 (recursive via 172.25.0.1)
	vyos@vyos:~/vyos_ut/zstack-vyos$ vtysh -c 'show ip route table 250'
	table 250:

	vyos@vyos:~/vyos_ut/zstack-vyos$ vtysh -c 'show ip route table 251'
	% Unknown command.
	vyos@vyos:~/vyos_ut/zstack-vyos$ vtysh -c 'show ip route table 252'
	% Unknown command.
	vyos@vyos:~/vyos_ut/zstack-vyos$ vtysh -c 'show ip route table 253'
	% Unknown command.
	vyos@vyos:~/vyos_ut/zstack-vyos$ vtysh -c 'show ip route table 254'
	% Unknown command.
	vyos@vyos:~/vyos_ut/zstack-vyos$ vtysh -c 'show ip route table 255'
	% Unknown command.
	**/

	if (tableId > ROUTETABLE_ID_MAX || tableId < ROUTETABLE_ID_MIN) && tableId != ROUTETABLE_ID_MAIN {
		panic("valid route table id range [1, 250]")
	}

	if IsEuler2203() {
		return GetCurrentRouteEntriesEuler2203(tableId)
	}

	var entries []ZStackRouteEntry
	cmd := fmt.Sprintf("vtysh -c 'show ip route table %d' | grep ^S", tableId)
	if tableId == ROUTETABLE_ID_MAIN {
		cmd = fmt.Sprintf("vtysh -c 'show ip route' | grep ^S")
	}

	bash := Bash{
		Command: cmd,
	}
	/*
	  output format:
	  $ vtysh -c "show ip route table 2"  | grep "^S"
	  S>* 3.2.4.0/24 [100/0] is directly connected, eth1
	  S>* 3.2.5.0/24 [1/0] is directly connected, eth1
	  S>* 3.3.3.0/24 [200/0] via 1.1.1.2, eth2
	  $ vtysh -c "show ip route"  | grep "^S"
	   S>* 0.0.0.0/0 [1/0] via 172.25.0.1, eth1
	   S   2.2.2.0/24 [200/0] via 1.1.2.101
	   S>* 2.2.2.0/24 [128/0] via 1.1.2.100 (recursive via 172.25.0.1)
	   S>* 2.2.3.0/24 [128/0] is directly connected, Null0, bh
	   S>* 2.2.4.0/24 [120/0] via 1.1.2.104 (recursive via 172.25.0.1)
	   S>* 2.2.5.0/24 [120/0] via 1.1.2.104 (recursive via 172.25.0.1)
	   S>* 3.2.4.0/24 [2/0] via 1.1.1.104, eth2
	*/
	ret, result, _, err := bash.RunWithReturn()
	if err == nil && ret == 0 {
		result = strings.TrimSpace(result)
		lines := strings.Split(result, "\n")
		for _, line := range lines {
			if line == "" {
				continue
			}

			items := strings.Fields(line)

			distances := strings.Split(items[2], "/")
			distance, _ := strconv.Atoi(distances[0][1:])

			if items[3] == "via" {
				nicName := ""
				if items[5] != "(recursive" {
					nicName = items[len(items)-1]
				}

				e := ZStackRouteEntry{
					TableId:         tableId,
					DestinationCidr: items[1],
					NextHopIp:       strings.TrimRight(items[4], ","), /* 1.1.1.2, */
					NicName:         nicName,
					Distance:        distance,
				}
				entries = append(entries, e)
			} else if items[3] == "unreachable" {
				nicName := "null0"
				e := ZStackRouteEntry{
					TableId:         tableId,
					DestinationCidr: items[1],
					NicName:         nicName,
					Distance:        distance,
				}
				entries = append(entries, e)
			} else if items[3] == "is" {
				nicName := items[6][:len(items[6])-1]
				e := ZStackRouteEntry{
					TableId:         tableId,
					DestinationCidr: items[1],
					NicName:         nicName,
					Distance:        distance,
				}
				entries = append(entries, e)
			} else {
				log.Errorf("unknow route format: %s", line)
			}
		}
	}

	return entries
}

func deleteRouteEntries(entries []ZStackRouteEntry) error {
	cmds := []string{"vtysh -c 'configure terminal'"}
	for _, r := range entries {
		cmds = append(cmds, fmt.Sprintf("-c '%s'", r.deleteCommand()))
	}

	bash := Bash{
		Command: fmt.Sprintf("%s", strings.Join(cmds, " ")),
	}

	ret, _, e, err := bash.RunWithReturn()
	if err != nil || ret != 0 {
		return fmt.Errorf("delete ip route: %s failed, because: %s", strings.Join(cmds, " "), e)
	}

	return nil
}

func addRouteEntries(entries []ZStackRouteEntry) error {
	cmds := []string{"vtysh -c 'configure terminal'"}
	for _, r := range entries {
		cmds = append(cmds, fmt.Sprintf("-c '%s'", r.addCommand()))
	}

	bash := Bash{
		Command: fmt.Sprintf("%s", strings.Join(cmds, " ")),
	}

	ret, _, e, err := bash.RunWithReturn()
	if err != nil || ret != 0 {
		return fmt.Errorf("add ip route: %s failed, because: %s", strings.Join(cmds, " "), e)
	}

	return nil
}

func SyncRouteEntries(currTables []ZStackRouteTable, entryMap map[int][]ZStackRouteEntry) error {
	var toDeleted []ZStackRouteEntry
	var toAdded []ZStackRouteEntry
	/* delete route tables */
	for _, table := range currTables {
		if _, ok := entryMap[table.TableId]; !ok {
			currEntries := GetCurrentRouteEntries(table.TableId)
			for _, r := range currEntries {
				toDeleted = append(toDeleted, r)
			}
		}
	}

	for tableId, entries := range entryMap {
		currEntries := GetCurrentRouteEntries(tableId)
		/* delete old entries that is not needed */
		for _, oe := range currEntries {
			exist := false
			for _, ne := range entries {
				if oe.Equal(ne) == nil {
					exist = true
					break
				}
			}

			if !exist {
				toDeleted = append(toDeleted, oe)
			}
		}

		/* add new entries that is added */
		for _, ne := range entries {
			exist := false
			for _, oe := range currEntries {
				if oe.Equal(ne) == nil {
					exist = true
					break
				}
			}

			if !exist {
				toAdded = append(toAdded, ne)
			}
		}
	}

	if len(toDeleted) != 0 {
		deleteRouteEntries(toDeleted)
	}

	if len(toAdded) != 0 {
		addRouteEntries(toAdded)
	}

	return nil
}

/*
# vtysh -c 'show ip route 172.25.16.161'
Routing entry for 172.25.0.0/16
  Known via "connected", distance 0, metric 0, best
  Last update 22:16:28 ago
  * directly connected, eth0

# vtysh -c 'show ip route 172.26.16.161'
Routing entry for 0.0.0.0/0
  Known via "kernel", distance 0, metric 0, best
  Last update 22:16:51 ago
  * 192.168.100.1, via eth1

# vtysh -c 'show ip route 172.25.0.0/16'
Routing entry for 172.25.0.0/16
  Known via "connected", distance 0, metric 0, best
  Last update 1d02h57m ago
  * directly connected, eth0

[root@vrouter zstack]# vtysh -c 'show ip route 172.26.0.0/16'
% Network not in table

*/

// TODO ipv6 is not implemented
func getRouteEntryForIp(ip string) (*ZStackRouteEntry, error) {
	bash := Bash{
		Command: fmt.Sprintf("vtysh -c 'show ip route %s' | tail -n 2", ip),
	}

	ret, o, e, err := bash.RunWithReturn()
	if err != nil || ret != 0 {
		return nil, fmt.Errorf("vtysh -c 'show ip route %s' | tail -n 2 failed: %+v", ip, e)
	}

	lines := strings.Split(o, "\n")
	if strings.Contains(lines[0], "Network not in table") {
		return nil, nil
	}

	items := strings.Split(lines[0], ",")
	if strings.Contains(items[0], "directly connected") {
		return &ZStackRouteEntry{
			DestinationCidr: ip,
			NicName:         strings.TrimSpace(items[1]),
			TableId:         ROUTETABLE_ID_MAIN,
		}, nil
	} else if strings.Contains(items[1], "via") {
		nicName := strings.Replace(items[1], "via", "", 1)
		nicName = strings.TrimSpace(nicName)
		nexthop := strings.Replace(items[0], "*", "", 1)
		nexthop = strings.TrimSpace(nexthop)
		return &ZStackRouteEntry{
			DestinationCidr: ip,
			NicName:         strings.TrimSpace(items[1]),
			NextHopIp:       nexthop,
			TableId:         ROUTETABLE_ID_MAIN,
		}, nil
	}

	return nil, fmt.Errorf("unknow route format: %s", lines[0])
}

func AddRouteForMgmtEuler2203(mgtIp, mgtNic, gw string) error {
	entry, err := getRouteEntryForIp(mgtIp)
	if err != nil {
		return err
	}

	if entry != nil && entry.NicName == mgtNic {
		log.Debugf("no need to add mgtip route")
		return nil
	}

	mgtEntry := ZStackRouteEntry{
		DestinationCidr: mgtIp,
		NicName:         mgtNic,
		NextHopIp:       gw,
		TableId:         ROUTETABLE_ID_MAIN,
		Ipv6:            strings.Contains(mgtIp, ":"),
	}
	return addRouteEntries([]ZStackRouteEntry{mgtEntry})
}

func AddDefaultRouteEuler2203(gw, gw6, nicName string) error {
	var entries []ZStackRouteEntry
	var delEntries []ZStackRouteEntry

	curRts := GetCurrentRouteEntriesEuler2203(RT_TABLES_MAIN)
	for _, r := range curRts {
		if r.DestinationCidr == "0.0.0.0/0" {
			delEntries = append(delEntries, r)
		} else if r.DestinationCidr == "::/0" {
			delEntries = append(delEntries, r)
		}
	}

	log.Debugf("AddDefaultRouteEuler2203 gw: %s, gw6: %s", gw, gw6)
	if gw != "" {
		entry := ZStackRouteEntry{
			TableId:         RT_TABLES_MAIN,
			DestinationCidr: "0.0.0.0/0",
			NextHopIp:       gw,
			NicName:         nicName,
		}
		entries = append(entries, entry)
	}

	if gw6 != "" {
		entry := ZStackRouteEntry{
			TableId:         RT_TABLES_MAIN,
			DestinationCidr: "::/0",
			NextHopIp:       gw6,
			NicName:         nicName,
			Ipv6:            true,
		}
		entries = append(entries, entry)
	}

	log.Debugf("AddDefaultRouteEuler2203 delEntries %+v", delEntries)
	if len(delEntries) > 0 {
		_ = deleteRouteEntries(delEntries)
	}

	err := addRouteEntries(entries)

	return err
}
