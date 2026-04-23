package plugin

import (
	"reflect"
	"testing"
)

// Golden fixture: real-world `ipvsadm -L -n --stats` output containing both
// TCP and UDP services.  Pre-fix, the parser hard-coded proto = "udp" and used
// `break` on the first lookup miss, so every TCP backend lookup failed and
// every UDP service after the first miss was dropped.
const ipvsadmStatsMixedFixture = `IP Virtual Server version 1.2.1 (size=4096)
Prot LocalAddress:Port               Conns   InPkts  OutPkts  InBytes OutBytes
  -> RemoteAddress:Port
TCP  172.25.116.175:80                  10      100      200     3000     4000
  -> 192.168.1.180:80                    5       50      100     1500     2000
  -> 192.168.1.230:80                    5       50      100     1500     2000
UDP  172.25.116.175:8080                 7       70        0     2100        0
  -> 192.168.1.180:8080                  3       30        0      900        0
  -> 192.168.1.230:8080                  4       40        0     1200        0
`

const ipvsadmThresholdsMixedFixture = `IP Virtual Server version 1.2.1 (size=4096)
Prot LocalAddress:Port            Uthreshold Lthreshold ActiveConn InActConn
  -> RemoteAddress:Port
TCP  172.25.116.175:80 rr
  -> 192.168.1.180:80             0          0          5          0
  -> 192.168.1.181:80             10000      0          7          0
UDP  172.25.116.175:8080 rr
  -> 192.168.1.180:8080           0          0          3          0
`

func TestParseIpvsTabular_StatsMixedTCPAndUDP(t *testing.T) {
	got := parseIpvsTabular(ipvsadmStatsMixedFixture)

	want := []IpvsTabularRecord{
		{Proto: "tcp", FrontIp: "172.25.116.175", FrontPort: "80", BackendIp: "192.168.1.180", BackendPort: "80"},
		{Proto: "tcp", FrontIp: "172.25.116.175", FrontPort: "80", BackendIp: "192.168.1.230", BackendPort: "80"},
		{Proto: "udp", FrontIp: "172.25.116.175", FrontPort: "8080", BackendIp: "192.168.1.180", BackendPort: "8080"},
		{Proto: "udp", FrontIp: "172.25.116.175", FrontPort: "8080", BackendIp: "192.168.1.230", BackendPort: "8080"},
	}

	if len(got) != len(want) {
		t.Fatalf("parseIpvsTabular: got %d records, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		g := got[i]
		if g.Proto != w.Proto || g.FrontIp != w.FrontIp || g.FrontPort != w.FrontPort ||
			g.BackendIp != w.BackendIp || g.BackendPort != w.BackendPort {
			t.Errorf("record[%d] mismatch:\n got = %+v\nwant = %+v", i, g, w)
		}
	}
}

func TestParseIpvsTabular_ThresholdsMixedTCPAndUDP(t *testing.T) {
	got := parseIpvsTabular(ipvsadmThresholdsMixedFixture)

	want := []struct{ proto, fIp, fPort, bIp, bPort string }{
		{"tcp", "172.25.116.175", "80", "192.168.1.180", "80"},
		{"tcp", "172.25.116.175", "80", "192.168.1.181", "80"},
		{"udp", "172.25.116.175", "8080", "192.168.1.180", "8080"},
	}

	if len(got) != len(want) {
		t.Fatalf("parseIpvsTabular: got %d records, want %d", len(got), len(want))
	}
	for i, w := range want {
		g := got[i]
		if g.Proto != w.proto || g.FrontIp != w.fIp || g.FrontPort != w.fPort ||
			g.BackendIp != w.bIp || g.BackendPort != w.bPort {
			t.Errorf("record[%d] mismatch: got=%+v want=%+v", i, g, w)
		}
	}
}

// IPv6 addresses contain ':' characters; the parser strips brackets and joins
// everything but the trailing port back together.  Ensures the fix didn't
// regress IPv6 handling.
func TestParseIpvsTabular_IPv6StripsBrackets(t *testing.T) {
	const fixture = `IP Virtual Server version 1.2.1 (size=4096)
Prot LocalAddress:Port               Conns   InPkts  OutPkts  InBytes OutBytes
  -> RemoteAddress:Port
TCP  [fd00::1]:80                       0        0        0        0        0
  -> [fd00::100]:80                     0        0        0        0        0
`
	got := parseIpvsTabular(fixture)
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1: %+v", len(got), got)
	}
	if got[0].Proto != "tcp" || got[0].FrontIp != "fd00::1" || got[0].BackendIp != "fd00::100" {
		t.Errorf("ipv6 parse mismatch: %+v", got[0])
	}
}

// A "->" line that appears with no preceding TCP/UDP header (malformed input)
// must not be emitted with a stale proto — the F-014 fix resets proto on the
// else branch and skips orphan "->" rows when proto is empty.
func TestParseIpvsTabular_OrphanArrowSkipped(t *testing.T) {
	const fixture = `IP Virtual Server version 1.2.1 (size=4096)
Prot LocalAddress:Port               Conns   InPkts  OutPkts  InBytes OutBytes
  -> RemoteAddress:Port
  -> 192.168.1.180:80                    0        0        0        0        0
`
	got := parseIpvsTabular(fixture)
	if len(got) != 0 {
		t.Errorf("expected 0 records for orphan arrow, got %d: %+v", len(got), got)
	}
}

// Empty / short output shouldn't panic.
func TestParseIpvsTabular_ShortOutput(t *testing.T) {
	for _, in := range []string{"", "one\n", "one\ntwo\n", "one\ntwo\nthree\n"} {
		got := parseIpvsTabular(in)
		if !reflect.DeepEqual(got, []IpvsTabularRecord(nil)) {
			t.Errorf("input %q: expected nil, got %+v", in, got)
		}
	}
}
