package plugin

import "testing"

func TestIpvsCommandBuildersUseTcpFullNatBackendPort(t *testing.T) {
	lb := LbInfo{
		LbUuid:           "lb",
		ListenerUuid:     "listener",
		Vip:              "172.24.7.153",
		LoadBalancerPort: 19086,
		InstancePort:     8080,
		Mode:             LB_MODE_TCP,
		DataPlane:        LB_DATA_PLANE_IPVS,
		ForwardMode:      LB_FORWARD_MODE_FULL_NAT,
		Parameters:       []string{"balancerAlgorithm::roundrobin"},
	}
	param := ParseLbParams(lb)
	fs := NewIpvsFrontService(lb, param, lb.Vip, map[string]*IpvsBackendServer{})
	bs := NewIpvsBackendServer("192.168.10.20", "8080", "100", fs)

	if got, want := makeIpvsAddServiceCommand(fs), "ipvsadm -A -t 172.24.7.153:19086 -s rr"; got != want {
		t.Fatalf("unexpected add service command:\nwant: %s\n got: %s", want, got)
	}
	if got, want := makeIpvsAddBackendCommand(bs), "ipvsadm -a -t 172.24.7.153:19086 -r 192.168.10.20:8080 -m -w 100 -x 0 -y 0"; got != want {
		t.Fatalf("unexpected add backend command:\nwant: %s\n got: %s", want, got)
	}
	if got, want := makeIpvsDeleteServiceCommand(fs), "ipvsadm -D -t 172.24.7.153:19086"; got != want {
		t.Fatalf("unexpected delete service command:\nwant: %s\n got: %s", want, got)
	}
}

func TestIpvsCommandBuildersQuoteIPv6Address(t *testing.T) {
	lb := LbInfo{
		LbUuid:           "lb",
		ListenerUuid:     "listener",
		Vip6:             "2001:db8::10",
		LoadBalancerPort: 19086,
		Mode:             LB_MODE_TCP,
		DataPlane:        LB_DATA_PLANE_IPVS,
		ForwardMode:      LB_FORWARD_MODE_FULL_NAT,
		Parameters:       []string{"balancerAlgorithm::rr"},
	}
	param := ParseLbParams(lb)
	fs := NewIpvsFrontService(lb, param, lb.Vip6, map[string]*IpvsBackendServer{})
	bs := NewIpvsBackendServer("2001:db8::20", "8080", "1", fs)

	if got, want := makeIpvsAddServiceCommand(fs), "ipvsadm -A -t [2001:db8::10]:19086 -s rr"; got != want {
		t.Fatalf("unexpected ipv6 add service command:\nwant: %s\n got: %s", want, got)
	}
	if got, want := makeIpvsDeleteBackendCommand(bs), "ipvsadm -d -t [2001:db8::10]:19086 -r [2001:db8::20]:8080"; got != want {
		t.Fatalf("unexpected ipv6 delete backend command:\nwant: %s\n got: %s", want, got)
	}
}

func TestParseIpvsAclConfigKeepsIPv6Entries(t *testing.T) {
	aclType, entries, enabled := parseIpvsAclConfig([]string{
		"accessControlStatus::enable",
		"aclType::white",
		"aclEntry::2001:db8::1/128, 192.168.10.0/24",
	})

	if !enabled {
		t.Fatal("expected acl to be enabled")
	}
	if aclType != "white" {
		t.Fatalf("unexpected acl type: %s", aclType)
	}
	if len(entries) != 2 || entries[0] != "2001:db8::1/128" || entries[1] != "192.168.10.0/24" {
		t.Fatalf("unexpected acl entries: %#v", entries)
	}
}
