package plugin

import "testing"

func TestHaproxyEndpointFormatsIpv6Address(t *testing.T) {
	if got := haproxyEndpoint("1000::4", 22); got != "[1000::4]:22" {
		t.Fatalf("unexpected IPv6 endpoint: %s", got)
	}

	if got := haproxyEndpoint("172.24.14.175", 22); got != "172.24.14.175:22" {
		t.Fatalf("unexpected IPv4 endpoint: %s", got)
	}
}

func TestHaproxyBackendNameCanRoundTripIpv6(t *testing.T) {
	ip := "111:13:178::ef"
	name := "nic-" + haproxyBackendName(ip)

	if name != "nic-111_13_178__ef" {
		t.Fatalf("unexpected backend name: %s", name)
	}

	if got := getIpFromLbStat(name); got != ip {
		t.Fatalf("unexpected backend IP: %s", got)
	}
}

func TestGetListenersWithIpv4VipSkipsIpv6WithoutSkippingIpv4(t *testing.T) {
	listeners := getListenersWithIpv4Vip([]Listener{
		&HaproxyListener{lb: LbInfo{ListenerUuid: "ipv6", Vip6: "fd86:8635:6:4::f:d16e"}},
		&HaproxyListener{lb: LbInfo{ListenerUuid: "ipv4-first", Vip: "172.24.14.175"}},
		&HaproxyListener{lb: LbInfo{ListenerUuid: "ipv4-second", Vip: "172.24.14.176"}},
	})

	if len(listeners) != 2 {
		t.Fatalf("expected two IPv4 listeners, got %#v", listeners)
	}
	if listeners[0].getLbInfo().ListenerUuid != "ipv4-first" || listeners[1].getLbInfo().ListenerUuid != "ipv4-second" {
		t.Fatalf("unexpected IPv4 listener order: %#v", listeners)
	}
}
