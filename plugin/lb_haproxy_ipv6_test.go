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
