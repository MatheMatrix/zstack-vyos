package main

import "testing"

func TestNicFirewallAddressUsesIpv6Fallback(t *testing.T) {
	if got := nicFirewallAddress(&nic{ip6: "2001:db8::10"}); got != "2001:db8::10" {
		t.Fatalf("expect IPv6 fallback address, got %s", got)
	}

	if got := nicFirewallAddress(&nic{ip: "192.168.1.10", ip6: "2001:db8::10"}); got != "192.168.1.10" {
		t.Fatalf("expect IPv4 address to be preferred, got %s", got)
	}
}
