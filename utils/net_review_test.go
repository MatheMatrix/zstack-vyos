package utils

import "testing"

func TestNetmaskToCIDRRejectsInvalidIPv4Mask(t *testing.T) {
	if _, err := NetmaskToCIDR("not.a.mask"); err == nil {
		t.Fatal("expected invalid dotted netmask to return error")
	}
	if _, err := NetmaskToCIDR("255.0.255.0"); err == nil {
		t.Fatal("expected non-contiguous dotted netmask to return error")
	}
}

func TestNetmaskToCIDRRejectsInvalidIPv6Mask(t *testing.T) {
	if _, err := NetmaskToCIDR("ffff::ffff"); err == nil {
		t.Fatal("expected non-contiguous IPv6 netmask to return error")
	}
}

func TestNetmaskToCIDRRejectsInvalidPrefixLength(t *testing.T) {
	for _, netmask := range []string{"-1", "129"} {
		if _, err := NetmaskToCIDR(netmask); err == nil {
			t.Fatalf("expected netmask prefix %s to return error", netmask)
		}
	}
}

func TestNetmaskToCIDRKeepsValidIPv4AndIpv6Prefixes(t *testing.T) {
	cidr, err := NetmaskToCIDR("255.255.255.0")
	if err != nil {
		t.Fatalf("expected valid IPv4 netmask: %v", err)
	}
	if cidr != 24 {
		t.Fatalf("expected IPv4 /24, got /%d", cidr)
	}

	cidr, err = NetmaskToCIDR("64")
	if err != nil {
		t.Fatalf("expected valid IPv6 prefix: %v", err)
	}
	if cidr != 64 {
		t.Fatalf("expected IPv6 /64, got /%d", cidr)
	}
}

func TestRouteCommandsUseIpv6ForCidrInput(t *testing.T) {
	if cmd := ipRouteCommand("2001:db8::1/128"); cmd != "ip -6 route" {
		t.Fatalf("expected IPv6 route command, got %s", cmd)
	}
	if cmd := frrRouteCommand("2001:db8::1/128"); cmd != "ipv6 route" {
		t.Fatalf("expected IPv6 FRR route command, got %s", cmd)
	}
	if cmd := ipRouteCommand("192.168.1.10/32"); cmd != "ip route" {
		t.Fatalf("expected IPv4 route command, got %s", cmd)
	}
}
