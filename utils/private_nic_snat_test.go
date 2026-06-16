package utils

import "testing"

func TestShouldConfigurePrivateNicSnat(t *testing.T) {
	oldBootstrapInfo := BootstrapInfo
	defer func() {
		BootstrapInfo = oldBootstrapInfo
	}()

	BootstrapInfo = map[string]interface{}{
		"applianceVmSubType": APPLIANCETYPE_VPC,
	}
	if !ShouldConfigurePrivateNicSnat("192.168.1.17") {
		t.Fatalf("expected private nic snat for non-SLB IPv4")
	}
	if ShouldConfigurePrivateNicSnat("2001:db8::1") {
		t.Fatalf("expected IPv6 private nic snat to be skipped")
	}

	BootstrapInfo = map[string]interface{}{
		"applianceVmSubType": APPLIANCETYPE_SLB,
	}
	if ShouldConfigurePrivateNicSnat("192.168.1.17") {
		t.Fatalf("expected SLB private nic snat to be skipped")
	}
}
