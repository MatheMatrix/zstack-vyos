package utils

import "testing"

func TestShouldConfigurePrivateNicSnat(t *testing.T) {
	originalBootstrapInfo := BootstrapInfo
	defer func() {
		BootstrapInfo = originalBootstrapInfo
	}()

	BootstrapInfo = map[string]interface{}{}
	if !ShouldConfigurePrivateNicSnat("192.168.10.1") {
		t.Fatal("IPv4 private SNAT should be configured for non-SLB appliance")
	}

	if ShouldConfigurePrivateNicSnat("2001:db8::1") {
		t.Fatal("IPv6 private SNAT should not be configured")
	}

	BootstrapInfo = map[string]interface{}{
		"applianceVmSubType": APPLIANCETYPE_SLB,
	}
	if ShouldConfigurePrivateNicSnat("192.168.10.1") {
		t.Fatal("private SNAT should not be configured for SLB appliance")
	}
}

func TestGetBootStrapPrivateNicInfo(t *testing.T) {
	originalBootstrapInfo := BootstrapInfo
	defer func() {
		BootstrapInfo = originalBootstrapInfo
	}()

	BootstrapInfo = map[string]interface{}{
		"additionalNics": []interface{}{
			map[string]interface{}{
				"category":   NIC_TYPE_PUBLIC,
				"deviceName": "eth0",
				"ip":         "10.0.0.2",
				"netmask":    "255.255.255.0",
			},
			map[string]interface{}{
				"category":   NIC_TYPE_PRIVATE,
				"deviceName": "eth1",
				"mac":        "52:54:00:12:34:56",
				"ip":         "192.168.10.1",
				"netmask":    "255.255.255.0",
			},
			map[string]interface{}{
				"category":   NIC_TYPE_PRIVATE,
				"deviceName": "eth2",
				"ip":         "2001:db8::1",
				"netmask":    "64",
			},
		},
	}

	nics := GetBootStrapPrivateNicInfo()
	if len(nics) != 1 {
		t.Fatalf("expected one private IPv4 nic, got %d", len(nics))
	}
	if nics[0].Name != "eth1" || nics[0].Ip != "192.168.10.1" || nics[0].Netmask != "255.255.255.0" {
		t.Fatalf("unexpected private nic info: %+v", nics[0])
	}
}
