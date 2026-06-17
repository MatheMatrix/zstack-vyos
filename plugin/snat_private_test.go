package plugin

import (
	"testing"

	"zstack-vyos/server"
	"zstack-vyos/utils"
)

func TestRemoveSlbDefaultPrivateNicSnatRulesByVyos(t *testing.T) {
	originalBootstrapInfo := utils.BootstrapInfo
	defer func() {
		utils.BootstrapInfo = originalBootstrapInfo
	}()

	utils.BootstrapInfo = map[string]interface{}{
		"applianceVmSubType": utils.APPLIANCETYPE_SLB,
		"additionalNics": []interface{}{
			map[string]interface{}{
				"category":   utils.NIC_TYPE_PRIVATE,
				"deviceName": "eth1",
				"ip":         "192.168.10.1",
				"netmask":    "255.255.255.0",
			},
			map[string]interface{}{
				"category":     utils.NIC_TYPE_PRIVATE,
				"deviceName":   "eth2",
				"ip6":          "2001:db8::1",
				"gateway6":     "2001:db8::ff",
				"prefixLength": 64,
			},
			map[string]interface{}{
				"category":   utils.NIC_TYPE_PUBLIC,
				"deviceName": "eth0",
				"ip":         "172.20.10.2",
				"netmask":    "255.255.255.0",
			},
		},
	}

	tree := server.NewParserFromConfiguration("").Tree
	tree.SetSnatWithRuleNumber(6000,
		"outbound-interface eth1",
		"source address 192.168.10.0/24",
		"destination address !224.0.0.0/8",
		"translation address 192.168.10.1",
	)
	tree.SetSnatWithRuleNumber(7000,
		"outbound-interface eth0",
		"source address 192.168.10.0/24",
		"destination address !224.0.0.0/8",
		"translation address 172.20.10.2",
	)
	tree.SetSnatWithRuleNumber(6500,
		"description eip-gw-snat",
		"outbound-interface eth1",
		"destination address 192.168.10.100",
		"translation address 192.168.10.1",
	)
	tree.SetSnatWithRuleNumber(6600,
		"outbound-interface eth2",
		"source address 2001:db8::/64",
		"destination address !224.0.0.0/8",
		"translation address 2001:db8::1",
	)
	tree.SetSnatWithRuleNumber(100,
		"description ipsec-exclude",
		"outbound-interface eth1",
		"destination address 10.10.0.0/24",
		"exclude",
	)

	if !RemoveSlbDefaultPrivateNicSnatRulesByVyos(tree) {
		t.Fatal("expected SLB private-local SNAT rule to be removed")
	}
	if tree.Get("nat source rule 6000") != nil {
		t.Fatal("private-local SNAT rule was not removed")
	}
	if tree.Get("nat source rule 7000") == nil {
		t.Fatal("public SNAT rule should not be removed")
	}
	if tree.Get("nat source rule 6500") == nil {
		t.Fatal("EIP gateway SNAT rule should not be removed")
	}
	if tree.Get("nat source rule 6600") == nil {
		t.Fatal("IPv6 private nic rule should not be removed by IPv4 SNAT cleanup")
	}
	if tree.Get("nat source rule 100") == nil {
		t.Fatal("IPsec exclude rule should not be removed")
	}
}

func TestAddPrivateNicSnatRuleByVyosSkipsUnsupportedPrivateSnat(t *testing.T) {
	originalBootstrapInfo := utils.BootstrapInfo
	defer func() {
		utils.BootstrapInfo = originalBootstrapInfo
	}()

	utils.BootstrapInfo = map[string]interface{}{}
	tree := server.NewParserFromConfiguration("").Tree
	if addPrivateNicSnatRuleByVyos(tree, "eth1", "2001:db8::1", "64") {
		t.Fatal("IPv6 private SNAT rule should not be added")
	}
	if tree.Get("nat source rule") != nil {
		t.Fatal("IPv6 private SNAT should not create nat source rules")
	}

	utils.BootstrapInfo = map[string]interface{}{
		"applianceVmSubType": utils.APPLIANCETYPE_SLB,
	}
	if addPrivateNicSnatRuleByVyos(tree, "eth1", "192.168.10.1", "255.255.255.0") {
		t.Fatal("SLB private SNAT rule should not be added")
	}
	if tree.Get("nat source rule") != nil {
		t.Fatal("SLB private SNAT should not create nat source rules")
	}
}

func TestGetAvailablePublicNicSNATRuleNumberSkipsOccupiedRules(t *testing.T) {
	tree := server.NewParserFromConfiguration("").Tree

	defaultRuleNo, _ := utils.GetPublicNicSNATRuleNumber(1)
	nextRuleNo, _ := utils.GetPublicNicSNATRuleNumber(2)
	tree.SetSnatWithRuleNumber(defaultRuleNo,
		"outbound-interface eth0",
		"source address 192.168.10.0/24",
		"destination address !224.0.0.0/8",
		"translation address 172.20.10.2",
	)

	ruleNo := getAvailablePublicNicSNATRuleNumber(tree, 1)
	if ruleNo != nextRuleNo {
		t.Fatalf("expected next available public SNAT rule %d, got %d", nextRuleNo, ruleNo)
	}
}
