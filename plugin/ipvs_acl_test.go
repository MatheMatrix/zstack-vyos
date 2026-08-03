package plugin

import (
	"reflect"
	"testing"
	"zstack-vyos/utils"
)

func TestParseIpvsAclConfigMatchesUdpEmptyEntrySemantics(t *testing.T) {
	aclType, aclEntries, enabled := parseIpvsAclConfig([]string{
		"accessControlStatus::enable",
		"aclType::black",
		"aclEntry::",
	})

	if enabled {
		t.Fatalf("empty aclEntry must not enable ipvs acl, got type=%q entries=%v", aclType, aclEntries)
	}
}

func TestParseIpvsAclConfigTrimsEntries(t *testing.T) {
	aclType, aclEntries, enabled := parseIpvsAclConfig([]string{
		"accessControlStatus::enable",
		"aclType::white",
		"aclEntry:: 10.0.0.10/32, ,10.0.0.20-10.0.0.30 ",
	})

	if !enabled {
		t.Fatal("expected non-empty acl entries to enable ipvs acl")
	}
	if aclType != "white" {
		t.Fatalf("unexpected acl type: %s", aclType)
	}
	expected := []string{"10.0.0.10/32", "10.0.0.20-10.0.0.30"}
	if !reflect.DeepEqual(expected, aclEntries) {
		t.Fatalf("unexpected acl entries: %v", aclEntries)
	}
}

func TestTcpIpvsAclRulesMatchUdpAclSemantics(t *testing.T) {
	fs := &IpvsFrontendService{
		FrontIp:   "172.24.7.153",
		FrontPort: "19086",
		AclType:   "white",
		AclEntry:  []string{"10.0.0.10/32", "10.0.0.20-10.0.0.30"},
	}
	table := &utils.IpTables{Name: utils.FirewallTable}

	rules := addAclRules(table, fs, "eth1", utils.IPTABLES_PROTO_TCP)

	if !table.CheckChain("acl-rules@eth1@19086") {
		t.Fatal("expected tcp ipvs acl chain to be created")
	}
	if len(rules) != 5 {
		t.Fatalf("expected jump, two allow rules, default reject and return, got %d", len(rules))
	}

	jump := rules[0]
	if jump.GetChainName() != "eth1.local" || jump.GetAction() != "acl-rules@eth1@19086" {
		t.Fatalf("unexpected tcp acl jump rule: %s", jump.String())
	}
	if jump.GetProto() != utils.IPTABLES_PROTO_TCP || jump.GetDstPort() != "19086" {
		t.Fatalf("tcp acl jump rule must match tcp frontend port: %s", jump.String())
	}

	firstAllow := rules[1]
	if firstAllow.GetAction() != utils.IPTABLES_ACTION_ACCEPT ||
		firstAllow.GetProto() != utils.IPTABLES_PROTO_TCP ||
		firstAllow.GetDstIp() != "172.24.7.153/32" ||
		firstAllow.GetDstPort() != "19086" ||
		firstAllow.GetSrcIp() != "10.0.0.10/32" {
		t.Fatalf("unexpected tcp whitelist allow rule: %s", firstAllow.String())
	}

	rangeAllow := rules[2]
	if rangeAllow.GetAction() != utils.IPTABLES_ACTION_ACCEPT ||
		rangeAllow.GetSrcIpRange() != "10.0.0.20-10.0.0.30" {
		t.Fatalf("unexpected tcp whitelist range rule: %s", rangeAllow.String())
	}

	defaultReject := rules[3]
	if defaultReject.GetAction() != utils.IPTABLES_ACTION_REJECT ||
		defaultReject.GetRejectType() != utils.REJECT_TYPE_ICMP_UNREACHABLE {
		t.Fatalf("tcp whitelist must reject unmatched sources: %s", defaultReject.String())
	}

	if rules[4].GetAction() != utils.IPTABLES_ACTION_RETURN {
		t.Fatalf("expected tcp acl chain to end with return: %s", rules[4].String())
	}
}

func TestTcpIpvsBlacklistRejectsMatchedSources(t *testing.T) {
	fs := &IpvsFrontendService{
		FrontIp:   "172.24.7.153",
		FrontPort: "19086",
		AclType:   "black",
		AclEntry:  []string{"10.0.0.10/32"},
	}
	table := &utils.IpTables{Name: utils.FirewallTable}

	rules := addAclRules(table, fs, "eth1", utils.IPTABLES_PROTO_TCP)

	if len(rules) != 3 {
		t.Fatalf("expected jump, reject and return, got %d", len(rules))
	}

	reject := rules[1]
	if reject.GetAction() != utils.IPTABLES_ACTION_REJECT ||
		reject.GetRejectType() != utils.REJECT_TYPE_ICMP_UNREACHABLE ||
		reject.GetProto() != utils.IPTABLES_PROTO_TCP ||
		reject.GetSrcIp() != "10.0.0.10/32" {
		t.Fatalf("unexpected tcp blacklist reject rule: %s", reject.String())
	}
}

func TestCleanupIpvsAclChainsOnlyRemovesIpvsAclChains(t *testing.T) {
	table := &utils.IpTables{Name: utils.FirewallTable}
	table.AddChain("acl-rules@eth1@33013")
	table.AddChain("acl-rules@eth0@33014")
	table.AddChain("eth1.local")

	cleanupIpvsAclChains(table)

	if table.CheckChain("acl-rules@eth1@33013") {
		t.Fatal("expected stale shared ipvs acl chain to be removed")
	}
	if table.CheckChain("acl-rules@eth0@33014") {
		t.Fatal("expected stale separate ipvs acl chain to be removed")
	}
	if !table.CheckChain("eth1.local") {
		t.Fatal("non-ipvs acl chain must not be removed")
	}
}
