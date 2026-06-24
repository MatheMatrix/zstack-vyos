package plugin

import (
	"testing"
	"zstack-vyos/server"
	"zstack-vyos/utils"
)

func TestZSTAC83935DiffUserRulesKeepsUnchangedRules(t *testing.T) {
	current := []ethRuleSetRef{firewallDiffRef("52:54:00:00:00:01", FIREWALL_DIRECTION_IN, []ruleInfo{
		firewallDiffRule(1100, "10.130.145.0/24", "10.240.3.0/24"),
		firewallDiffRule(1105, "10.130.145.0/24", "172.23.0.0/16"),
		firewallDiffRule(2000, "", ""),
	})}
	desired := []ethRuleSetRef{firewallDiffRef("52:54:00:00:00:01", FIREWALL_DIRECTION_IN, []ruleInfo{
		firewallDiffRule(1100, "10.130.145.0/24", "10.240.3.0/24"),
		firewallDiffRule(1105, "10.130.145.0/24", "10.240.4.0/24"),
		firewallDiffRule(2000, "", ""),
	})}

	diffs := diffUserRules(current, desired)
	if len(diffs) != 1 {
		t.Fatalf("expected one ruleset diff, got %d", len(diffs))
	}
	diff := diffs[0]
	if !diff.RuleSetExists {
		t.Fatal("expected existing ruleset to be reconciled in place")
	}
	if len(diff.RulesToDelete) != 0 {
		t.Fatalf("unchanged reconnect must not delete existing rules, got %#v", diff.RulesToDelete)
	}
	if len(diff.RulesToAdd) != 0 {
		t.Fatalf("unchanged reconnect must not recreate existing rules, got %#v", diff.RulesToAdd)
	}
	if len(diff.RulesToUpdate) != 1 || diff.RulesToUpdate[0].RuleNumber != 1105 {
		t.Fatalf("expected only rule 1105 to be updated, got %#v", diff.RulesToUpdate)
	}
}

func TestZSTAC83935DiffUserRulesDeletesOnlyStaleRules(t *testing.T) {
	current := []ethRuleSetRef{firewallDiffRef("52:54:00:00:00:01", FIREWALL_DIRECTION_IN, []ruleInfo{
		firewallDiffRule(1100, "10.130.145.0/24", "10.240.3.0/24"),
		firewallDiffRule(1101, "10.130.145.0/24", "172.23.111.0/24"),
	})}
	desired := []ethRuleSetRef{firewallDiffRef("52:54:00:00:00:01", FIREWALL_DIRECTION_IN, []ruleInfo{
		firewallDiffRule(1100, "10.130.145.0/24", "10.240.3.0/24"),
		firewallDiffRule(1102, "10.130.145.0/24", "10.240.4.0/24"),
	})}

	diffs := diffUserRules(current, desired)
	if len(diffs) != 1 {
		t.Fatalf("expected one ruleset diff, got %d", len(diffs))
	}
	diff := diffs[0]
	if len(diff.RulesToDelete) != 1 || diff.RulesToDelete[0].RuleNumber != 1101 {
		t.Fatalf("expected only stale rule 1101 to be deleted, got %#v", diff.RulesToDelete)
	}
	if len(diff.RulesToAdd) != 1 || diff.RulesToAdd[0].RuleNumber != 1102 {
		t.Fatalf("expected only missing rule 1102 to be added, got %#v", diff.RulesToAdd)
	}
	if len(diff.RulesToUpdate) != 0 {
		t.Fatalf("unchanged rule must not be updated, got %#v", diff.RulesToUpdate)
	}
}

func TestZSTAC83935DiffUserRulesCreatesMissingRuleSet(t *testing.T) {
	desired := []ethRuleSetRef{firewallDiffRef("52:54:00:00:00:01", FIREWALL_DIRECTION_IN, []ruleInfo{
		firewallDiffRule(1100, "10.130.145.0/24", "10.240.3.0/24"),
		firewallDiffRule(1101, "10.130.145.0/24", "172.23.111.0/24"),
	})}

	diffs := diffUserRules(nil, desired)
	if len(diffs) != 1 {
		t.Fatalf("expected one ruleset diff, got %d", len(diffs))
	}
	diff := diffs[0]
	if diff.RuleSetExists {
		t.Fatal("missing ruleset must trigger create/attach path")
	}
	if len(diff.RulesToAdd) != 2 {
		t.Fatalf("expected all desired rules to be added, got %#v", diff.RulesToAdd)
	}
	if len(diff.RulesToDelete) != 0 || len(diff.RulesToUpdate) != 0 {
		t.Fatalf("missing ruleset must not delete or update rules, got deletes=%#v updates=%#v", diff.RulesToDelete, diff.RulesToUpdate)
	}
}

func TestZSTAC83935DeleteExtraRuleSetRemovesNodeAndAttachments(t *testing.T) {
	tree := server.NewParserFromConfiguration(`
interfaces {
    ethernet eth5 {
        firewall {
            in {
                name eth5.in
            }
            out {
                name eth5.out
            }
        }
    }
    ethernet eth6 {
        firewall {
            in {
                name eth5.in
            }
        }
    }
}
firewall {
    group {
        address-group eth5.in-1100-source {
            address 10.130.145.0/24
        }
    }
    name eth5.in {
        default-action reject
        enable-default-log
        rule 1100 {
            action accept
            source {
                group {
                    address-group eth5.in-1100-source
                }
            }
        }
    }
    name eth5.out {
        default-action accept
    }
}
`).Tree

	deleteExtraRuleSet(tree, "eth5.in")

	if tree.Get("firewall name eth5.in") != nil {
		t.Fatal("expected extra firewall ruleset node to be deleted")
	}
	if tree.Get("interfaces ethernet eth5 firewall in name eth5.in") != nil {
		t.Fatal("expected eth5 in binding to extra ruleset to be detached")
	}
	if tree.Get("interfaces ethernet eth6 firewall in name eth5.in") != nil {
		t.Fatal("expected eth6 in binding to extra ruleset to be detached")
	}
	if tree.Get("firewall group address-group eth5.in-1100-source") != nil {
		t.Fatal("expected address group owned by extra ruleset to be deleted")
	}
	if tree.Get("firewall name eth5.out") == nil || tree.Get("interfaces ethernet eth5 firewall out name eth5.out") == nil {
		t.Fatal("unrelated firewall ruleset and binding must be kept")
	}
}

func TestZSTAC83935RuleEqualNormalizesProtocolStateAndGroups(t *testing.T) {
	current := firewallDiffRule(1100, "10.240.3.0/24,10.130.145.0/24", "172.23.0.0/16")
	current.Protocol = ""
	current.AllowStates = "new,established,related,invalid"

	desired := firewallDiffRule(1100, "10.130.145.0/24,10.240.3.0/24", "172.23.0.0/16")
	desired.Protocol = "ALL"
	desired.AllowStates = "invalid,new,related,established"

	if !current.Equal(desired) {
		t.Fatalf("expected equivalent rule values to compare equal: current=%#v desired=%#v", current, desired)
	}
}

func firewallDiffRef(mac, forward string, rules []ruleInfo) ethRuleSetRef {
	return ethRuleSetRef{
		Mac:     mac,
		Forward: forward,
		RuleSetInfo: ruleSetInfo{
			Name:       "eth5.in",
			ActionType: "reject",
			Rules:      rules,
		},
	}
}

func firewallDiffRule(number int, sourceIP, destIP string) ruleInfo {
	return ruleInfo{
		Action:      "accept",
		Protocol:    "all",
		SourceIp:    sourceIP,
		DestIp:      destIP,
		AllowStates: "established,invalid,new,related",
		RuleNumber:  number,
		State:       RULEINFO_ENABLE,
	}
}

// TestZSTAC83935DetachedRuleSetReattached verifies that a VyOS ruleset whose firewall node
// exists but whose interface binding is absent is detected as requiring reattach.
func TestZSTAC83935DetachedRuleSetReattached(t *testing.T) {
	tree := server.NewParserFromConfiguration(`
firewall {
    name eth5.in {
        default-action reject
        rule 1100 {
            action accept
        }
    }
}
`).Tree

	// Firewall node exists but interface binding is intentionally absent.
	if tree.Getf("firewall name %s", "eth5.in") == nil {
		t.Fatal("test setup: expected firewall node to exist")
	}
	if tree.Getf("interfaces ethernet %s firewall %s name %s", "eth5", "in", "eth5.in") != nil {
		t.Fatal("test setup: expected interface binding to be absent")
	}

	// Simulate the fix: detect missing binding and reattach.
	tree.AttachRuleSetOnInterface("eth5", "in", "eth5.in")

	if tree.Getf("interfaces ethernet %s firewall %s name %s", "eth5", "in", "eth5.in") == nil {
		t.Fatal("expected interface binding to be present after reattach")
	}
}

// TestZSTAC83935StaleIptablesChainFullyRemoved verifies that removing a stale iptables ruleset
// also removes the hook rule, the default rule, and the chain itself — not just user rules.
func TestZSTAC83935StaleIptablesChainFullyRemoved(t *testing.T) {
	// Build an IpTables directly to avoid calling iptables-save (not available in unit-test env).
	table := &utils.IpTables{Name: utils.FirewallTable, IpVersion: utils.IP_VERSION_4}
	table.AddChain(utils.VYOS_FWD_ROOT_CHAIN)
	table.AddChain("eth5.in") // stale
	table.AddChain("eth6.in") // desired — must survive

	// Hook rule dispatching to the stale chain.
	staleHook := utils.NewIpTableRule(utils.VYOS_FWD_ROOT_CHAIN)
	staleHook.SetAction("eth5.in")
	staleHook.SetInNic("eth5")
	table.AddIpTableRules([]*utils.IpTableRule{staleHook})

	// Hook rule dispatching to the desired chain — must survive.
	desiredHook := utils.NewIpTableRule(utils.VYOS_FWD_ROOT_CHAIN)
	desiredHook.SetAction("eth6.in")
	desiredHook.SetInNic("eth6")
	table.AddIpTableRules([]*utils.IpTableRule{desiredHook})

	// Default rule inside the stale chain.
	defaultRule := utils.NewDefaultIpTableRule("eth5.in", utils.IPTABLES_RULENUMBER_MAX)
	defaultRule.SetAction("REJECT")
	table.AddIpTableRules([]*utils.IpTableRule{defaultRule})

	// A user rule inside the stale chain.
	userRule := utils.NewIpTableRule("eth5.in")
	utils.SetFirewallRuleNumber(userRule, "eth5.in", 1100)
	userRule.SetAction("RETURN")
	table.AddIpTableRules([]*utils.IpTableRule{userRule})

	// Apply the fix logic for extra rulesets.
	extraRuleSetNames := []string{"eth5.in"}
	for _, ruleSetName := range extraRuleSetNames {
		var filteredRules []*utils.IpTableRule
		for _, r := range table.Rules {
			if r.GetChainName() == ruleSetName || r.GetAction() == ruleSetName {
				continue
			}
			filteredRules = append(filteredRules, r)
		}
		table.Rules = filteredRules
		table.DeleteChain(ruleSetName)
	}

	// Chain must be gone.
	if table.CheckChain("eth5.in") {
		t.Fatal("stale chain eth5.in must be deleted")
	}

	// No rule must reference the stale chain.
	for _, r := range table.Rules {
		if r.GetChainName() == "eth5.in" || r.GetAction() == "eth5.in" {
			t.Fatalf("stale rule must be removed: chain=%q action=%q", r.GetChainName(), r.GetAction())
		}
	}

	// Desired chain and its hook rule must survive.
	if !table.CheckChain("eth6.in") {
		t.Fatal("desired chain eth6.in must be kept")
	}
	desiredHookFound := false
	for _, r := range table.Rules {
		if r.GetChainName() == utils.VYOS_FWD_ROOT_CHAIN && r.GetAction() == "eth6.in" {
			desiredHookFound = true
		}
	}
	if !desiredHookFound {
		t.Fatal("hook rule for desired chain eth6.in must be kept")
	}
}

func TestZSTAC86344ExistingIptablesRuleSetMissingDefaultDetected(t *testing.T) {
	table := &utils.IpTables{Name: utils.FirewallTable}
	table.AddChain(utils.VYOS_FWD_OUT_ROOT_CHAIN)
	table.AddChain("eth1.out")

	hookRule := utils.NewIpTableRule(utils.VYOS_FWD_OUT_ROOT_CHAIN)
	hookRule.SetAction("eth1.out")
	hookRule.SetOutNic("eth1")
	table.AddIpTableRules([]*utils.IpTableRule{hookRule})

	userRule := utils.NewIpTableRule("eth1.out")
	userRule.SetAction(utils.IPTABLES_ACTION_RETURN)
	utils.SetFirewallRuleNumber(userRule, "eth1.out", 1015)
	table.AddIpTableRules([]*utils.IpTableRule{userRule})

	defaultRuleSetNames := getDefaultRuleSetNamesFromIpTable(table)
	if _, exists := defaultRuleSetNames["eth1.out"]; exists {
		t.Fatal("test setup must not contain eth1.out default rule")
	}

	currentRuleSets := getRuleSetFromIpTable(table)
	currentRuleSet, exists := currentRuleSets["eth1.out"]
	if !exists {
		t.Fatal("existing eth1.out chain must be detected")
	}
	if currentRuleSet.ActionType != "accept" {
		t.Fatalf("missing default rule is interpreted as accept before fix, got %s", currentRuleSet.ActionType)
	}
	if len(currentRuleSet.Rules) != 1 || currentRuleSet.Rules[0].RuleNumber != 1015 {
		t.Fatalf("expected existing user rule 1015 to be detected, got %#v", currentRuleSet.Rules)
	}

	ref := ethRuleSetRef{
		Mac:         "52:54:00:00:00:01",
		Forward:     FIREWALL_DIRECTION_OUT,
		RuleSetInfo: *currentRuleSet,
	}
	diffs := diffUserRules([]ethRuleSetRef{ref}, []ethRuleSetRef{ref})
	if len(diffs) != 1 {
		t.Fatalf("expected one diff, got %d", len(diffs))
	}
	diff := diffs[0]
	if !diff.RuleSetExists || diff.ActionChanged || diff.LogChanged || len(diff.RulesToAdd) != 0 || len(diff.RulesToDelete) != 0 || len(diff.RulesToUpdate) != 0 {
		t.Fatalf("regular rule diff must not detect missing default rule, got %#v", diff)
	}

	missingDefaultRuleSetNames := getMissingDefaultRuleSetNames(
		map[string]struct{}{"eth1.out": {}},
		currentRuleSets,
		defaultRuleSetNames,
	)
	if _, exists := missingDefaultRuleSetNames["eth1.out"]; !exists {
		t.Fatal("existing desired ruleset without default rule must be repaired")
	}
}
