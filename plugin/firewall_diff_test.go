package plugin

import (
	"testing"
	"zstack-vyos/server"
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
