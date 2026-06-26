package plugin

import (
	"strings"
	"testing"
	"zstack-vyos/utils"
)

func TestZSTAC81326PimdSkipsBondSriovSlaves(t *testing.T) {
	nics := map[string]utils.Nic{
		"eth1": {
			Name: "eth1",
			Mac:  "fa:20:cb:25:5d:01",
		},
		"eth1-phy1": {
			Name: "eth1-phy1",
			Mac:  "fa:20:cb:25:5d:01",
		},
		"eth1-phy2": {
			Name: "eth1-phy2",
			Mac:  "fa:20:cb:25:5d:01",
		},
	}

	var rendered strings.Builder
	for _, rule := range getPimdFirewallByNic(nics) {
		rendered.WriteString(rule.String())
	}

	rules := rendered.String()
	if !strings.Contains(rules, "eth1.local") || !strings.Contains(rules, "eth1.in") {
		t.Fatalf("expected pimd rules for bond master eth1, got:\n%s", rules)
	}
	if strings.Contains(rules, "eth1-phy1") || strings.Contains(rules, "eth1-phy2") {
		t.Fatalf("pimd rules must not be generated for bond slaves, got:\n%s", rules)
	}
}
