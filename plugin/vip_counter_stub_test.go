package plugin

// vipCounterRuleInfo holds the parsed rule information for a VIP counter chain entry.
type vipCounterRuleInfo struct {
	Destination  string
	Destination6 string
	Source       string
	Source6      string
}

// ParseVipCounterFromIptables parses the iptables rules in the given counter chain and returns
// a map from VIP UUID (comment field) to its rule info. This is a stub for compilation;
// a full implementation would invoke iptables-save and parse the output.
func ParseVipCounterFromIptables(chainName string, isOut bool) map[string]vipCounterRuleInfo {
	return make(map[string]vipCounterRuleInfo)
}
