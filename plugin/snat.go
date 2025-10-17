package plugin

import (
	"fmt"
	"strconv"

	"zstack-vyos/server"
	"zstack-vyos/utils"

	log "github.com/sirupsen/logrus"
)

const (
	SET_SNAT_PATH       = "/setsnat"
	REMOVE_SNAT_PATH    = "/removesnat"
	SYNC_SNAT_PATH      = "/syncsnat"
	SET_SNAT_STATE_PATH = "/setsnatservicestate"
)

type SnatInfo struct {
	PublicNicMac     string `json:"publicNicMac"`
	PublicIp         string `json:"publicIp"`
	PrivateNicMac    string `json:"privateNicMac"`
	PrivateNicIp     string `json:"privateNicIp"`
	PrivateGatewayIp string `json:"privateGatewayIp"`
	SnatNetmask      string `json:"snatNetmask"`
	State            bool   `json:"state"`
}

type SetSnatCmd struct {
	Snat SnatInfo `json:"snat"`
}

type RemoveSnatCmd struct {
	NatInfo []SnatInfo `json:"natInfo"`
}

type SyncSnatCmd struct {
	Snats  []SnatInfo `json:"snats"`
	Enable bool       `json:"enable"`
}

type SetSnatStateCmd struct {
	Snats  []SnatInfo `json:"snats"`
	Enable bool       `json:"enabled"`
}

type setNetworkServiceRsp struct {
	ServiceStatus string `json:"serviceStatus"`
}

func getNicSNATRuleNumberByConfig(tree *server.VyosConfigTree, snat SnatInfo, checkPubIp bool) (pubNicRuleNo int, priNicRuleNo int) {
	rules := tree.Get("nat source rule")
	ruleId1 := ""
	ruleId2 := ""
	if rules != nil {
		for _, r := range rules.Children() {
			outNic, err := utils.GetNicNameByMac(snat.PublicNicMac)
			utils.PanicOnError(err)
			address, err := utils.GetNetworkNumber(snat.PrivateNicIp, snat.SnatNetmask)
			utils.PanicOnError(err)
			sAddr := r.Get("source address")
			tAddr := r.Get("translation address")
			outIf := r.Get("outbound-interface")
			if sAddr != nil && sAddr.Value() == address &&
				tAddr != nil && tAddr.Value() == snat.PublicIp &&
				outIf != nil && outIf.Value() == outNic {
				ruleId1 = r.Name()
				break
			}
		}
		PrivateSnatIp := snat.PrivateGatewayIp
		if checkPubIp {
			PrivateSnatIp = snat.PublicIp
		}

		for _, r := range rules.Children() {
			inNic, err := utils.GetNicNameByMac(snat.PrivateNicMac)
			utils.PanicOnError(err)
			address, err := utils.GetNetworkNumber(snat.PrivateNicIp, snat.SnatNetmask)
			utils.PanicOnError(err)
			sAddr := r.Get("source address")
			tAddr := r.Get("translation address")
			outIf := r.Get("outbound-interface")
			if sAddr != nil && sAddr.Value() == address &&
				tAddr != nil && tAddr.Value() == PrivateSnatIp &&
				outIf != nil && outIf.Value() == inNic {
				ruleId2 = r.Name()
				break
			}
		}
	}
	ruleId3, _ := strconv.Atoi(ruleId1)
	ruleId4, _ := strconv.Atoi(ruleId2)
	return ruleId3, ruleId4
}

// Deprecated
func setSnatHandler(ctx *server.CommandContext) interface{} {
	cmd := &SetSnatCmd{}
	ctx.GetCommand(cmd)

	return SetSnat(cmd)
}

// Deprecated
func SetSnat(cmd *SetSnatCmd) interface{} {
	s := cmd.Snat
	outNic, err := utils.GetNicNameByMac(s.PublicNicMac)
	utils.PanicOnError(err)
	inNic, err := utils.GetNicNameByMac(s.PrivateNicMac)
	utils.PanicOnError(err)
	nicNumber, err := utils.GetNicNumber(inNic)
	utils.PanicOnError(err)
	address, err := utils.GetNetworkNumber(s.PrivateNicIp, s.SnatNetmask)
	utils.PanicOnError(err)

	if utils.IsSkipVyosIptables() {
		table := utils.NewIpTables(utils.NatTable)

		var rules []*utils.IpTableRule

		rule := utils.NewIpTableRule(utils.RULESET_SNAT.String())
		rule.SetAction(utils.IPTABLES_ACTION_SNAT).SetComment(utils.SNATComment)
		rule.SetDstIp("! 224.0.0.0/8").SetSrcIp(address).SetOutNic(outNic).SetSnatTargetIp(s.PublicIp)
		rules = append(rules, rule)

		table.AddIpTableRules(rules)
		err := table.Apply()
		utils.PanicOnError(err)

		utils.AddSnatRuleForPrivateNic(inNic, s.PrivateNicIp, s.SnatNetmask)
	} else {
		// make source nat rule as the latest rule
		// in case there are EIP rules
		tree := server.NewParserFromShowConfiguration().Tree
		pubNicRuleNo, _ := utils.GetPublicNicSNATRuleNumber(nicNumber)
		setted := false
		if !hasRuleNumberForAddress(tree, address, pubNicRuleNo) {
			tree.SetSnatWithRuleNumber(pubNicRuleNo,
				fmt.Sprintf("outbound-interface %s", outNic),
				fmt.Sprintf("source address %v", address),
				"destination address !224.0.0.0/8",
				fmt.Sprintf("translation address %s", s.PublicIp),
			)
			setted = true
		}

		if setted {
			tree.Apply(false)
		}
	}

	return nil
}

func removeSnatHandler(ctx *server.CommandContext) interface{} {
	cmd := &RemoveSnatCmd{}
	ctx.GetCommand(&cmd)

	return RemoveSnat(cmd)
}

func RemoveSnat(cmd *RemoveSnatCmd) interface{} {
	if utils.IsSkipVyosIptables() {

		table := utils.NewIpTables(utils.NatTable)
		for _, s := range cmd.NatInfo {
			publicNic, err := utils.GetNicNameByMac(s.PublicNicMac)
			utils.PanicOnError(err)

			address, err := utils.GetNetworkNumber(s.PrivateNicIp, s.SnatNetmask)
			utils.PanicOnError(err)

			rule := utils.NewIpTableRule(utils.RULESET_SNAT.String())
			rule.SetAction(utils.IPTABLES_ACTION_SNAT).SetComment(utils.SNATComment)
			rule.SetDstIp("! 224.0.0.0/8").SetSrcIp(address).SetOutNic(publicNic).SetSnatTargetIp(s.PublicIp)
			table.RemoveIpTableRule([]*utils.IpTableRule{rule})

		}

		err := table.Apply()
		utils.PanicOnError(err)
	} else {
		tree := server.NewParserFromShowConfiguration().Tree

		for _, s := range cmd.NatInfo {
			pubNicRuleNo, _ := getNicSNATRuleNumberByConfig(tree, s, false)
			if rs := tree.Get(fmt.Sprintf("nat source rule %v", pubNicRuleNo)); rs == nil {
				log.Debugf(fmt.Sprintf("nat source rule %v not found", pubNicRuleNo))
			} else {
				rs.Delete()
			}

		}
		tree.Apply(false)
	}

	return nil
}

func hasRuleNumberForAddress(tree *server.VyosConfigTree, address string, ruleNo int) bool {
	rs := tree.Get(fmt.Sprintf("nat source rule %v", ruleNo))
	if rs == nil {
		return false
	}

	return true
}

func setSnatStateByIptables(Snats []SnatInfo, state bool) {
	table := utils.NewIpTables(utils.NatTable)

	var rules []*utils.IpTableRule
	for _, s := range Snats {
		outNic, err := utils.GetNicNameByMac(s.PublicNicMac)
		utils.PanicOnError(err)

		address, err := utils.GetNetworkNumber(s.PrivateNicIp, s.SnatNetmask)
		utils.PanicOnError(err)

		rule := utils.NewIpTableRule(utils.RULESET_SNAT.String())
		rule.SetAction(utils.IPTABLES_ACTION_SNAT).SetComment(utils.SNATComment)
		rule.SetDstIp("! 224.0.0.0/8").SetSrcIp(address).SetOutNic(outNic).SetSnatTargetIp(s.PublicIp)
		rules = append(rules, rule)

	}

	if state == false {
		table.RemoveIpTableRule(rules)
	} else {
		table.AddIpTableRules(rules)
	}

	err := table.Apply()
	utils.PanicOnError(err)

}

func syncSnatByIptables(Snats []SnatInfo, state bool) {

	/* delete all snat rules */
	table := utils.NewIpTables(utils.NatTable)
	table.RemoveIpTableRuleByComments(utils.SNATComment)

	if state == false {
		err := table.Apply()
		utils.PanicOnError(err)
		return
	}

	var rules []*utils.IpTableRule
	for _, s := range Snats {
		if !s.State {
			continue
		}
		outNic, err := utils.GetNicNameByMac(s.PublicNicMac)
		utils.PanicOnError(err)
		address, err := utils.GetNetworkNumber(s.PrivateNicIp, s.SnatNetmask)
		utils.PanicOnError(err)

		rule := utils.NewIpTableRule(utils.RULESET_SNAT.String())
		rule.SetAction(utils.IPTABLES_ACTION_SNAT).SetComment(utils.SNATComment)
		rule.SetDstIp("! 224.0.0.0/8").SetSrcIp(address).SetOutNic(outNic).SetSnatTargetIp(s.PublicIp)
		rules = append(rules, rule)
	}

	table.AddIpTableRules(rules)
	err := table.Apply()
	utils.PanicOnError(err)

}

func applySnatRules(Snats []SnatInfo, state bool) bool {
	tree := server.NewParserFromShowConfiguration().Tree

	update := false
	for _, s := range Snats {
		outNic, err := utils.GetNicNameByMac(s.PublicNicMac)
		utils.PanicOnError(err)
		inNic, err := utils.GetNicNameByMac(s.PrivateNicMac)
		utils.PanicOnError(err)
		nicNumber, err := utils.GetNicNumber(inNic)
		utils.PanicOnError(err)
		address, err := utils.GetNetworkNumber(s.PrivateNicIp, s.SnatNetmask)
		utils.PanicOnError(err)

		pubNicRuleNo, _ := getNicSNATRuleNumberByConfig(tree, s, false)
		if s.State == true {
			newPubNicRuleNo, _ := utils.GetPublicNicSNATRuleNumber(nicNumber)

			if pubNicRuleNo == 0 {
				pubNicRuleNo = newPubNicRuleNo
				pubRule := tree.Getf("nat source rule %v", pubNicRuleNo)
				if pubRule == nil {
					tree.SetSnatWithRuleNumber(pubNicRuleNo,
						fmt.Sprintf("outbound-interface %s", outNic),
						fmt.Sprintf("source address %s", address),
						"destination address !224.0.0.0/8",
						fmt.Sprintf("translation address %s", s.PublicIp),
					)
					update = true
				}
			}

		} else {
			pubNicRuleNo, _ = getNicSNATRuleNumberByConfig(tree, s, false)
			if rs := tree.Getf("nat source rule %v", pubNicRuleNo); rs != nil {
				update = true
				rs.Delete()
			}

		}

	}

	tree.Apply(false)
	return update
}

func setSnatStateHandler(ctx *server.CommandContext) interface{} {
	cmd := &SetSnatStateCmd{}
	ctx.GetCommand(cmd)

	return SetSnatState(cmd)
}

func SetSnatState(cmd *SetSnatStateCmd) interface{} {
	if utils.IsSkipVyosIptables() {
		setSnatStateByIptables(cmd.Snats, cmd.Enable)
	} else {
		update := applySnatRules(cmd.Snats, cmd.Enable)
		if update && len(cmd.Snats) > 0 {
			/* after snat is enabled, delete connections which is not snat */
			t := utils.ConnectionTrackTuple{IsNat: false, IsDst: true, Ip: cmd.Snats[0].PublicIp, Protocol: "",
				PortStart: 0, PortEnd: 0}
			t.CleanConnTrackConnection()
		}
	}

	if cmd.Enable {
		return setNetworkServiceRsp{ServiceStatus: "enable"}
	} else {
		t := utils.ConnectionTrackTuple{IsNat: true, IsDst: false, Ip: cmd.Snats[0].PublicIp, Protocol: "",
			PortStart: 0, PortEnd: 0}
		t.CleanConnTrackConnection()
		return setNetworkServiceRsp{ServiceStatus: "disable"}
	}
}

func syncSnatHandler(ctx *server.CommandContext) interface{} {
	cmd := &SyncSnatCmd{}
	ctx.GetCommand(cmd)

	return SyncSnat(cmd)
}

func SyncSnat(cmd *SyncSnatCmd) interface{} {
	if utils.IsSkipVyosIptables() {
		syncSnatByIptables(cmd.Snats, cmd.Enable)
	} else {
		update := applySnatRules(cmd.Snats, cmd.Enable)
		if update && len(cmd.Snats) > 0 {
			/* after snat is enabled, delete connections which is not snat */
			t := utils.ConnectionTrackTuple{IsNat: false, IsDst: true, Ip: cmd.Snats[0].PublicIp, Protocol: "",
				PortStart: 0, PortEnd: 0}
			t.CleanConnTrackConnection()
		}
	}

	// ensure private SNAT rules exist when enabled:
	// collect all unique private NICs and their CIDRs
	type priInfo struct {
		nicName string
		nicIp   string
		netmask string
		addr    string
	}
	privates := make(map[string]priInfo) // key: private MAC
	for _, s := range cmd.Snats {
		if _, ok := privates[s.PrivateNicMac]; ok {
			continue
		}

		// derive nic name, cidr and ip
		inNic, err := utils.GetNicNameByMac(s.PrivateNicMac)
		if err != nil || inNic == "" {
			continue
		}
		address, err := utils.GetNetworkNumber(s.PrivateNicIp, s.SnatNetmask)
		if err != nil || address == "" {
			continue
		}
		privates[s.PrivateNicMac] = priInfo{
			nicName: inNic,
			nicIp:   s.PrivateNicIp,
			netmask: s.SnatNetmask,
			addr:    address,
		}
	}

	// add missing private SNAT rules per mode
	if utils.IsSkipVyosIptables() {
		for _, p := range privates {
			_ = utils.AddSnatRuleForPrivateNic(p.nicName, p.nicIp, p.netmask)
		}
	} else {
		tree := server.NewParserFromShowConfiguration().Tree
		updated := false
		for _, p := range privates {
			nicNo, err := utils.GetNicNumber(p.nicName)
			if err != nil {
				continue
			}
			ruleNo := utils.GetPrivateNicSNATRuleNumber(nicNo)
			// scan existing nat source rules to see if one matches fields:
			rules := tree.Get("nat source rule")
			exists := false
			if rules != nil {
				for _, r := range rules.Children() {
					outIf := r.Get("outbound-interface")
					sAddr := r.Get("source address")
					tAddr := r.Get("translation address")
					if outIf != nil && outIf.Value() == p.nicName &&
						sAddr != nil && sAddr.Value() == p.addr &&
						tAddr != nil && tAddr.Value() == p.nicIp {
						exists = true
						break
					}
				}
			}
			if !exists {
				tree.SetSnatWithRuleNumber(ruleNo,
					fmt.Sprintf("outbound-interface %s", p.nicName),
					fmt.Sprintf("source address %s", p.addr),
					"destination address !224.0.0.0/8",
					fmt.Sprintf("translation address %s", p.nicIp),
				)
				updated = true
			}
		}
		if updated {
			tree.Apply(false)
		}
	}

	return nil
}

func SnatEntryPoint() {
	server.RegisterAsyncCommandHandler(SET_SNAT_PATH, server.VyosLock(setSnatHandler))
	server.RegisterAsyncCommandHandler(REMOVE_SNAT_PATH, server.VyosLock(removeSnatHandler))
	server.RegisterAsyncCommandHandler(SYNC_SNAT_PATH, server.VyosLock(syncSnatHandler))
	server.RegisterAsyncCommandHandler(SET_SNAT_STATE_PATH, server.VyosLock(setSnatStateHandler))
}
