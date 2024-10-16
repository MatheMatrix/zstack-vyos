package plugin

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/zstackio/zstack-vyos/server"
	"github.com/zstackio/zstack-vyos/utils"
	"io/ioutil"
	"strconv"
	"strings"
	"time"
)

const (
	SET_VYOSHA_PATH = "/enableVyosha"
)

type setVyosHaCmd struct {
	Keepalive    int          `json:"keepalive"`
	HeartbeatNic string       `json:"heartbeatNic"`
	LocalIp      string       `json:"localIp"`
	PeerIp       string       `json:"peerIp"`
	Monitors     []string     `json:"monitors"`
	Vips         []macVipPair `json:"vips"`
	CallbackUrl  string       `json:"callbackUrl"`
}

type macVipPair struct {
	NicMac   string `json:"nicMac"`
	NicVip   string `json:"nicVip"`
	Netmask  string `json:"netmask"`
	Category string `json:"category"`
}

var (
	haStatusCallbackUrl      = ""
	getKeepAlivedStatusStart = false
	keepAlivedCheckStart     = false
)

func setVyosHaHandler(ctx *server.CommandContext) interface{} {
	cmd := &setVyosHaCmd{}
	ctx.GetCommand(cmd)

	return setVyosHa(cmd)
}

func setVyosHa(cmd *setVyosHaCmd) interface{} {
	if cmd.PeerIp == "" {
		cmd.PeerIp = cmd.LocalIp
	}

	heartbeatNicNme, _ := utils.GetNicNameByMac(cmd.HeartbeatNic)
	/* add firewall */
	tree := server.NewParserFromShowConfiguration().Tree
	if utils.IsSkipVyosIptables() {
		table := utils.NewIpTables(utils.FirewallTable)
		var rules []*utils.IpTableRule

		rule := utils.NewIpTableRule(utils.GetRuleSetName(heartbeatNicNme, utils.RULESET_LOCAL))
		rule.SetAction(utils.IPTABLES_ACTION_ACCEPT).SetComment(utils.SystemTopRule)
		rule.SetProto(utils.IPTABLES_PROTO_VRRP).SetSrcIp(cmd.PeerIp + "/32")
		rules = append(rules, rule)

		rule = utils.NewIpTableRule(utils.GetRuleSetName(heartbeatNicNme, utils.RULESET_LOCAL))
		rule.SetAction(utils.IPTABLES_ACTION_ACCEPT).SetComment(utils.SystemTopRule)
		rule.SetProto(utils.IPTABLES_PROTO_UDP).SetSrcIp(cmd.PeerIp + "/32").SetDstPort("3780")
		rules = append(rules, rule)
		table.AddIpTableRules(rules)

		if err := table.Apply(); err != nil {
			log.Debugf("apply vrrp firewall table failed")
			return err
		}

		natTable := utils.NewIpTables(utils.NatTable)
		rule = utils.NewIpTableRule(utils.RULESET_SNAT.String())
		rule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.SystemTopRule)
		rule.SetProto(utils.IPTABLES_PROTO_VRRP)
		natTable.AddIpTableRules([]*utils.IpTableRule{rule})

		if err := natTable.Apply(); err != nil {
			log.Debugf("apply vrrp nat table failed")
			panic(err)
		}
	} else {
		des := "Vyos-HA"
		if fr := tree.FindFirewallRuleByDescription(heartbeatNicNme, "local", des); fr == nil {
			tree.SetFirewallOnInterface(heartbeatNicNme, "local",
				"action accept",
				fmt.Sprintf("description %v", des),
				fmt.Sprintf("source address %s", cmd.PeerIp),
				fmt.Sprintf("protocol vrrp"),
			)
		} else {
			rulenum, _ := strconv.Atoi(fr.Name())
			sourceNode := fr.Getf("source address")
			if sourceNode == nil || sourceNode.Name() != cmd.PeerIp {
				tree.SetFirewallWithRuleNumber(heartbeatNicNme, "local", rulenum, fmt.Sprintf("source address %s", cmd.PeerIp))
			}
		}

		if r := tree.FindSnatRuleDescription(des); r == nil {
			num := tree.SetSnatExclude(
				fmt.Sprintf("protocol vrrp"),
				fmt.Sprintf("outbound-interface %v", heartbeatNicNme),
				fmt.Sprintf("description %v", des),
			)
			if f := tree.FindFirstNotExcludeSNATRule(1); num != 1 && num > f {
				/* there has not been run here never */
				utils.LogError(fmt.Errorf("there is SNAT rule number unexcepted, rule:%v %v",
					tree.Getf("nat source rule %v", num), tree.Getf("nat source rule %v", f)))
				tree.SwapSnatRule(num, f)
				num = f
			}
			tree.SetSnatWithRuleNumber(num, "exclude")
		}
	}

	pairs := []nicVipPair{}
	for _, p := range cmd.Vips {
		nicname, err := utils.GetNicNameByMac(p.NicMac)
		utils.PanicOnError(err)
		cidr, err := utils.NetmaskToCIDR(p.Netmask)
		utils.PanicOnError(err)
		pairs = append(pairs, nicVipPair{NicName: nicname, Vip: p.NicVip, Prefix: cidr})

		/* if vip is same to nic Ip, there is no need to add firewall again */
		if nicIp := getNicIp(nicname); nicIp == p.NicVip {
			continue
		}
		addSecondaryIpFirewall(nicname, p.NicVip, tree)
	}

	tree.Apply(false)

	/* generate notify script first */
	haStatusCallbackUrl = cmd.CallbackUrl
	addHaNicVipPair(pairs, false)

	if cmd.PeerIp == "" {
		cmd.PeerIp = cmd.LocalIp
	}
	checksum, err := getFileChecksum(KeepalivedConfigFile)
	utils.PanicOnError(err)

	keepalivedConf := NewKeepalivedConf(heartbeatNicNme, cmd.LocalIp, cmd.PeerIp, cmd.Monitors, cmd.Keepalive)
	keepalivedConf.BuildCheckScript()
	keepalivedConf.BuildConf()
	newCheckSum, err := getFileChecksum(KeepalivedConfigFile)
	utils.PanicOnError(err)
	/* if keepalived is not started, RestartKeepalived will also start keepalived */
	if newCheckSum != checksum {
		keepalivedConf.RestartKeepalived(KeepAlivedProcess_Reload)
	} else {
		log.Debugf("keepalived configure file unchanged")
		keepalivedConf.RestartKeepalived(KeepAlivedProcess_Skip)
	}

	if !getKeepAlivedStatusStart {
		go getKeepAlivedStatusTask()
	}

	if !keepAlivedCheckStart {
		go keepAlivedCheckTask()
	}

	err = utils.Retry(func() error {
		if IsMaster() || IsBackup() {
			return nil
		}
		return fmt.Errorf("keepalived master election not finished")
	}, 5, uint(cmd.Keepalive))
	utils.PanicOnError(err)
	return nil
}

func IsMaster() bool {
	if !utils.IsHaEnabled() {
		return true
	}

	return keepAlivedStatus == KeepAlivedStatus_Master
}

func IsBackup() bool {
	if !utils.IsHaEnabled() {
		return true
	}

	return keepAlivedStatus == KeepAlivedStatus_Backup
}

type haStatusCallback struct {
	VirtualRouterUuid string `json:"virtualRouterUuid"`
	HaStatus          string `json:"haStatus"`
}

/*
func postHaStatusToManageNode(status KeepAlivedStatus) {
	cmd := haStatusCallback{VirtualRouterUuid: utils.GetVirtualRouterUuid(), HaStatus: status.string()}
	err := utils.HttpPostForObject(haStatusCallbackUrl, map[string]string{"commandpath": "/vpc/hastatus", }, cmd, nil)
}*/

func NonManagementUpNics() []string {
	var upNics []string
	nics, _ := utils.GetAllNics()
	for _, nic := range nics {
		/* skip management nic */
		if nic.Name == "eth0" {
			continue
		}

		if strings.Contains(nic.Name, "eth") {
			path := fmt.Sprintf("/sys/class/net/%s/operstate", nic.Name)
			operstate, err := ioutil.ReadFile(path)
			if err != nil {
				continue
			}

			state := strings.TrimSpace(string(operstate))
			if state == "up" {
				upNics = append(upNics, nic.Name)
			}
		}
	}

	return upNics
}

func getKeepAlivedStatusTask() {
	if utils.IsRuingUT() {
		return
	}

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	defer func() { getKeepAlivedStatusStart = false; log.Errorf("!!!!!!!!!keepalived status check task exited") }()

	getKeepAlivedStatusStart = true
	for {
		select {
		case <-ticker.C:
			if utils.IsHaEnabled() {
				newHaStatus := getKeepAlivedStatus()
				if newHaStatus == KeepAlivedStatus_Unknown || newHaStatus == keepAlivedStatus {
					/* sometime keepalived is in backup state, but nic is up,
					   we need to call notify script to correct it */

					if newHaStatus == KeepAlivedStatus_Backup {
						upNics := NonManagementUpNics()
						if len(upNics) > 0 {
							log.Warnf("nic %s is up when keepalived state is backup", upNics)
							server.VyosLockInterface(callStatusChangeScripts)()
						}
					}
					continue
				}

				/* there is a situation when zvr write the keepalived notify script,
				at the same time keepalived is changing state,
				so when zvr detect status change, all script again to make sure no missing config */
				keepAlivedStatus = newHaStatus
				server.VyosLockInterface(callStatusChangeScripts)()
			}
		}
	}
}

func keepAlivedCheckTask() {
	if utils.IsRuingUT() {
		return
	}

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	defer func() { keepAlivedCheckStart = false; log.Errorf("!!!!!!!!!keepalived process check task exited") }()

	keepAlivedCheckStart = true
	for {
		select {
		case <-ticker.C:
			if utils.IsHaEnabled() {
				checkKeepalivedRunning()
				//checkConntrackdRunning()
			}
		}
	}
}

type nicVipPair struct {
	NicName string
	Vip     string
	Prefix  int
}

type vyosNicVipPairs struct {
	pairs []nicVipPair
}

func generateNotityScripts() {
	/* only vip on management nic will be added in master script and will be deleted in backup script */
	mgmtVip := []nicVipPair{}
	for _, p := range haVipPairs.pairs {
		if utils.IsInManagementCidr(p.Vip) {
			mgmtVip = append(mgmtVip, p)
		}
	}

	keepalivedNofityConf := NewKeepalivedNotifyConf(haVipPairs.pairs, mgmtVip)
	keepalivedNofityConf.CreateMasterScript()
	keepalivedNofityConf.CreateBackupScript()
}

func addHaNicVipPair(pairs []nicVipPair, callscript bool) {
	count := 0
	for _, p := range pairs {
		found := false
		for _, op := range haVipPairs.pairs {
			if p.NicName == op.NicName && p.Vip == op.Vip {
				found = true
				break
			}
		}

		if !found {
			count++
			haVipPairs.pairs = append(haVipPairs.pairs, p)
		}
	}

	generateNotityScripts()

	if callscript {
		callStatusChangeScripts()
	}
}

func removeHaNicVipPair(pairs []nicVipPair) {
	newPair := []nicVipPair{}
	for _, p := range haVipPairs.pairs {
		found := false
		for _, np := range pairs {
			if p.NicName == np.NicName && p.Vip == np.Vip {
				found = true
				break
			}
		}

		if !found {
			newPair = append(newPair, p)
		}
	}

	if len(newPair) != len(haVipPairs.pairs) {
		haVipPairs.pairs = newPair
		generateNotityScripts()
	}
}

func InitHaNicState() {
	if !utils.IsHaEnabled() {
		return
	}

	/* disable conntrackd at current time */
	b := utils.Bash{
		Command: "pkill -9 conntrackd",
		Sudo:    true,
	}
	b.Run()

	/* if ha is enable, shutdown all interface except eth0 */
	var cmds []string
	cmds = append(cmds, fmt.Sprintf("sudo sysctl -w net.ipv4.ip_nonlocal_bind=1"))
	b = utils.Bash{
		Command: strings.Join(cmds, "\n"),
	}

	b.Run()
	b.PanicIfError()
}

var haVipPairs = vyosNicVipPairs{
	pairs: []nicVipPair{},
}

func VyosHaEntryPoint() {
	server.RegisterAsyncCommandHandler(SET_VYOSHA_PATH, server.VyosLock(setVyosHaHandler))
	if utils.IsHaEnabled() {
		/* set as unknown, then getKeepAlivedStatusTask will get master or backup, then will the right script  */
		keepAlivedStatus = KeepAlivedStatus_Unknown
	}
}
