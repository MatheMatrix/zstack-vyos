package plugin

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"zstack-vyos/server"
	"zstack-vyos/utils"

	prom "github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
)

const (
	VR_CREATE_VIP        = "/createvip"
	VR_REMOVE_VIP        = "/removevip"
	VR_SET_VIP_QOS       = "/setvipqos"
	VR_DELETE_VIP_QOS    = "/deletevipqos"
	VR_SYNC_VIP_QOS      = "/syncvipqos"
	VR_FLUSH_VIP_QOS     = "/flushvipqos"
	VR_IFB               = "ifb"
	TC_MAX_CLASSID       = 0xFFFF
	TC_MAX_FILTER        = 0xFFF
	MAX_UINT32           = uint32(0xFFFFFFFF)
	MAX_PUBLIC_INTERFACE = 128

	/* 16G */
	MAX_BINDWIDTH = uint64(0x4FFFFFFFF)
)

const (
	IP_NONE    = 0
	IPv4       = 4
	IPv6       = 6
	DUAL_STACK = 46
)

type direction int

const (
	INGRESS       direction = 0
	EGRESS        direction = 1
	DIRECTION_MAX direction = 2
)

/* a single tc rule  */
type qosRule struct {
	/* each qos rule mapped to a htb class which is subclass of root
		   ###### htb root class
		 * tc qdisc replace dev eth0 root handle 1: htb default 1

		   ###### htb class for default traffic
		 * tc class add dev eth0 parent 1:0 classid 1:1 htb rate 10gbit ceil 10gbit

		   ###### htb class for first rule, cburst = rate/800, max 128k
		 * tc class add dev eth0 parent 1:0 classid 1:2 htb rate 1mbit ceil 1mbit burst 15k cburst 15k
	         * tc qdisc add dev eth0 parent 1:2 sfq
	*/
	qosProtocol    string
	matchIpversion string
	classId        uint32

	/* all tc filters is attached to htb class 1:0, there are 4095 filter handlers, each handle contains 4095 filters. Totally FFFFFF rules
	 * rules from same IP address will be put in same filter handler. so totally there will have 4095 ip address
	 * more IP addresses will be supported later
	 * */
	prioId    uint32
	filterId  uint32
	filterPos uint32

	ip            string
	port          uint16
	bandwidth     uint64
	vipUuid       string
	sharedQosUuid string
}

func newQosRule(ip string, port uint16, bandwidth uint64, vipUuid string) *qosRule {
	var qosProtocol = "ip"
	var matchIpversion = "ip"
	var sharedQosUuid = ""
	if !utils.IsIpv4Address(ip) {
		qosProtocol = "ipv6"
		matchIpversion = "ip6"
	}
	return &qosRule{
		ip:             ip,
		port:           port,
		bandwidth:      bandwidth,
		vipUuid:        vipUuid,
		qosProtocol:    qosProtocol,
		matchIpversion: matchIpversion,
		sharedQosUuid:  sharedQosUuid,
	}
}

type qosRuleHook interface {
	AddRule(nic string, direct direction)
	DelRule(nic string, direct direction)
	AddFilter(nic string, direct direction)
	DelFilter(nic string, direct direction)
}

func (rule *qosRule) UpdateRule(nic string, direct direction) interface{} {
	bandwidth := rule.bandwidth
	if bandwidth <= 0 {
		bandwidth = 1
	}

	bash := utils.Bash{
		Command: fmt.Sprintf("tc class change dev %s parent 1:0 classid 1:%x htb rate %d ceil %d burst 15k cburst 15k;",
			nic, rule.classId, bandwidth, bandwidth),
		Sudo: true,
	}
	bash.Run()
	bash.PanicIfError()

	return nil
}

func (rule *qosRule) AddRule(nic string, direct direction) interface{} {
	checkQdisc(nic)

	bash := utils.Bash{
		Command: fmt.Sprintf("tc qdisc del dev %s parent 1:%x;"+
			"tc class del dev %s parent 1:0 classid 1:%x;",
			nic, rule.classId,
			nic, rule.classId),
		Sudo: true,
	}
	bash.Run()

	bandwidth := rule.bandwidth
	if bandwidth <= 0 {
		bandwidth = 1
	}

	bash1 := utils.Bash{
		Command: fmt.Sprintf("tc class add dev %s parent 1:0 classid 1:%x htb rate %d ceil %d burst 15k cburst 15k;",
			nic, rule.classId, bandwidth, bandwidth),
		Sudo: true,
	}
	bash1.Run()

	// Ensure bandwidth settings are applied correctly using tc class change
	bash2 := utils.Bash{
		Command: fmt.Sprintf("tc class change dev %s parent 1:0 classid 1:%x htb rate %d ceil %d burst 15k cburst 15k;",
			nic, rule.classId, bandwidth, bandwidth),
		Sudo: true,
	}
	bash2.Run()
	bash2.PanicIfError()

	bash3 := utils.Bash{
		Command: fmt.Sprintf("tc qdisc add dev %s parent 1:%x sfq;",
			nic, rule.classId),
		Sudo: true,
	}
	bash3.Run()
	bash3.PanicIfError()

	return nil
}

func (rule *qosRule) DelRule(nic string, direct direction) interface{} {
	checkQdisc(nic)

	bash := utils.Bash{
		Command: fmt.Sprintf("tc filter del dev %s parent 1:0 prio %d handle %03x::%03x protocol ip u32;"+
			"tc qdisc del dev %s parent 1:%x sfq;"+
			"tc class del dev %s parent 1:0 classid 1:%x;",
			nic, rule.prioId, rule.filterId, rule.filterPos,
			nic, rule.classId,
			nic, rule.classId),
		Sudo: true,
	}
	bash.Run()

	return nil
}

func (rule *qosRule) AddFilter(nic string, direct direction) interface{} {
	var bash utils.Bash
	rule.DelFilter(nic, direct)
	if rule.port != 0 {
		if direct == INGRESS {
			bash = utils.Bash{
				Command: fmt.Sprintf(
					"tc filter add dev %s parent 1:0 prio %d handle %03x::%03x protocol %s u32 match %s dst %s match %s dport %d 0xffff flowid 1:%x",
					nic, rule.prioId, rule.filterId, rule.filterPos, rule.qosProtocol, rule.matchIpversion, rule.ip, rule.matchIpversion, rule.port, rule.classId),
				Sudo: true,
			}
		} else {
			bash = utils.Bash{
				Command: fmt.Sprintf(
					"tc filter add dev %s parent 1:0 prio %d handle %03x::%03x protocol %s u32 match %s src %s match %s sport %d 0xffff flowid 1:%x",
					nic, rule.prioId, rule.filterId, rule.filterPos, rule.qosProtocol, rule.matchIpversion, rule.ip, rule.matchIpversion, rule.port, rule.classId),
				Sudo: true,
			}
		}
	} else {
		if direct == INGRESS {
			bash = utils.Bash{
				Command: fmt.Sprintf(
					"tc filter add dev %s parent 1:0 prio %d handle %03x::%03x protocol %s u32 match %s dst %s flowid 1:%x",
					nic, rule.prioId, rule.filterId, rule.filterPos, rule.qosProtocol, rule.matchIpversion, rule.ip, rule.classId),
				Sudo: true,
			}
		} else {
			bash = utils.Bash{
				Command: fmt.Sprintf(
					"tc filter add dev %s parent 1:0 prio %d handle %03x::%03x protocol %s u32 match %s src %s flowid 1:%x",
					nic, rule.prioId, rule.filterId, rule.filterPos, rule.qosProtocol, rule.matchIpversion, rule.ip, rule.classId),
				Sudo: true,
			}
		}
	}
	bash.Run()
	bash.PanicIfError()

	return nil
}

func (rule *qosRule) DelFilter(nic string, direct direction) interface{} {
	bash := utils.Bash{
		Command: fmt.Sprintf("tc filter del dev %s parent 1:0 prio %d handle %03x::%03x protocol %s u32",
			nic, rule.prioId, rule.filterId, rule.filterPos, rule.qosProtocol),
		Sudo: true,
	}
	bash.Run()
	return nil
}

type Bitmap struct {
	bitmap []uint32
}
type bitmapHook interface {
	Init(int)
	AddNumber(uint32)
	DelNumber(uint32)
	FindFirstAvailable() uint32
	Reset()
}

func (bitmap *Bitmap) Init(length int) {
	bitmap.bitmap = make([]uint32, length)
}

func (bitmap *Bitmap) AddNumber(number uint32) {
	pos := number >> 5
	if pos >= uint32(len(bitmap.bitmap)) {
		return
	}
	bit := number - (pos << 5)
	(bitmap.bitmap)[pos] |= (1 << bit)
}

func (bitmap *Bitmap) DelNumber(number uint32) {
	pos := number >> 5
	if pos >= uint32(len(bitmap.bitmap)) {
		return
	}
	bit := number - (pos << 5)
	(bitmap.bitmap)[pos] &= ^(1 << bit)
}

func (bitmap *Bitmap) FindFirstAvailable() uint32 {
	for i := 0; i < len(bitmap.bitmap); i++ {
		if bitmap.bitmap[i] == 0xffffffff {
			continue
		}
		for j := 0; j < 32; j++ {
			if ((bitmap.bitmap)[i] & (1 << uint32(j))) == 0 {
				return uint32((i << 5) + j)
			}
		}
	}
	return MAX_UINT32
}

func (bitmap *Bitmap) Reset() {
	for i := 0; i < len(bitmap.bitmap); i++ {
		(bitmap.bitmap)[i] = 0
	}
}

/* all qos rules of same vip */
type vipQosRules struct {
	portRules      map[uint16]*qosRule
	vip            string
	prioId         uint32
	filterHandleID uint32
	filterMap      Bitmap
	vipUuid        string
	qosProtocol    string
}

func newVipQosRules(portRules map[uint16]*qosRule, vip string, prioId uint32, vipUuid string) *vipQosRules {
	var qosProtocol = "ip"
	if !utils.IsIpv4Address(vip) {
		qosProtocol = "ipv6"
	}
	return &vipQosRules{
		portRules:   portRules,
		vip:         vip,
		prioId:      prioId,
		vipUuid:     vipUuid,
		qosProtocol: qosProtocol}
}

type vipQosHook interface {
	VipQosRulesInit(string) interface{}
	VipQosAddRule(qosRule, string, direction) interface{}
	VipQosDelRule(qosRule, string, direction) interface{}
}

func (vipRules *vipQosRules) VipQosRulesInit(nicName string) interface{} {

	/* generate the filter handler */
	filterBash := utils.Bash{
		Command: fmt.Sprintf("tc filter add dev %s parent 1:0 prio %d protocol %s u32; "+
			"tc filter show dev %s prio %d protocol %s | grep 'ht divisor'",
			nicName, vipRules.prioId, vipRules.qosProtocol,
			nicName, vipRules.prioId, vipRules.qosProtocol),
		Sudo: true,
	}
	_, o, _, _ := filterBash.RunWithReturn()
	filterBash.PanicIfError()
	o = strings.TrimSpace(o)
	ids := strings.Split(o, "fh ")
	if len(ids) == 1 {
		utils.PanicOnError(fmt.Errorf("can not find qos filter handler in %s", o))
	}
	ids = strings.Split(ids[1], ":")
	filterHandleID, err := strconv.ParseUint(ids[0], 16, 32)
	utils.PanicOnError(err)
	vipRules.filterHandleID = uint32(filterHandleID)

	vipRules.filterMap.Init((TC_MAX_FILTER >> 5) + 1)
	vipRules.filterMap.AddNumber(0)
	vipRules.filterMap.AddNumber(TC_MAX_FILTER)

	log.Debugf("InitVipQosRule for ip %s for prioId %d filterHandleID %d",
		vipRules.vip, vipRules.prioId, vipRules.filterHandleID)

	return nil
}

func (vipRules *vipQosRules) VipQosAddRule(rule *qosRule, nicName string, direct direction) interface{} {
	rule.prioId = vipRules.prioId
	rule.filterId = vipRules.filterHandleID
	if rule.port == 0 {
		rule.filterPos = TC_MAX_FILTER
	} else {
		/* when filterPos exceed the max, rule add will fail, so not handle here  */
		rule.filterPos = vipRules.filterMap.FindFirstAvailable()
		vipRules.filterMap.AddNumber(rule.filterPos)
	}

	rule.AddFilter(nicName, direct)

	/* add rules to map */
	vipRules.portRules[rule.port] = rule

	log.Debugf("AddRuleToInterface ip %s port %d, classId %d, prio %d, filter %03x:%03x, port number %d",
		rule.ip, rule.port, rule.classId, rule.prioId, rule.filterId, rule.filterPos, len(vipRules.portRules))

	return nil
}

func (vipRules *vipQosRules) VipQosDelRule(rule qosRule, nicName string, direct direction) interface{} {
	rule.DelRule(nicName, direct)

	/* clean data struct */
	vipRules.filterMap.DelNumber(rule.filterPos)
	delete(vipRules.portRules, rule.port)
	if len(vipRules.portRules) == 0 {
		log.Debugf("DelRule clean ip %s prio %d", rule.ip, rule.prioId)
		/* delete filter */
		bash := utils.Bash{
			Command: fmt.Sprintf("tc filter del dev %s parent 1:0 prio %d protocol %s u32",
				nicName, rule.prioId, rule.qosProtocol),
			Sudo: true,
		}
		bash.Run()
		//bash.PanicIfError()
		vipRules.filterMap.Reset()
	}
	log.Debugf("VipQosDelRule ip %s port %d, filterPos %d, remain port number %d", rule.ip, rule.port, rule.filterPos, len(vipRules.portRules))

	return nil
}

/* tc rules per interface per direction
 * rules       		#### 	map key is the vip ip, value is another map of rules of same vip
 * classBitmap      	#### 	record the classID used
 * fliterBitMap     	#### 	filter priority also use this id
 * cntMap               ####    map classId to vip ip
 */
type interfaceQosRules struct {
	name             string
	ifbName          string
	direct           direction
	rules            map[string]*vipQosRules
	classBitmap      Bitmap
	prioBitMap       Bitmap
	classIdMap       map[uint32][]string
	sharedClassIdMap map[string]uint32
}

type interfaceQosHook interface {
	InterfaceQosRulesInit() interface{}
	InterfaceQosRuleCleanUp() interface{}
	InterfaceQosRuleAddRule(qosRule) interface{}
	InterfaceQosRuleDelRule(qosRule) interface{}
	InterfaceQosRuleFind(qosRule) interface{}
}

func getInterfaceIndex(name string) string {
	f := func(c rune) bool {
		return !unicode.IsNumber(c)
	}
	return strings.TrimFunc(name, f)
}

func (rules *interfaceQosRules) InterfaceQosRuleFind(newRule *qosRule) *qosRule {
	if _, ok := rules.rules[newRule.ip]; ok == false {
		return nil
	}

	if _, ok := rules.rules[newRule.ip].portRules[newRule.port]; ok == false {
		return nil
	}

	return rules.rules[newRule.ip].portRules[newRule.port]
}

func (rules *interfaceQosRules) InterfaceQosRuleInit(direct direction) interface{} {
	var name string
	rules.direct = direct
	/* reserve 0 for root class, 1 for default class */
	rules.classBitmap.Init((TC_MAX_CLASSID >> 5) + 1)
	rules.classBitmap.Reset()
	rules.classBitmap.AddNumber(0)
	rules.classBitmap.AddNumber(1)
	rules.classBitmap.AddNumber(TC_MAX_CLASSID)
	rules.prioBitMap.Init((TC_MAX_CLASSID >> 5) + 1)
	rules.prioBitMap.Reset()
	rules.prioBitMap.AddNumber(0)
	rules.prioBitMap.AddNumber(1)
	rules.prioBitMap.AddNumber(TC_MAX_CLASSID)
	rules.rules = make(map[string]*vipQosRules)
	rules.classIdMap = make(map[uint32][]string)
	rules.sharedClassIdMap = make(map[string]uint32)

	if rules.direct == INGRESS {
		/* get interface index */
		index := getInterfaceIndex(rules.name)
		if len(index) == 0 {
			utils.PanicOnError(fmt.Errorf("Can not find index for interface: %s", rules.name))
			return nil
		}

		/* get ifb interface name */
		ifbName := bytes.NewBufferString("")
		ifbName.WriteString(VR_IFB)
		ifbName.WriteString(index)
		rules.ifbName = ifbName.String()

		if !utils.IsEnableVyosCmd() {
			if !utils.IpLinkIsExist(rules.ifbName) {
				err := utils.IpLinkAdd(rules.ifbName, utils.IpLinkTypeIfb.String())
				utils.PanicOnError(err)
			}
			_ = utils.IpLinkSetUp(rules.ifbName)
			if HasClsact(rules.name) {
				// clsact qdisc is owned by eBPF; add mirred redirect on its ingress hook.
				bash := utils.Bash{
					Command: fmt.Sprintf(
						"tc filter replace dev %s ingress prio 49152 protocol ip u32 match u32 0 0 action mirred egress redirect dev %s;"+
							"tc filter replace dev %s ingress prio 49151 protocol ipv6 u32 match u32 0 0 action mirred egress redirect dev %s",
						rules.name, rules.ifbName,
						rules.name, rules.ifbName),
					Sudo: true,
				}
				bash.Run()
			} else {
				bash := utils.Bash{
					Command: fmt.Sprintf("tc qdisc add dev %s handle ffff: ingress;"+
						"tc filter add dev %s parent ffff: protocol ip u32 match u32 0 0 action mirred egress redirect dev %s;"+
						"tc filter add dev %s parent ffff: protocol ipv6 u32 match u32 0 0 action mirred egress redirect dev %s",
						rules.name,
						rules.name, rules.ifbName,
						rules.name, rules.ifbName),
					Sudo: true,
				}
				bash.Run()
			}
			name = rules.ifbName

			mtu, _ := utils.IpLinkGetMTU(rules.name)
			_ = utils.IpLinkSetMTU(rules.ifbName, mtu)
		} else {
			/* create ifb interface */
			tree := server.NewParserFromShowConfiguration().Tree
			if n := tree.Getf("interfaces input %s", rules.ifbName); n == nil {
				tree.SetfWithoutCheckExisting("interfaces input %s ", rules.ifbName)
			}

			/* redirect ingress to ifb */
			if n := tree.Getf("interfaces ethernet %s redirect", rules.name); n != nil {
				n.Delete()
			}
			tree.Setf("interfaces ethernet %s redirect %s", rules.name, rules.ifbName)
			tree.Apply(false)
			name = rules.ifbName

			if mtu := tree.Getf("interfaces ethernet %s mtu", rules.name); mtu != nil {
				bash := utils.Bash{
					Command: fmt.Sprintf("ip link set mtu %s dev %s", mtu.Value(), rules.ifbName),
				}
				bash.Run()
			}
		}

	} else {
		name = rules.name
	}

	log.Debugf("InitInterfaceQosRule for interface %s", name)
	/* apply htb to interface */
	bash := utils.Bash{
		Command: fmt.Sprintf("sudo tc qdisc del dev %s root;", name),
	}
	bash.RunWithReturn()
	/*
		if err != nil {
			ignore := strings.Contains(e, "with handle of zero") || strings.Contains(e, "No such file")
			utils.Assertf(ignore, "Failed to del rules from dev %s", name)
		}*/

	checkQdisc(name)

	bash1 := utils.Bash{
		Command: fmt.Sprintf("sudo tc qdisc replace dev %s root handle 1: htb default 1;"+
			"sudo tc class add dev %s parent 1:0 classid 1:1 htb rate 10gbit ceil 10gbit;"+
			"sudo tc qdisc add dev %s parent 1:1 sfq", name, name, name),
	}
	bash1.Run()
	bash1.PanicIfError()

	return nil
}

func (rules *interfaceQosRules) InterfaceQosRuleCleanUp() interface{} {
	name := rules.name
	if rules.direct == INGRESS {
		name = rules.ifbName
	}

	log.Debugf("CleanupInterfaceQosRule for interface %s", name)
	/* apply del rules from interface */
	bash := utils.Bash{
		Command: fmt.Sprintf("sudo tc qdisc del dev %s root", name),
	}
	_, _, e, err := bash.RunWithReturn()
	if err != nil {
		ignore := strings.Contains(e, "with handle of zero") || strings.Contains(e, "No such file")
		utils.Assertf(ignore, "Failed to del rules from dev %s", name)
	}

	if rules.direct == INGRESS {
		if !utils.IsEnableVyosCmd() {
			if HasClsact(rules.name) {
				// clsact is managed by eBPF; only remove mirred filters, leave clsact intact.
				bash := utils.Bash{
					Command: fmt.Sprintf(
						"tc filter del dev %s ingress prio 49152 protocol ip || true;"+
							"tc filter del dev %s ingress prio 49151 protocol ipv6 || true",
						rules.name, rules.name),
					Sudo: true,
				}
				bash.Run()
			} else {
				bash := utils.Bash{
					Command: fmt.Sprintf("tc qdisc del dev %s handle ffff: ingress;"+
						"tc filter del dev %s parent ffff: protocol ip u32 match u32 0 0 action mirred egress redirect dev %s;"+
						"tc filter del dev %s parent ffff: protocol ipv6 u32 match u32 0 0 action mirred egress redirect dev %s",
						rules.name,
						rules.name, rules.ifbName,
						rules.name, rules.ifbName),
					Sudo: true,
				}
				bash.Run()
			}
			if utils.IpLinkIsExist(rules.ifbName) {
				err := utils.IpLinkDel(rules.ifbName)
				utils.PanicOnError(err)
			}
		} else {
			tree := server.NewParserFromShowConfiguration().Tree
			if n := tree.Getf("interfaces ethernet %s redirect", rules.name); n != nil {
				n.Delete()
			}
			if n := tree.Getf("interfaces input %s", rules.ifbName); n != nil {
				n.Delete()
			}
			tree.Apply(false)
		}
	}

	rules.classBitmap.Reset()
	rules.prioBitMap.Reset()

	return nil
}

func (rules *interfaceQosRules) InterfaceQosRuleUpdateRule(rule *qosRule) interface{} {
	name := rules.name
	if rules.direct == INGRESS {
		name = rules.ifbName
	}
	if sharedClassId, exists := rules.sharedClassIdMap[rule.sharedQosUuid]; exists {
		rule.classId = sharedClassId
	} else {
		rule.classId = rules.rules[rule.ip].portRules[rule.port].classId
	}
	rule.UpdateRule(name, rules.direct)
	rules.rules[rule.ip].portRules[rule.port].bandwidth = rule.bandwidth
	return nil
}

func (rules *interfaceQosRules) InterfaceQosRuleAddRule(rule *qosRule) interface{} {
	name := rules.name
	if rules.direct == INGRESS {
		name = rules.ifbName
	}

	if rule.sharedQosUuid != "" {
		// Only handle port related to the current rule
		if oldVipRules, vipOk := rules.rules[rule.ip]; vipOk {
			if oldRule, exists := oldVipRules.portRules[rule.port]; exists {
				log.Debugf("Deleting old rule for IP %s port %d due to new sharedQosUuid", rule.ip, rule.port)
				rules.InterfaceQosRuleDelRule(*oldRule)
				if len(rules.rules) == 0 {
					log.Debugf("Reinitializing interface %s after sharedQosUuid cleanup", name)
					rules.InterfaceQosRuleInit(rules.direct)
				}
			}
		}

		// If it is a new sharedQosUuid, assign a classId to it
		if _, exists := rules.sharedClassIdMap[rule.sharedQosUuid]; !exists {
			classId := rules.classBitmap.FindFirstAvailable()
			if classId == MAX_UINT32 {
				utils.PanicOnError(fmt.Errorf("Qos class is full for interface %s ifbname %s", rules.name, rules.ifbName))
			}
			rules.classBitmap.AddNumber(classId)
			rules.sharedClassIdMap[rule.sharedQosUuid] = classId
			log.Debugf("Allocated new classId %x for sharedQosUuid %s", classId, rule.sharedQosUuid)
		}
	}

	if _, vipOk := rules.rules[rule.ip]; vipOk == false {
		log.Debugf("AddRuleToInterface create map for ip %s", rule.ip)
		if len(rules.rules) >= TC_MAX_FILTER {
			utils.PanicOnError(fmt.Errorf("VipQos Reach the max number %d of interface %s ifbname %s",
				TC_MAX_FILTER, rules.name, rules.ifbName))
		}
		prioId := rules.prioBitMap.FindFirstAvailable()
		rules.prioBitMap.AddNumber(prioId)
		rules.rules[rule.ip] = newVipQosRules(make(map[uint16]*qosRule), rule.ip, prioId, rule.vipUuid)
		rules.rules[rule.ip].VipQosRulesInit(name)
	}

	if oldRule, portOk := rules.rules[rule.ip].portRules[rule.port]; portOk {
		/* delete old rule first */
		log.Debugf("AddRuleToInterface delete existed rule for ip %s port %d", rule.ip, rule.port)
		rules.InterfaceQosRuleDelRule(*oldRule)

		/* if this rule of this ip is the only rule for the vip*/
		if _, vipOk := rules.rules[rule.ip]; vipOk == false {
			/* all rules of interface has been deleted */
			if len(rules.rules) == 0 {
				rules.InterfaceQosRuleInit(rules.direct)
			}

			log.Debugf("AddRuleToInterface create map for ip %s", rule.ip)
			if len(rules.rules) >= TC_MAX_FILTER {
				utils.PanicOnError(fmt.Errorf("VipQos Reach the max number %d of interface %s ifbname %s",
					TC_MAX_FILTER, rules.name, rules.ifbName))
			}
			prioId := rules.prioBitMap.FindFirstAvailable()
			rules.prioBitMap.AddNumber(prioId)
			rules.rules[rule.ip] = newVipQosRules(make(map[uint16]*qosRule), rule.ip, prioId, rule.vipUuid)
			rules.rules[rule.ip].VipQosRulesInit(name)
		}
	}
	if sharedClassId, exists := rules.sharedClassIdMap[rule.sharedQosUuid]; exists {
		rule.classId = sharedClassId
		rules.classIdMap[sharedClassId] = append(rules.classIdMap[sharedClassId], rule.ip)
	} else {
		classId := rules.classBitmap.FindFirstAvailable()
		if classId == MAX_UINT32 {
			utils.PanicOnError(fmt.Errorf("Qos class is full for interface %s ifbname %s", rules.name, rules.ifbName))
		}
		rules.classBitmap.AddNumber(classId)
		rule.classId = classId
		rules.classIdMap[classId] = []string{rule.ip}
		if rule.sharedQosUuid != "" {
			rules.sharedClassIdMap[rule.sharedQosUuid] = classId
		}
	}
	rule.AddRule(name, rules.direct)
	rules.rules[rule.ip].VipQosAddRule(rule, name, rules.direct)

	log.Debugf("AddRuleToInterface rule ip %s, port %d, bandwith %d on interface %s, vip number %d",
		rule.ip, rule.port, rule.bandwidth, rules.name, len(rules.rules))

	return nil
}

func (rules *interfaceQosRules) InterfaceQosRuleDelRule(rule qosRule) interface{} {
	/* find qos rule */
	if _, vipOk := rules.rules[rule.ip]; !vipOk {
		log.Debugf("Vyos can not find rule for vip [ip:%s]", rule.ip)
		return nil
	}

	if _, portOK := rules.rules[rule.ip].portRules[rule.port]; !portOK {
		log.Debugf("Vyos can not find rule for vip [ip:%s, port: %d]", rule.ip, rule.port)
		return nil
	}

	/* delete rules */
	name := rules.name
	if rules.direct == INGRESS {
		name = rules.ifbName
	}

	classId := rules.rules[rule.ip].portRules[rule.port].classId
	rules.rules[rule.ip].VipQosDelRule(*rules.rules[rule.ip].portRules[rule.port], name, rules.direct)
	if ips, ok := rules.classIdMap[classId]; ok {
		for i, vip := range ips {
			if vip == rule.ip {
				rules.classIdMap[classId] = append(rules.classIdMap[classId][:i], rules.classIdMap[classId][i+1:]...)
				break
			}
		}
		if len(rules.classIdMap[classId]) == 0 {
			delete(rules.classIdMap, classId)
			rules.classBitmap.DelNumber(classId)
			for sharedUuid, sharedClassId := range rules.sharedClassIdMap {
				if sharedClassId == classId {
					delete(rules.sharedClassIdMap, sharedUuid)
					break
				}
			}
		}
	}
	if len(rules.rules[rule.ip].portRules) == 0 {
		rules.prioBitMap.DelNumber(rules.rules[rule.ip].prioId)
		delete(rules.rules, rule.ip)
		if len(rules.rules) == 0 {
			/* clean data struct to avoid classid overflow */
			log.Debugf("DelRuleFromInterface clean interface %s", name)
			rules.InterfaceQosRuleCleanUp()
		}
	}

	log.Debugf("DelRule for ip %s port %d, classid %d, name %s, remain vip number %d", rule.ip, rule.port, classId, name, len(rules.rules))
	return nil
}

/* var for qos rules of all interfaces */
type interfaceInOutQosRules [DIRECTION_MAX]*interfaceQosRules

var totalQosRules map[string]interfaceInOutQosRules

func updateQosRule(publicInterface string, direct direction, qosRule *qosRule) interface{} {
	if _, ok := totalQosRules[publicInterface]; ok {
		log.Debugf("updateQosRule update rule of publicInterface: %s direct %d", publicInterface, direct)
		totalQosRules[publicInterface][direct].InterfaceQosRuleUpdateRule(qosRule)
	}
	return nil
}

func addQosRule(publicInterface string, direct direction, qosRule *qosRule) interface{} {
	if _, ok := totalQosRules[publicInterface]; !ok {
		log.Debugf("init data struct for %s", publicInterface)
		totalQosRules[publicInterface] = interfaceInOutQosRules([DIRECTION_MAX]*interfaceQosRules{
			&(interfaceQosRules{name: publicInterface}), &(interfaceQosRules{name: publicInterface})})
	}

	log.Debugf("addQosRule add rule to map of publicInterface: %s direct %d", publicInterface, direct)
	if len(totalQosRules[publicInterface][direct].rules) == 0 {
		log.Debugf("addQosRule init data struct for %s dirct %d", publicInterface, direct)
		totalQosRules[publicInterface][direct].InterfaceQosRuleInit(direct)
	}
	totalQosRules[publicInterface][direct].InterfaceQosRuleAddRule(qosRule)

	return nil
}

func delQosRule(publicInterface string, direct direction, qosRule qosRule) interface{} {
	if _, ok := totalQosRules[publicInterface]; !ok {
		log.Debugf("Can not find qos rules for interface %s", publicInterface)
		return nil
	}

	log.Debugf("delQosRule publicInterface %s, direct %d, ip %s, port %d",
		publicInterface, direct, qosRule.ip, qosRule.port)
	totalQosRules[publicInterface][direct].InterfaceQosRuleDelRule(qosRule)

	return nil
}

func deleteQosRulesOfVip(publicInterface string, vip string) {
	if _, ok := totalQosRules[publicInterface]; ok {
		if _, rok := totalQosRules[publicInterface][INGRESS].rules[vip]; rok {
			for _, rule := range totalQosRules[publicInterface][INGRESS].rules[vip].portRules {
				totalQosRules[publicInterface][INGRESS].InterfaceQosRuleDelRule(*rule)
			}
		}

		if _, rok := totalQosRules[publicInterface][EGRESS].rules[vip]; rok {
			for _, rule := range totalQosRules[publicInterface][EGRESS].rules[vip].portRules {
				totalQosRules[publicInterface][EGRESS].InterfaceQosRuleDelRule(*rule)
			}
		}

		if (len(totalQosRules[publicInterface][INGRESS].rules) == 0) &&
			(len(totalQosRules[publicInterface][EGRESS].rules) == 0) {
			delete(totalQosRules, publicInterface)
		}
	}
}

func interfaceHasEffectiveVipQosRules(rules *interfaceQosRules) bool {
	if rules == nil || len(rules.rules) == 0 {
		return false
	}

	for _, vipRules := range rules.rules {
		if vipRules == nil || len(vipRules.portRules) == 0 {
			continue
		}
		for _, rule := range vipRules.portRules {
			if rule == nil {
				continue
			}
			if rule.port != 0 || rule.bandwidth != MAX_BINDWIDTH {
				return true
			}
		}
	}

	return false
}

func deletePlaceholderVipQosRules(publicInterface string, direct direction) {
	biRule, ok := totalQosRules[publicInterface]
	if !ok {
		return
	}

	rules := biRule[direct]
	if rules == nil || len(rules.rules) == 0 {
		return
	}

	var placeholderVips []string
	for vip, vipRules := range rules.rules {
		if vipRules == nil {
			continue
		}
		if r, ok := vipRules.portRules[0]; ok && r != nil && r.bandwidth == MAX_BINDWIDTH {
			placeholderVips = append(placeholderVips, vip)
		}
	}

	for _, vip := range placeholderVips {
		rules.InterfaceQosRuleDelRule(qosRule{ip: vip, port: 0})
	}
}

func cleanupVipTcIfNoEffectiveVipQos(publicInterface string) {
	biRule, ok := totalQosRules[publicInterface]
	if !ok {
		return
	}

	ingressHasEffective := interfaceHasEffectiveVipQosRules(biRule[INGRESS])
	egressHasEffective := interfaceHasEffectiveVipQosRules(biRule[EGRESS])
	if ingressHasEffective || egressHasEffective {
		return
	}

	deletePlaceholderVipQosRules(publicInterface, INGRESS)
	deletePlaceholderVipQosRules(publicInterface, EGRESS)

	if (biRule[INGRESS] == nil || len(biRule[INGRESS].rules) == 0) &&
		(biRule[EGRESS] == nil || len(biRule[EGRESS].rules) == 0) {
		delete(totalQosRules, publicInterface)
	}
}

type vipInfo struct {
	Ip               string `json:"ip"`
	Netmask          string `json:"netmask"`
	Gateway          string `json:"gateway"`
	OwnerEthernetMac string `json:"ownerEthernetMac"`
	Nic              string `json:"nic"` /* this is used for delete */
	VipUuid          string `json:"vipUuid"`
	Ip6              string `json:"ip6"`
	PrefixLength     int    `json:"prefixLength"`
	Gateway6         string `json:"gateway6"`
	AddressMode      string `json:"addressMode"`
}

func (vip vipInfo) GetIpWithOutCidr() string {
	if vip.Ip != "" {
		return vip.Ip
	} else {
		return vip.Ip6
	}
}

func (vip vipInfo) GetIpWithCidr() (string, int) {
	if vip.Ip != "" {
		cidr, err := utils.NetmaskToCIDR(vip.Netmask)
		utils.PanicOnError(err)
		addr := fmt.Sprintf("%v/%v", vip.Ip, cidr)
		return addr, cidr
	} else {
		return fmt.Sprintf("%s/%d", vip.Ip6, vip.PrefixLength), vip.PrefixLength
	}
}

func (vip vipInfo) GetIpVersion() int {
	if vip.Ip != "" {
		return IPv4
	} else if vip.Ip6 != "" {
		return IPv6
	} else {
		return IP_NONE
	}
}

func (vip vipInfo) GetPrefix() int {
	if vip.Ip != "" {
		cidr, err := utils.NetmaskToCIDR(vip.Netmask)
		utils.PanicOnError(err)
		return cidr
	} else {
		return vip.PrefixLength
	}
}

type nicIpInfo struct {
	Ip               string `json:"ip"`
	Netmask          string `json:"netmask"`
	OwnerEthernetMac string `json:"ownerEthernetMac"`
}

type vipQosSettings struct {
	Vip               string `json:"vip"`
	PublicNic         string `json:"publicNic"`
	VipUuid           string `json:"vipUuid"`
	Port              int    `json:"port"`
	InboundBandwidth  int64  `json:"inboundBandwidth"`
	OutboundBandwidth int64  `json:"outboundBandwidth"`
	Type              string `json:"type"`
	HasVipQos         bool   `json:"hasVipQos"`
	SharedQosUuid     string `json:"sharedQosUuid"`
	Update            bool   `json:"update"`
}

type setVipCmd struct {
	SyncVip       bool        `json:"syncVip"`
	ResetQosRules bool        `json:"resetQosRules"`
	Vips          []vipInfo   `json:"vips"`
	NicIps        []nicIpInfo `json:"nicIps"`
}

type removeVipCmd struct {
	Vips []vipInfo `json:"vips"`
}

type setVipQosCmd struct {
	Settings []vipQosSettings `json:"vipQosSettings"`
}

type deleteVipQosCmd struct {
	Settings []vipQosSettings `json:"vipQosSettings"`
}

type syncVipQosCmd struct {
	Settings []vipQosSettings `json:"vipQosSettings"`
}

type flushVipQosCmd struct {
	VipUuids []string `json:"vipUuids"`
}

type vipQosSettingsArray []vipQosSettings

func (a vipQosSettingsArray) Len() int           { return len(a) }
func (a vipQosSettingsArray) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a vipQosSettingsArray) Less(i, j int) bool { return a[i].Port > a[j].Port }

func getVyosNicVips(tree *server.VyosConfigTree, nicName string) []string {
	var ips []string
	ipNode := tree.Getf("interfaces ethernet %s address", nicName)
	if ipNode == nil {
		return ips
	}

	for _, key := range ipNode.ChildNodeKeys() {
		ips = append(ips, key)
	}
	return ips
}

func getLinuxNicVips(nicName string) []string {
	var linuxIps []string

	bash := utils.Bash{
		Command: fmt.Sprintf("ip add show dev %s | grep -E \"inet|inet6\" | awk '{print $2}'", nicName),
	}
	ret, o, _, err := bash.RunWithReturn()
	if ret != 0 || err != nil {
		return linuxIps
	}

	o = strings.TrimSpace(o)
	ips := strings.Split(o, "\n")
	for _, key := range ips {
		ip := strings.Split(key, "/")[0]
		if ip != "" {
			linuxIps = append(linuxIps, key)
		}

	}
	return linuxIps
}

func addVipFirewalRuleByIptables(cmd *setVipCmd) error {
	table := utils.NewIpTables(utils.FirewallTable)
	var rules []*utils.IpTableRule

	for _, vip := range cmd.Vips {
		// Skip IPv6 VIPs - no IPv6 iptables management yet
		if vip.Ip == "" || !utils.IsIpv4Address(vip.Ip) {
			continue
		}

		nicname, err := utils.GetNicNameByMac(vip.OwnerEthernetMac)
		utils.PanicOnError(err)

		vipDes := makeVipRuleDescription(vip)
		rule := utils.NewIpTableRule(utils.GetRuleSetName(nicname, utils.RULESET_LOCAL))
		rule.SetAction(utils.IPTABLES_ACTION_ACCEPT).SetComment(vipDes)
		rule.SetDstIp(vip.Ip + "/32").SetProto(utils.IPTABLES_PROTO_ICMP)
		rules = append(rules, rule)
	}

	if len(rules) > 0 {
		table.AddIpTableRules(rules)
		return table.Apply()
	}

	return nil
}

func addVipFirewalRuleByVyos(cmd *setVipCmd) error {
	tree := server.NewParserFromShowConfiguration().Tree

	for _, vip := range cmd.Vips {
		nicname, err := utils.GetNicNameByMac(vip.OwnerEthernetMac)
		utils.PanicOnError(err)

		vipDes := makeVipRuleDescription(vip)
		if r := tree.FindFirewallRuleByDescription(nicname, "local", vipDes); r == nil {
			tree.SetFirewallOnInterface(nicname, "local",
				fmt.Sprintf("destination address %v", vip.Ip),
				fmt.Sprintf("description %v", vipDes),
				"protocol icmp",
				"action accept")
		}
	}

	tree.Apply(false)
	return nil
}

func initVipCounterChains() error {
	bash := utils.Bash{
		Command: "sysctl -w net.netfilter.nf_conntrack_acct=1",
		Sudo:    true,
	}
	bash.Run()

	if utils.IsEuler2203() {
		log.Infof("VIP counter: OpenEuler 22.03 detected, attempting eBPF mode")
		if err := initEbpfVipCounter(); err != nil {
			if errors.Is(err, ErrEbpfArchUnsupported) {
				log.Infof("VIP counter: eBPF not supported on this architecture, using conntrack mode")
			} else {
				log.Warnf("VIP counter: eBPF init failed, falling back to conntrack mode: %v", err)
			}
		} else {
			log.Infof("VIP counter: eBPF mode active")
		}
	} else {
		log.Infof("VIP counter: non-OpenEuler platform, using conntrack mode")
	}
	return nil
}

func setVipHandler(ctx *server.CommandContext) interface{} {
	cmd := &setVipCmd{}
	ctx.GetCommand(cmd)

	return SetVip(cmd)
}

func SetVip(cmd *setVipCmd) interface{} {
	for _, vip := range cmd.Vips {
		if vipPromCollector != nil {
			vipPromCollector.mu.Lock()
			if vip.Ip != "" {
				if _, ok := vipPromCollector.counters[vip.Ip]; !ok {
					vipPromCollector.counters[vip.Ip] = &VipCounter{VipUuid: vip.VipUuid}
				}
			}
			if vip.Ip6 != "" {
				if _, ok := vipPromCollector.counters[vip.Ip6]; !ok {
					vipPromCollector.counters[vip.Ip6] = &VipCounter{VipUuid: vip.VipUuid}
				}
			}
			vipPromCollector.mu.Unlock()
		}

		if ebpfObjs != nil {
			nicName, err := utils.GetNicNameByMac(vip.OwnerEthernetMac)
			if err != nil || nicName == "" {
				log.Warnf("VIP eBPF: cannot resolve NIC for VIP %s (mac=%s): %v — TC filter may not cover this VIP", vip.Ip, vip.OwnerEthernetMac, err)
			} else {
				log.Debugf("VIP eBPF: resolved NIC %s for VIP %s (mac=%s), ensuring TC filters", nicName, vip.Ip, vip.OwnerEthernetMac)
				ensureEbpfOnInterface(nicName)
			}
			if vip.Ip != "" {
				log.Debugf("VIP eBPF: registering IPv4 VIP %s (uuid=%s) in eBPF map", vip.Ip, vip.VipUuid)
				ebpfAddVip(net.ParseIP(vip.Ip))
			}
			if vip.Ip6 != "" {
				log.Debugf("VIP eBPF: registering IPv6 VIP %s (uuid=%s) in eBPF map", vip.Ip6, vip.VipUuid)
				ebpfAddVip(net.ParseIP(vip.Ip6))
			}
		}
	}

	if cmd.ResetQosRules {
		clearedNics := make(map[string]bool)
		for _, vip := range cmd.Vips {
			nicName, err := utils.GetNicNameByMac(vip.OwnerEthernetMac)
			utils.PanicOnError(err)
			if _, cleared := clearedNics[nicName]; cleared {
				continue
			}
			if _, exists := totalQosRules[nicName]; !exists {
				continue
			}
			delete(totalQosRules, nicName)
			clearedNics[nicName] = true
			log.Debugf("clear QoS rules for interface %s due to ResetQosRules flag", nicName)
		}
	}

	if utils.IsSkipVyosIptables() {
		addVipFirewalRuleByIptables(cmd)
	} else {
		addVipFirewalRuleByVyos(cmd)
	}

	if !utils.IsEnableVyosCmd() {
		return setVipByLinux(cmd)
	}

	return setVip(cmd)
}

func setVip(cmd *setVipCmd) interface{} {
	tree := server.NewParserFromShowConfiguration().Tree

	/* when mn syncvip, we will check whether nic ip is first ip in vyos nic configure and in linux nic configure
	 * if not, delete all nic vyos config and linux config, and reconfigure all ips */
	if cmd.SyncVip {
		var cmds []string
		for _, nicIp := range cmd.NicIps {
			nicname, err := utils.GetNicNameByMac(nicIp.OwnerEthernetMac)
			utils.PanicOnError(err)
			vyosNicIps := getVyosNicVips(tree, nicname)

			/*
				if len(vyosNicIps) > 0 {
					for _, oldVyosIp := range vyosNicIps {
						exist := false
						items := strings.Split(oldVyosIp, "/")
						for _, vip := range cmd.Vips {
							if items[0] == vip.Ip {
								exist = true
								break
							}
						}

						if items[0] == nicIp.Ip {
							exist = true
						}

						if !exist {
							tree.Deletef("interfaces ethernet %s address %v", nicname, oldVyosIp)
						}
					}
				} else {
					log.Errorf("get vyos interfaces ip for nic %s failed", nicname)
				}*/

			linuxNicIps := getLinuxNicVips(nicname)
			cidr, err := utils.NetmaskToCIDR(nicIp.Netmask)
			utils.PanicOnError(err)
			addr := fmt.Sprintf("%v/%v", nicIp.Ip, cidr)
			if len(linuxNicIps) == 0 || linuxNicIps[0] != addr {
				/* nicIp is not the first ip, reconfigured linux nic */
				if len(linuxNicIps) > 0 {
					for _, linuxIp := range linuxNicIps {
						cmd := fmt.Sprintf("sudo ip address del %s dev %s", linuxIp, nicname)
						cmds = append(cmds, cmd)
					}
					cmd := fmt.Sprintf("sudo ip address add %s dev %s", addr, nicname)
					cmds = append(cmds, cmd)
				}

				/* reconfigured vyos */
				if len(vyosNicIps) > 0 {
					for _, oldVyosIp := range vyosNicIps {
						tree.Deletef("interfaces ethernet %s address %v", nicname, oldVyosIp)
					}
				}
				if n := tree.Getf("interfaces ethernet %s address %v", nicname, addr); n == nil {
					tree.SetfWithoutCheckExisting("interfaces ethernet %s address %v", nicname, addr)
				}
			}
		}

		tree.Apply(false)

		if len(cmds) > 0 {
			bash := utils.Bash{
				Command: strings.Join(cmds, ";"),
			}
			bash.Run()
		}

		tree = server.NewParserFromShowConfiguration().Tree
	}

	var cmds []string
	if !utils.IsHaEnabled() {
		for _, vip := range cmd.Vips {
			nicname, err := utils.GetNicNameByMac(vip.OwnerEthernetMac)
			utils.PanicOnError(err)

			// IPv4 VIP
			if vip.Ip != "" {
				addr := fmt.Sprintf("%v/%v", vip.Ip, vip.GetPrefix())
				if n := tree.Getf("interfaces ethernet %s address %v", nicname, addr); n == nil {
					tree.SetfWithoutCheckExisting("interfaces ethernet %s address %v", nicname, addr)
				}
			}

			// IPv6 VIP
			if vip.Ip6 != "" {
				addr := fmt.Sprintf("%s/%d", vip.Ip6, vip.PrefixLength)
				if n := tree.Getf("interfaces ethernet %s address %v", nicname, addr); n == nil {
					tree.SetfWithoutCheckExisting("interfaces ethernet %s address %v", nicname, addr)
				}
			}
		}
	} else {
		for _, vip := range cmd.Vips {
			nicname, err := utils.GetNicNameByMac(vip.OwnerEthernetMac)
			utils.PanicOnError(err)

			// IPv4 VIP
			if vip.Ip != "" {
				addr := fmt.Sprintf("%v/%v", vip.Ip, vip.GetPrefix())
				/* vip on mgt nic will not configure in vyos config */
				if utils.IsInManagementCidr(vip.Ip) {
					if n := tree.Getf("interfaces ethernet %s address %v", nicname, addr); n != nil {
						/* delete old config if existed */
						n.Delete()
					}
					if IsMaster() {
						cmd := fmt.Sprintf("sudo ip address add %s dev %s", addr, nicname)
						cmds = append(cmds, cmd)
					}
				} else {
					if n := tree.Getf("interfaces ethernet %s address %v", nicname, addr); n == nil {
						tree.SetfWithoutCheckExisting("interfaces ethernet %s address %v", nicname, addr)
					}
				}
			}

			// IPv6 VIP
			if vip.Ip6 != "" {
				addr := fmt.Sprintf("%s/%d", vip.Ip6, vip.PrefixLength)
				if n := tree.Getf("interfaces ethernet %s address %v", nicname, addr); n == nil {
					tree.SetfWithoutCheckExisting("interfaces ethernet %s address %v", nicname, addr)
				}
			}
		}
	}

	tree.Apply(false)
	if len(cmds) > 0 {
		bash := utils.Bash{
			Command: strings.Join(cmds, ";"),
		}
		bash.Run()
	}

	vyosVips := []nicVipPair{}
	for _, vip := range cmd.Vips {
		nicname, err := utils.GetNicNameByMac(vip.OwnerEthernetMac)
		utils.PanicOnError(err)

		// IPv4 VIP
		if vip.Ip != "" {
			vyosVips = append(vyosVips, nicVipPair{NicName: nicname, Vip: vip.Ip, Prefix: vip.GetPrefix()})
		}

		//  vyosVips is used by vyosha, ipv6 vip is not used
		// if vip.Ip6 != "" {
		//	vyosVips = append(vyosVips, nicVipPair{NicName: nicname, Vip6: vip.Ip6, Prefix: vip.PrefixLength})
		// }
	}

	if utils.IsHaEnabled() {
		addHaNicVipPair(vyosVips, false)
	}

	/* this is for debug, will be deleted */
	bash := utils.Bash{
		Command: fmt.Sprintf("ip add"),
	}
	bash.Run()

	go sendGARP(cmd)

	return nil
}

func sendGARP(cmd *setVipCmd) {
	if utils.IsHaEnabled() {
		if IsBackup() {
			return
		}
	}

	var command strings.Builder
	for _, vip := range cmd.Vips {
		nicName, _ := utils.GetNicNameByMac(vip.OwnerEthernetMac)
		if nicName != "" {
			// IPv4 gratuitous ARP
			if vip.Ip != "" {
				command.WriteString(fmt.Sprintf("sudo arping -U -I %s %s -c 5;", nicName, vip.Ip))
			}
			// IPv6 unsolicited neighbor advertisement (using ndisc6 or similar tool if available)
			// Note: IPv6 ND is handled differently, typically by kernel automatically
		}
	}
	//send the gratuitious ARP out
	if command.Len() > 0 {
		bash := utils.Bash{
			Command: command.String(),
		}
		_, _, _, error := bash.RunWithReturn()
		if error != nil {
			log.Debugf("send the gratuitious ARP for eip failed : %v", error)
		}
	}
}

func getDeleteFailVip(info []vipInfo) []vipInfo {
	toDeletelVip := []vipInfo{}
	for _, vip := range info {
		// Try to find NIC by IPv4
		if vip.Ip != "" {
			nic, err := utils.GetNicNameByIp(vip.Ip)
			if err == nil {
				vip.Nic = nic
				toDeletelVip = append(toDeletelVip, vip)
				continue
			}
		}

		// Try to find NIC by IPv6
		if vip.Ip6 != "" {
			nic, err := utils.GetNicNameByIp(vip.Ip6)
			if err == nil {
				vip.Nic = nic
				toDeletelVip = append(toDeletelVip, vip)
			}
		}
	}

	return toDeletelVip
}

func makeVipRuleDescription(info vipInfo) string {
	return fmt.Sprintf("vip-%s", info.VipUuid)
}

func delVipFirewalRuleByIptables(cmd *removeVipCmd) error {
	table := utils.NewIpTables(utils.FirewallTable)
	var rules []*utils.IpTableRule

	for _, vip := range cmd.Vips {
		// Skip IPv6 VIPs - no IPv6 iptables management yet
		if vip.Ip == "" || !utils.IsIpv4Address(vip.Ip) {
			continue
		}

		nicname, err := utils.GetNicNameByMac(vip.OwnerEthernetMac)
		utils.PanicOnError(err)

		vipDes := makeVipRuleDescription(vip)
		rule := utils.NewIpTableRule(utils.GetRuleSetName(nicname, utils.RULESET_LOCAL))
		rule.SetAction(utils.IPTABLES_ACTION_ACCEPT).SetComment(vipDes)
		rule.SetDstIp(vip.Ip + "/32").SetProto(utils.IPTABLES_PROTO_ICMP)
		rules = append(rules, rule)
	}

	if len(rules) > 0 {
		table.RemoveIpTableRule(rules)
		table.Apply()
	}

	return nil
}

func delVipFirewalRuleByVyos(cmd *removeVipCmd) error {
	tree := server.NewParserFromShowConfiguration().Tree

	for _, vip := range cmd.Vips {
		nicname, err := utils.GetNicNameByMac(vip.OwnerEthernetMac)
		utils.PanicOnError(err)

		vipDes := makeVipRuleDescription(vip)
		if r := tree.FindFirewallRuleByDescription(nicname, "local", vipDes); r != nil {
			r.Delete()
		}
	}

	tree.Apply(false)
	return nil
}

func removeVipHandler(ctx *server.CommandContext) interface{} {
	cmd := &removeVipCmd{}
	ctx.GetCommand(cmd)

	return RemoveVip(cmd)
}

func RemoveVip(cmd *removeVipCmd) interface{} {
	for _, vip := range cmd.Vips {
		if vipPromCollector != nil {
			vipPromCollector.mu.Lock()
			if vip.Ip != "" {
				delete(vipPromCollector.counters, vip.Ip)
			}
			if vip.Ip6 != "" {
				delete(vipPromCollector.counters, vip.Ip6)
			}
			vipPromCollector.mu.Unlock()
		}

		if ebpfObjs != nil {
			if vip.Ip != "" {
				ebpfDelVip(net.ParseIP(vip.Ip))
			}
			if vip.Ip6 != "" {
				ebpfDelVip(net.ParseIP(vip.Ip6))
			}
		}
	}

	if utils.IsSkipVyosIptables() {
		delVipFirewalRuleByIptables(cmd)
	} else {
		delVipFirewalRuleByVyos(cmd)
	}

	if !utils.IsEnableVyosCmd() {
		return removeVipByLinux(cmd)
	}

	return removeVip(cmd)
}

func removeVip(cmd *removeVipCmd) interface{} {
	tree := server.NewParserFromShowConfiguration().Tree
	for _, vip := range cmd.Vips {
		nicname, err := utils.GetNicNameByMac(vip.OwnerEthernetMac)
		utils.PanicOnError(err)

		// Remove IPv4 VIP
		if vip.Ip != "" {
			cidr, err := utils.NetmaskToCIDR(vip.Netmask)
			utils.PanicOnError(err)
			addr := fmt.Sprintf("%v/%v", vip.Ip, cidr)
			tree.Deletef("interfaces ethernet %s address %v", nicname, addr)
			deleteQosRulesOfVip(nicname, vip.Ip)
		}

		// Remove IPv6 VIP
		if vip.Ip6 != "" {
			addr := fmt.Sprintf("%s/%d", vip.Ip6, vip.PrefixLength)
			tree.Deletef("interfaces ethernet %s address %v", nicname, addr)
			deleteQosRulesOfVip(nicname, vip.Ip6)
		}
	}
	tree.Apply(false)

	toDeletelVip := getDeleteFailVip(cmd.Vips)
	err := utils.Retry(func() error {
		for _, vip := range toDeletelVip {
			var cmds []string
			if vip.Ip != "" {
				cidr, err := utils.NetmaskToCIDR(vip.Netmask)
				utils.PanicOnError(err)
				cmds = append(cmds, fmt.Sprintf("sudo ip add del %s/%d dev %s ", vip.Ip, cidr, vip.Nic))
			}
			if vip.Ip6 != "" {
				cmds = append(cmds, fmt.Sprintf("sudo ip -6 add del %s/%d dev %s ", vip.Ip6, vip.PrefixLength, vip.Nic))
			}

			if len(cmds) > 0 {
				bash := utils.Bash{
					Command: strings.Join(cmds, ";"),
				}
				bash.Run()
			}
		}

		toDeletelVip := getDeleteFailVip(toDeletelVip)
		if len(toDeletelVip) == 0 {
			return nil
		} else {
			return fmt.Errorf("delete vips address %v failed", toDeletelVip)
		}
	}, 3, 1)
	utils.LogError(err)

	vyosVips := []nicVipPair{}
	for _, vip := range cmd.Vips {
		nicname, err := utils.GetNicNameByMac(vip.OwnerEthernetMac)
		utils.PanicOnError(err)

		// IPv4 VIP
		if vip.Ip != "" {
			cidr, _ := utils.NetmaskToCIDR(vip.Netmask)
			vyosVips = append(vyosVips, nicVipPair{NicName: nicname, Vip: vip.Ip, Prefix: cidr})
		}

		// vyosVips is used by vyosha, ipv6 vip is not used
		// if vip.Ip6 != "" {
		//	vyosVips = append(vyosVips, nicVipPair{NicName: nicname, Vip6: vip.Ip6, Prefix: vip.PrefixLength})
		// }
	}
	removeHaNicVipPair(vyosVips)

	/* this is for debug, will be deleted */
	bash := utils.Bash{
		Command: fmt.Sprintf("ip add"),
	}
	bash.Run()

	return nil
}

func setVipQos(ctx *server.CommandContext) interface{} {
	cmd := &setVipQosCmd{}
	ctx.GetCommand(cmd)

	/* sort will make sure vip with port rule is added first to avoid adjust filter position */
	sort.Sort(vipQosSettingsArray(cmd.Settings))
	for _, setting := range cmd.Settings {
		publicInterface, err := utils.GetNicNameByMac(setting.PublicNic)
		utils.PanicOnError(err)
		if setting.InboundBandwidth != 0 {
			ingressrule := newQosRule(setting.Vip, uint16(setting.Port), uint64(setting.InboundBandwidth), setting.VipUuid)
			ingressrule.sharedQosUuid = setting.SharedQosUuid
			if setting.Update {
				updateQosRule(publicInterface, INGRESS, ingressrule)
			} else {
				addQosRule(publicInterface, INGRESS, ingressrule)
			}
		}
		if setting.OutboundBandwidth != 0 {
			egressrule := newQosRule(setting.Vip, uint16(setting.Port), uint64(setting.OutboundBandwidth), setting.VipUuid)
			egressrule.sharedQosUuid = setting.SharedQosUuid
			if setting.Update {
				updateQosRule(publicInterface, EGRESS, egressrule)
			} else {
				addQosRule(publicInterface, EGRESS, egressrule)
			}
		}
	}

	return nil
}

func deleteVipQos(ctx *server.CommandContext) interface{} {
	cmd := &deleteVipQosCmd{}
	ctx.GetCommand(cmd)

	touchedIfaces := make(map[string]struct{})

	/* sort will make sure vip with port rule is deleted first to avoid adjust filter position */
	sort.Sort(vipQosSettingsArray(cmd.Settings))
	for _, setting := range cmd.Settings {
		publicInterface, error := utils.GetNicNameByMac(setting.PublicNic)
		utils.PanicOnError(error)
		touchedIfaces[publicInterface] = struct{}{}
		qosRule := qosRule{ip: setting.Vip, port: uint16(setting.Port), vipUuid: setting.VipUuid}
		delQosRule(publicInterface, INGRESS, qosRule)
		delQosRule(publicInterface, EGRESS, qosRule)
	}

	for publicInterface := range touchedIfaces {
		cleanupVipTcIfNoEffectiveVipQos(publicInterface)
	}

	return nil
}

func syncVipQos(ctx *server.CommandContext) interface{} {
	cmd := &syncVipQosCmd{}
	ctx.GetCommand(cmd)

	sort.Sort(vipQosSettingsArray(cmd.Settings))
	for _, setting := range cmd.Settings {
		publicInterface, err := utils.GetNicNameByMac(setting.PublicNic)
		utils.PanicOnError(err)
		if setting.InboundBandwidth != 0 {

			ingressrule := newQosRule(setting.Vip, uint16(setting.Port), uint64(setting.InboundBandwidth), setting.VipUuid)
			ingressrule.sharedQosUuid = setting.SharedQosUuid
			if biRule, ok := totalQosRules[publicInterface]; ok && biRule[INGRESS] != nil {
				if existed := biRule[INGRESS].InterfaceQosRuleFind(ingressrule); existed != nil {
					if existed.sharedQosUuid == ingressrule.sharedQosUuid {
						if existed.bandwidth != ingressrule.bandwidth {
							updateQosRule(publicInterface, INGRESS, ingressrule)
						}
						continue
					}
				}
			}
			addQosRule(publicInterface, INGRESS, ingressrule)
		}

		if setting.OutboundBandwidth != 0 {
			egressrule := newQosRule(setting.Vip, uint16(setting.Port), uint64(setting.OutboundBandwidth), setting.VipUuid)
			egressrule.sharedQosUuid = setting.SharedQosUuid
			if biRule, ok := totalQosRules[publicInterface]; ok && biRule[EGRESS] != nil {
				if existed := biRule[EGRESS].InterfaceQosRuleFind(egressrule); existed != nil {
					if existed.sharedQosUuid == egressrule.sharedQosUuid {
						if existed.bandwidth != egressrule.bandwidth {
							updateQosRule(publicInterface, EGRESS, egressrule)
						}
						continue
					}
				}
			}
			addQosRule(publicInterface, EGRESS, egressrule)
		}
	}

	return nil
}

func flushVipQos(ctx *server.CommandContext) interface{} {
	cmd := &flushVipQosCmd{}
	ctx.GetCommand(cmd)

	clearUnusedTcRule()
	for publicInterface := range totalQosRules {
		cleanupVipTcIfNoEffectiveVipQos(publicInterface)
	}
	return nil
}

type vipQosRemoveNic struct{}

func (vipQos *vipQosRemoveNic) RemoveNic(nicName string) error {
	bash := utils.Bash{
		Command: fmt.Sprintf("sudo tc qdisc del dev %s root;", nicName),
	}
	_, _, e, err := bash.RunWithReturn()
	if err != nil {
		ignore := strings.Contains(e, "with handle of zero") || strings.Contains(e, "No such file")
		utils.Assertf(ignore, "Failed to del rules from dev %s", nicName)
	}

	delete(totalQosRules, nicName)
	return nil
}

func init() {
	RegisterRemoveNicCallback(&vipQosRemoveNic{})
	RegisterPrometheusCollector(NewVipPrometheusCollector())
}

type vipCollector struct {
	inByteEntry  *prom.Desc
	inPktEntry   *prom.Desc
	outByteEntry *prom.Desc
	outPktEntry  *prom.Desc

	// Fields for conntrack-based monitoring
	mu            sync.Mutex
	previousStats map[string]*SessionStat
	counters      map[string]*VipCounter
}

var vipPromCollector *vipCollector

const (
	LABEL_VIP_UUID = "VipUUID"
)

func NewVipPrometheusCollector() MetricCollector {
	vipPromCollector = &vipCollector{
		inByteEntry: prom.NewDesc(
			"zstack_vip_in_bytes",
			"VIP inbound traffic in bytes",
			[]string{LABEL_VIP_UUID}, nil,
		),
		inPktEntry: prom.NewDesc(
			"zstack_vip_in_packages",
			"VIP inbound traffic packages",
			[]string{LABEL_VIP_UUID}, nil,
		),
		outByteEntry: prom.NewDesc(
			"zstack_vip_out_bytes",
			"VIP outbound traffic in bytes",
			[]string{LABEL_VIP_UUID}, nil,
		),
		outPktEntry: prom.NewDesc(
			"zstack_vip_out_packages",
			"VIP outbound traffic packages",
			[]string{LABEL_VIP_UUID}, nil,
		),

		previousStats: make(map[string]*SessionStat),
		counters:      make(map[string]*VipCounter),
	}
	return vipPromCollector
}

func (c *vipCollector) Describe(ch chan<- *prom.Desc) error {
	ch <- c.inByteEntry
	ch <- c.inPktEntry
	ch <- c.outByteEntry
	ch <- c.outPktEntry
	return nil
}

type VipCounter struct {
	VipUuid    string
	InPackets  uint64
	InBytes    uint64
	OutPackets uint64
	OutBytes   uint64
}

// SessionStat holds the parsed statistics for a single connection track entry.
type SessionStat struct {
	Protocol      string
	SrcIp         string
	DstIp         string
	SrcPort       string
	DstPort       string
	IcmpType      string
	IcmpCode      string
	ReplySrcIp    string
	ReplyDstIp    string
	ReplySrcPort  string
	ReplyDstPort  string
	ReplyIcmpType string
	ReplyIcmpCode string
	Packets       uint64
	Bytes         uint64
	ReplyPackets  uint64
	ReplyBytes    uint64
	LastUpdate    int64 // Unix timestamp of last update in seconds
}

func (s *SessionStat) Key() string {
	if s.Protocol == "icmp" {
		return s.Protocol + "-" + s.SrcIp + "-" + s.DstIp + "-" + s.IcmpType + "-" + s.IcmpCode
	}
	return s.Protocol + "-" + s.SrcIp + "-" + s.SrcPort + "-" + s.DstIp + "-" + s.DstPort
}

// extractDstIps extracts the two dst= IP addresses from a conntrack line.
// A conntrack line contains two tuples: the original direction and the reply direction.
// Example: ipv4 2 tcp 6 86390 ESTABLISHED src=10.0.0.1 dst=192.168.1.100 sport=12345 dport=80 packets=10 bytes=600 src=192.168.1.100 dst=10.0.0.1 sport=80 dport=12345 packets=8 bytes=480 mark=0 zone=0 use=2
// Returns (original-dst, reply-dst), i.e. ("192.168.1.100", "10.0.0.1") in the example above.
func extractDstIps(line string) (string, string) {
	var first, second string
	searchFrom := 0
	for i := 0; i < 2; i++ {
		idx := strings.Index(line[searchFrom:], "dst=")
		if idx < 0 {
			break
		}

		start := searchFrom + idx + 4
		end := start
		for end < len(line) && line[end] != ' ' && line[end] != '\t' {
			end++
		}

		if i == 0 {
			first = line[start:end]
		} else {
			second = line[start:end]
		}
		searchFrom = end
	}

	return first, second
}

// parseConntrackLine parses a single line from /proc/net/nf_conntrack.
// example: ipv4     2 icmp     1 8 src=10.1.2.197 dst=192.168.100.1 type=8 code=0 id=63489 packets=88 bytes=7392 src=192.168.100.1 dst=192.168.100.147 type=0 code=0 id=63489 packets=20 bytes=1680 mark=0 zone=0 use=2
func parseConntrackLine(line string) (*SessionStat, bool) {
	fields := strings.Fields(line)
	if len(fields) < 10 {
		return nil, false
	}

	stat := &SessionStat{
		Protocol: fields[2],
	}

	var packets, bytes, replyPackets, replyBytes uint64
	var src, dst, rsrc, rdst string
	var sport, dport, rsport, rdport string
	var icmpType, replyIcmpType, icmpCode, replyIcmpCode string

	unreplied := strings.Contains(line, "[UNREPLIED]")

	for _, field := range fields {
		parts := strings.Split(field, "=")
		if len(parts) != 2 {
			continue
		}
		key, value := parts[0], parts[1]

		switch key {
		case "src":
			if src == "" {
				src = value
			} else {
				rsrc = value
			}
		case "dst":
			if dst == "" {
				dst = value
			} else {
				rdst = value
			}
		case "sport":
			if sport == "" {
				sport = value
			} else {
				rsport = value
			}
		case "dport":
			if dport == "" {
				dport = value
			} else {
				rdport = value
			}
		case "type":
			if icmpType == "" {
				icmpType = value
			} else {
				replyIcmpType = value
			}
		case "code":
			if icmpCode == "" {
				icmpCode = value
			} else {
				replyIcmpCode = value
			}
		case "packets":
			if packets == 0 {
				packets, _ = strconv.ParseUint(value, 10, 64)
			} else {
				replyPackets, _ = strconv.ParseUint(value, 10, 64)
			}
		case "bytes":
			if bytes == 0 {
				bytes, _ = strconv.ParseUint(value, 10, 64)
			} else {
				replyBytes, _ = strconv.ParseUint(value, 10, 64)
			}
		}
	}

	stat.SrcIp = src
	stat.DstIp = dst
	stat.IcmpType = icmpType
	stat.IcmpCode = icmpCode
	stat.SrcPort = sport
	stat.DstPort = dport
	stat.Packets = packets
	stat.Bytes = bytes

	if !unreplied {
		stat.ReplySrcIp = rsrc
		stat.ReplyDstIp = rdst
		stat.ReplySrcPort = rsport
		stat.ReplyDstPort = rdport
		stat.ReplyIcmpType = replyIcmpType
		stat.ReplyIcmpCode = replyIcmpCode
		stat.ReplyPackets = replyPackets
		stat.ReplyBytes = replyBytes
	}

	return stat, true
}

// updateCountersByConntrack assumes the caller already holds c.mu.
// Its only caller, Update(), locks c.mu before dispatching to the eBPF
// or conntrack path; locking again here would self-deadlock since
// sync.Mutex is non-reentrant, leaving c.mu held forever. Subsequent
// SetVip / RemoveVip handlers block on vipPromCollector.mu.Lock() and
// async commands never invoke their callback URL.
func (c *vipCollector) updateCountersByConntrack() {
	startTime := time.Now()
	var totalSessions, parsedSessions, skippedSessions, newSessions, staleSessions, matchedSessions int

	file, err := os.Open("/proc/net/nf_conntrack")
	if err != nil {
		log.Warnf("Failed to open /proc/net/nf_conntrack: %v", err)
		return
	}
	defer file.Close()

	currentStats := make(map[string]*SessionStat)
	currentTime := time.Now().Unix()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		totalSessions++

		firstDst, secondDst := extractDstIps(line)
		_, matchFirst := c.counters[firstDst]
		_, matchSecond := c.counters[secondDst]
		if !matchFirst && !matchSecond {
			skippedSessions++
			continue
		}

		stat, ok := parseConntrackLine(line)
		if !ok {
			continue
		}
		parsedSessions++
		stat.LastUpdate = currentTime
		currentStats[stat.Key()] = stat
	}

	if err := scanner.Err(); err != nil {
		log.Warnf("Error reading /proc/net/nf_conntrack: %v", err)
	}

	for key, current := range currentStats {
		previous, exists := c.previousStats[key]
		if !exists {
			newSessions++
		}

		var pktIn, bytesIn, pktOut, bytesOut uint64

		// packets counter will not decrease when the session is closed
		if exists && current.Packets >= previous.Packets &&
			current.ReplyPackets >= previous.ReplyPackets {
			pktIn = current.Packets - previous.Packets
			bytesIn = current.Bytes - previous.Bytes
			pktOut = current.ReplyPackets - previous.ReplyPackets
			bytesOut = current.ReplyBytes - previous.ReplyBytes
		} else {
			pktIn = current.Packets
			bytesIn = current.Bytes
			pktOut = current.ReplyPackets
			bytesOut = current.ReplyBytes
		}

		if counter, ok := c.counters[current.DstIp]; ok {
			matchedSessions++
			counter.InPackets += pktIn
			counter.InBytes += bytesIn
			counter.OutPackets += pktOut
			counter.OutBytes += bytesOut
		} else if counter, ok := c.counters[current.ReplyDstIp]; ok {
			matchedSessions++
			counter.OutPackets += pktIn
			counter.OutBytes += bytesIn
			counter.InPackets += pktOut
			counter.InBytes += bytesOut
		}

		// Update previousStats with current session data
		c.previousStats[key] = current
	}

	// Clean up sessions older than 300 seconds from previousStats
	for key, previous := range c.previousStats {
		if currentTime-previous.LastUpdate > 300 {
			staleSessions++
			delete(c.previousStats, key)
		}
	}

	log.Debugf("updateCountersByConntrack completed: duration=%v, totalSessions=%d, skippedSessions=%d, parsedSessions=%d, newSessions=%d, matchedSessions=%d, staleSessions=%d",
		time.Since(startTime), totalSessions, skippedSessions, parsedSessions, newSessions, matchedSessions, staleSessions)
}

func (c *vipCollector) Update(ch chan<- prom.Metric) error {
	if !IsMaster() {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if ebpfObjs != nil {
		log.Debugf("VIP metrics: eBPF mode — collecting stats for %d VIPs", len(c.counters))
		updateCountersByEbpf(c.counters)
	} else {
		log.Debugf("VIP metrics: conntrack mode — collecting stats for %d VIPs", len(c.counters))
		c.updateCountersByConntrack()
	}

	for _, rule := range c.counters {
		vipUuid := rule.VipUuid
		ch <- prom.MustNewConstMetric(c.inByteEntry, prom.CounterValue, float64(rule.InBytes), vipUuid)
		ch <- prom.MustNewConstMetric(c.inPktEntry, prom.CounterValue, float64(rule.InPackets), vipUuid)
		ch <- prom.MustNewConstMetric(c.outByteEntry, prom.CounterValue, float64(rule.OutBytes), vipUuid)
		ch <- prom.MustNewConstMetric(c.outPktEntry, prom.CounterValue, float64(rule.OutPackets), vipUuid)
	}

	return nil
}

func checkQdisc(nic string) {
	bash := utils.Bash{
		Command: fmt.Sprintf("tc qdisc show dev %s | grep 'mq'", nic),
	}
	_, _, errOut, _ := bash.RunWithReturn()
	if strings.Contains(errOut, "mq") {
		resetBash := utils.Bash{
			Command: fmt.Sprintf("tc qdisc replace dev %s root handle 1: htb default 1", nic),
			Sudo:    true,
		}
		resetBash.Run()
	}
}

func init() {
	totalQosRules = make(map[string]interfaceInOutQosRules, MAX_PUBLIC_INTERFACE)
}

func VipEntryPoint() {
	initVipCounterChains()

	server.RegisterAsyncCommandHandler(VR_CREATE_VIP, server.VyosLock(setVipHandler))
	server.RegisterAsyncCommandHandler(VR_REMOVE_VIP, server.VyosLock(removeVipHandler))
	server.RegisterAsyncCommandHandler(VR_SET_VIP_QOS, server.VyosLock(setVipQos))
	server.RegisterAsyncCommandHandler(VR_DELETE_VIP_QOS, server.VyosLock(deleteVipQos))
	server.RegisterAsyncCommandHandler(VR_SYNC_VIP_QOS, server.VyosLock(syncVipQos))
	server.RegisterAsyncCommandHandler(VR_FLUSH_VIP_QOS, server.VyosLock(flushVipQos))
}

func clearUnusedTcRule() {
	interfaces, err := net.Interfaces()
	if err != nil {
		return
	}

	if utils.IsVYOS() && utils.IsEnableVyosCmd() {
		tree := server.NewParserFromShowConfiguration().Tree
		updated := false
		for _, iface := range interfaces {
			if !strings.HasPrefix(iface.Name, "ifb") {
				continue
			}

			srcNicName := strings.Replace(iface.Name, "ifb", "eth", -1)
			if n := tree.Getf("interfaces ethernet %s redirect", srcNicName); n != nil {
				n.Delete()
				updated = true
			}
			if n := tree.Getf("interfaces input %s", iface.Name); n != nil {
				n.Delete()
				updated = true
			}
		}
		if updated {
			tree.Apply(false)
		}
		return
	}

	for _, iface := range interfaces {
		if !strings.HasPrefix(iface.Name, "ifb") {
			continue
		}

		srcNicName := strings.Replace(iface.Name, "ifb", "eth", -1)
		b := utils.Bash{
			Command: fmt.Sprintf("tc qdisc del dev %s ingress; ip link del %s", srcNicName, iface.Name),
			Sudo:    true,
		}

		b.Run()
	}
}
