package plugin

import (
	"fmt"
	"strings"
	"testing"

	"zstack-vyos/utils"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/suite"
)

// VipTestSuite VIP功能测试套件
type VipTestSuite struct {
	suite.Suite
	env *VpcTestEnv
}

// SetupTest 每个测试前的准备工作
func (s *VipTestSuite) SetupTest() {
	s.env = NewVpcTestEnv()
	s.env.Setup()
	s.env.SetupVIP()
}

// TearDownTest 每个测试后的清理工作
func (s *VipTestSuite) TearDownTest() {
	s.env.Teardown()
}

// TestSetVipForNoHA 测试在非 HA 模式下设置 VIP
func (s *VipTestSuite) TestSetVipForNoHA() {
	oldHaStatus := utils.GetHaStatus()
	utils.SetHaStatus(utils.NOHA)
	defer utils.SetHaStatus(oldHaStatus)

	vips := []vipInfo{s.env.Vip1, s.env.Vip2}
	nicIps := []nicIpInfo{s.env.PubNicIp}

	cmd := &setVipCmd{
		SyncVip: false,
		Vips:    vips,
		NicIps:  nicIps,
	}

	log.Debugf("__________TestSetVipForNoHA: setting VIP %+v", cmd)
	SetVip(cmd)
	s.checkVipConfig(vips, s.env.PubNic, utils.NOHA)

	// 再次设置，验证幂等性
	SetVip(cmd)
	s.checkVipConfig(vips, s.env.PubNic, utils.NOHA)

	// 删除 VIP
	removeCmd := &removeVipCmd{Vips: vips}
	RemoveVip(removeCmd)
	s.checkVipDelete(vips, s.env.PubNic)

	// 再次删除，验证幂等性
	RemoveVip(removeCmd)
	s.checkVipDelete(vips, s.env.PubNic)
}

// TestSetVipForBackup 测试在 HA Backup 模式下设置 VIP
func (s *VipTestSuite) TestSetVipForBackup() {
	oldHaStatus := utils.GetHaStatus()
	utils.SetHaStatus(utils.HABACKUP)
	defer utils.SetHaStatus(oldHaStatus)

	vips := []vipInfo{s.env.Vip1, s.env.Vip2}
	nicIps := []nicIpInfo{s.env.PubNicIp}

	cmd := &setVipCmd{
		SyncVip: false,
		Vips:    vips,
		NicIps:  nicIps,
	}

	log.Debugf("__________TestSetVipForBackup: setting VIP %+v", cmd)
	SetVip(cmd)
	s.checkVipConfig(vips, s.env.PubNic, utils.HABACKUP)

	// 再次设置，验证幂等性
	SetVip(cmd)
	s.checkVipConfig(vips, s.env.PubNic, utils.HABACKUP)

	// 删除 VIP
	removeCmd := &removeVipCmd{Vips: vips}
	RemoveVip(removeCmd)
	s.checkVipDelete(vips, s.env.PubNic)

	// 再次删除，验证幂等性
	RemoveVip(removeCmd)
	s.checkVipDelete(vips, s.env.PubNic)
}

// TestSetVipWithSync 测试同步模式设置 VIP
func (s *VipTestSuite) TestSetVipWithSync() {
	oldHaStatus := utils.GetHaStatus()
	utils.SetHaStatus(utils.HABACKUP)
	defer utils.SetHaStatus(oldHaStatus)

	vips := []vipInfo{s.env.Vip1, s.env.Vip2}
	nicIps := []nicIpInfo{s.env.PubNicIp}

	cmd := &setVipCmd{
		SyncVip: true,
		Vips:    vips,
		NicIps:  nicIps,
	}

	log.Debugf("__________TestSetVipWithSync: setting VIP with sync %+v", cmd)
	SetVip(cmd)
	s.checkVipConfig(vips, s.env.PubNic, utils.HABACKUP)

	// 删除网卡 IP 地址，测试同步功能
	cidr, err := utils.NetmaskToCIDR(s.env.PubNic.Netmask)
	s.Require().NoError(err)
	addr := fmt.Sprintf("%v/%v", s.env.PubNic.Ip, cidr)
	bash := utils.Bash{
		Command: fmt.Sprintf("ip address del %s dev %s", addr, s.env.PubNic.Name),
	}
	bash.Run()

	// 再次设置 VIP，应该恢复网卡 IP
	SetVip(cmd)
	s.checkVipConfig(vips, s.env.PubNic, utils.HABACKUP)

	// 删除 VIP
	removeCmd := &removeVipCmd{Vips: vips}
	RemoveVip(removeCmd)
	s.checkVipDelete(vips, s.env.PubNic)
}

// TestSetVipMultipleNics 测试多网卡 VIP 配置
func (s *VipTestSuite) TestSetVipMultipleNics() {
	oldHaStatus := utils.GetHaStatus()
	utils.SetHaStatus(utils.NOHA)
	defer utils.SetHaStatus(oldHaStatus)

	// 在公网网卡上设置 VIP
	vipsPub := []vipInfo{s.env.Vip1, s.env.Vip2}
	nicIpsPub := []nicIpInfo{s.env.PubNicIp}

	cmdPub := &setVipCmd{
		SyncVip: false,
		Vips:    vipsPub,
		NicIps:  nicIpsPub,
	}

	SetVip(cmdPub)
	s.checkVipConfig(vipsPub, s.env.PubNic, utils.NOHA)

	// 在私网网卡上设置 VIP
	vipsPri := []vipInfo{s.env.Vip3}
	nicIpsPri := []nicIpInfo{s.env.PriNicIp}

	cmdPri := &setVipCmd{
		SyncVip: false,
		Vips:    vipsPri,
		NicIps:  nicIpsPri,
	}

	log.Debugf("__________TestSetVipMultipleNics: setting IPv6 VIP %+v", cmdPri)
	SetVip(cmdPri)
	s.checkVipConfig(vipsPri, s.env.PriNic, utils.NOHA)

	// 删除所有 VIP
	removeCmd1 := &removeVipCmd{Vips: vipsPub}
	RemoveVip(removeCmd1)
	s.checkVipDelete(vipsPub, s.env.PubNic)

	removeCmd2 := &removeVipCmd{Vips: vipsPri}
	RemoveVip(removeCmd2)
	s.checkVipDelete(vipsPri, s.env.PriNic)
}

// TestSetVipIPv6 测试 IPv6 VIP 配置
func (s *VipTestSuite) TestSetVipIPv6() {
	oldHaStatus := utils.GetHaStatus()
	utils.SetHaStatus(utils.NOHA)
	defer utils.SetHaStatus(oldHaStatus)

	vips := []vipInfo{s.env.Vip4, s.env.Vip5}
	nicIps := []nicIpInfo{s.env.PubNicIp}

	cmd := &setVipCmd{
		SyncVip: false,
		Vips:    vips,
		NicIps:  nicIps,
	}

	log.Debugf("__________TestSetVipIPv6: setting IPv6 VIP %+v", cmd)
	SetVip(cmd)
	s.checkVipConfig(vips, s.env.PubNic, utils.NOHA)

	// 再次设置，验证幂等性
	SetVip(cmd)
	s.checkVipConfig(vips, s.env.PubNic, utils.NOHA)

	// 删除 VIP
	removeCmd := &removeVipCmd{Vips: vips}
	RemoveVip(removeCmd)
	s.checkVipDelete(vips, s.env.PubNic)

	// 再次删除，验证幂等性
	RemoveVip(removeCmd)
	s.checkVipDelete(vips, s.env.PubNic)
}

// TestSetVipDualStack 测试双栈 VIP 配置（IPv4 + IPv6）
func (s *VipTestSuite) TestSetVipDualStack() {
	oldHaStatus := utils.GetHaStatus()
	utils.SetHaStatus(utils.NOHA)
	defer utils.SetHaStatus(oldHaStatus)

	vips := []vipInfo{s.env.Vip6}
	nicIps := []nicIpInfo{s.env.PubNicIp}

	cmd := &setVipCmd{
		SyncVip: false,
		Vips:    vips,
		NicIps:  nicIps,
	}

	log.Debugf("__________TestSetVipDualStack: setting dual-stack VIP %+v", cmd)
	SetVip(cmd)
	s.checkVipConfig(vips, s.env.PubNic, utils.NOHA)

	// 测试 VIP 计数器规则，验证 inRules 和 outRules 包含 IPv4 和 IPv6 两种 VIP 的计数
	for _, vip := range vips {
		s.checkVipCounterRules(vip, s.env.PubNic.Name, true)
	}

	log.Debugf("__________TestSetVipDualStack 1: setting dual-stack VIP %+v", cmd)
	// 再次设置，验证幂等性
	SetVip(cmd)
	s.checkVipConfig(vips, s.env.PubNic, utils.NOHA)

	// 验证计数器规则仍然存在
	for _, vip := range vips {
		s.checkVipCounterRules(vip, s.env.PubNic.Name, true)
	}

	log.Debugf("__________TestSetVipDualStack 2: setting dual-stack VIP %+v", cmd)
	// 删除 VIP
	removeCmd := &removeVipCmd{Vips: vips}
	RemoveVip(removeCmd)
	s.checkVipDelete(vips, s.env.PubNic)

	// 验证计数器规则已被删除
	for _, vip := range vips {
		s.checkVipCounterRules(vip, s.env.PubNic.Name, false)
	}

	log.Debugf("__________TestSetVipDualStack 3: setting dual-stack VIP %+v", cmd)
	// 再次删除，验证幂等性
	RemoveVip(removeCmd)
	s.checkVipDelete(vips, s.env.PubNic)
}

// TestSetVipMixedIPv4IPv6 测试混合 IPv4 和 IPv6 VIP 配置
func (s *VipTestSuite) TestSetVipMixedIPv4IPv6() {
	oldHaStatus := utils.GetHaStatus()
	utils.SetHaStatus(utils.NOHA)
	defer utils.SetHaStatus(oldHaStatus)

	// 同时设置 IPv4、IPv6 和双栈 VIP
	vips := []vipInfo{s.env.Vip1, s.env.Vip4, s.env.Vip6}
	nicIps := []nicIpInfo{s.env.PubNicIp}

	cmd := &setVipCmd{
		SyncVip: false,
		Vips:    vips,
		NicIps:  nicIps,
	}

	log.Debugf("__________TestSetVipMixedIPv4IPv6: setting mixed VIPs %+v", cmd)
	SetVip(cmd)
	s.checkVipConfig(vips, s.env.PubNic, utils.NOHA)

	// 删除 VIP
	removeCmd := &removeVipCmd{Vips: vips}
	RemoveVip(removeCmd)
	s.checkVipDelete(vips, s.env.PubNic)
}

// TestVipSuite 运行 VIP 测试套件
func TestVipSuite(t *testing.T) {
	suite.Run(t, new(VipTestSuite))
}

// checkVipConfig 检查 VIP 是否正确配置
func (s *VipTestSuite) checkVipConfig(vips []vipInfo, nic utils.NicInfo, haStatus string) {
	// 获取 Linux 上的 IP 地址
	ipsInLinux := s.getLinuxNicVips(nic.Name)

	// 检查网卡 IP 必须是第一个
	s.Require().Contains(ipsInLinux[0], nic.Ip, "check ip[%s] in linux failed on interface %s, result %s", nic.Ip, nic.Name, ipsInLinux)

	// 构建 IP 映射
	ipMaps := make(map[string]string)
	for _, ip := range ipsInLinux {
		iip := strings.Split(ip, "/")[0]
		ipMaps[iip] = iip
	}

	// 检查每个 VIP
	for _, vip := range vips {
		// 检查 IPv4 地址（非 HA Backup 的管理网卡）
		if vip.Ip != "" && (haStatus != utils.HABACKUP || nic.Category != "Management") {
			_, ok := ipMaps[vip.Ip]
			s.Require().True(ok, "check IPv4 ip[%s] in linux failed on interface %s, ipMaps %+v", vip.Ip, nic.Name, ipMaps)
		}

		// 检查 IPv6 地址（非 HA Backup 的管理网卡）
		if vip.Ip6 != "" && (haStatus != utils.HABACKUP || nic.Category != "Management") {
			_, ok := ipMaps[vip.Ip6]
			s.Require().True(ok, "check IPv6 ip[%s] in linux failed on interface %s, ipMaps %+v", vip.Ip6, nic.Name, ipMaps)
		}

		// 检查 iptables 规则
		s.checkVipIptablesRules(vip, nic.Name, true)
	}
}

// checkVipDelete 检查 VIP 是否正确删除
func (s *VipTestSuite) checkVipDelete(vips []vipInfo, nic utils.NicInfo) {
	// 获取 Linux 上的 IP 地址
	ipsInLinux := s.getLinuxNicVips(nic.Name)
	s.Require().Contains(ipsInLinux[0], nic.Ip, "check ip[%s] in linux failed on interface %s", nic.Ip, nic.Name)

	// 构建 IP 映射
	ipMaps := make(map[string]string)
	for _, ip := range ipsInLinux {
		iip := strings.Split(ip, "/")[0]
		ipMaps[iip] = iip
	}

	// 检查每个 VIP 已被删除
	for _, vip := range vips {
		// 检查 IPv4 地址已删除
		if vip.Ip != "" {
			_, ok := ipMaps[vip.Ip]
			s.Require().False(ok, "check delete IPv4 ip[%s] in linux failed on interface %s", vip.Ip, nic.Name)
		}

		// 检查 IPv6 地址已删除
		if vip.Ip6 != "" {
			_, ok := ipMaps[vip.Ip6]
			s.Require().False(ok, "check delete IPv6 ip[%s] in linux failed on interface %s", vip.Ip6, nic.Name)
		}

		// 检查 iptables 规则已删除
		s.checkVipIptablesRules(vip, nic.Name, false)
	}
}

// getLinuxNicVips 获取 Linux 网卡上的所有 IP 地址
func (s *VipTestSuite) getLinuxNicVips(nicName string) []string {
	var linuxIps []string

	bash := utils.Bash{
		Command: fmt.Sprintf("ip add show dev %s | grep -E \"inet|inet6\" | awk '{print $2}'", nicName),
	}
	_, out, _, err := bash.RunWithReturn()
	if err != nil {
		return linuxIps
	}

	lines := strings.Split(out, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			linuxIps = append(linuxIps, line)
		}
	}

	return linuxIps
}

// checkVipIptablesRules 检查 VIP 相关的 iptables 规则
// shouldExist: true 表示规则应该存在，false 表示规则应该被删除
func (s *VipTestSuite) checkVipIptablesRules(vip vipInfo, nicName string, shouldExist bool) {
	// 检查 IPv4 规则
	if vip.Ip != "" {
		s.checkVipIpv4IptablesRules(vip, nicName, shouldExist)
	}

	// 检查 IPv6 规则
	if vip.Ip6 != "" {
		s.checkVipIpv6IptablesRules(vip, nicName, shouldExist)
	}
}

// checkVipIpv4IptablesRules 检查 IPv4 VIP 相关的 iptables 规则
func (s *VipTestSuite) checkVipIpv4IptablesRules(vip vipInfo, nicName string, shouldExist bool) {
	// 1. 检查 filter 表中的 ICMP ACCEPT 规则
	// 规则格式: -A <RULESET_NAME> -d <VIP>/32 -p icmp -m comment --comment vip-<vip.VipUuid> -j ACCEPT
	// 注意：addVipFirewalRuleByIptables 使用 makeVipRuleDescription(vip) 即 "vip-<VipUuid>"
	ruleSetName := utils.GetRuleSetName(nicName, utils.RULESET_LOCAL)
	filterTable := utils.NewIpTables(utils.FirewallTable)

	vipComment := fmt.Sprintf("vip-%s", vip.VipUuid)
	icmpRule := utils.NewIpTableRule(ruleSetName).
		SetDstIp(vip.Ip + "/32").
		SetProto(utils.IPTABLES_PROTO_ICMP).
		SetComment(vipComment).
		SetAction(utils.IPTABLES_ACTION_ACCEPT)

	icmpExists := filterTable.Check(icmpRule)
	if shouldExist {
		s.Require().True(icmpExists, "IPv4 VIP ICMP firewall rule should exist for %s on %s", vip.Ip, nicName)
	} else {
		s.Require().False(icmpExists, "IPv4 VIP ICMP firewall rule should be deleted for %s on %s", vip.Ip, nicName)
	}

	// 2. 检查 nat 表中的入向计数规则
	// 规则格式: -A vip.in.counter -i <nicName> -d <VIP>/32 -m comment --comment <vip.VipUuid> -j RETURN
	natTable := utils.NewIpTables(utils.NatTable)

	inCounterRule := utils.NewIpTableRule("vip.in.counter").
		SetInNic(nicName).
		SetDstIp(vip.Ip + "/32").
		SetComment(vip.VipUuid).
		SetAction(utils.IPTABLES_ACTION_RETURN)

	inCounterExists := natTable.Check(inCounterRule)
	if shouldExist {
		s.Require().True(inCounterExists, "IPv4 VIP in-counter rule should exist for %s on %s", vip.Ip, nicName)
	} else {
		s.Require().False(inCounterExists, "IPv4 VIP in-counter rule should be deleted for %s on %s", vip.Ip, nicName)
	}

	// 3. 检查 nat 表中的出向计数规则
	// 规则格式: -A vip.out.counter -o <nicName> -s <VIP>/32 -m comment --comment <vip.VipUuid> -j RETURN
	outCounterRule := utils.NewIpTableRule("vip.out.counter").
		SetOutNic(nicName).
		SetSrcIp(vip.Ip + "/32").
		SetComment(vip.VipUuid).
		SetAction(utils.IPTABLES_ACTION_RETURN)

	outCounterExists := natTable.Check(outCounterRule)
	if shouldExist {
		s.Require().True(outCounterExists, "IPv4 VIP out-counter rule should exist for %s on %s", vip.Ip, nicName)
	} else {
		s.Require().False(outCounterExists, "IPv4 VIP out-counter rule should be deleted for %s on %s", vip.Ip, nicName)
	}
}

// checkVipIpv6IptablesRules 检查 IPv6 VIP 相关的 ip6tables 规则
func (s *VipTestSuite) checkVipIpv6IptablesRules(vip vipInfo, nicName string, shouldExist bool) {
	// 1. 检查 nat 表中的入向计数规则 (IPv6)
	// 规则格式: -A vip.in.counter -i <nicName> -d <VIP6>/128 -m comment --comment <vip.VipUuid> -j RETURN
	natTable := utils.NewIpTablesByIpVersion(utils.NatTable, utils.IP_VERSION_6)

	inCounterRule := utils.NewIpTableRule("vip.in.counter").
		SetInNic(nicName).
		SetDstIp(vip.Ip6 + "/128").
		SetComment(vip.VipUuid).
		SetAction(utils.IPTABLES_ACTION_RETURN)

	inCounterExists := natTable.Check(inCounterRule)
	if shouldExist {
		s.Require().True(inCounterExists, "IPv6 VIP in-counter rule should exist for %s on %s", vip.Ip6, nicName)
	} else {
		s.Require().False(inCounterExists, "IPv6 VIP in-counter rule should be deleted for %s on %s", vip.Ip6, nicName)
	}

	// 2. 检查 nat 表中的出向计数规则 (IPv6)
	// 规则格式: -A vip.out.counter -o <nicName> -s <VIP6>/128 -m comment --comment <vip.VipUuid> -j RETURN
	outCounterRule := utils.NewIpTableRule("vip.out.counter").
		SetOutNic(nicName).
		SetSrcIp(vip.Ip6 + "/128").
		SetComment(vip.VipUuid).
		SetAction(utils.IPTABLES_ACTION_RETURN)

	outCounterExists := natTable.Check(outCounterRule)
	if shouldExist {
		s.Require().True(outCounterExists, "IPv6 VIP out-counter rule should exist for %s on %s", vip.Ip6, nicName)
	} else {
		s.Require().False(outCounterExists, "IPv6 VIP out-counter rule should be deleted for %s on %s", vip.Ip6, nicName)
	}
}

// checkVipCounterRules 检查 VIP 计数器规则的存在性和计数值读取
// 使用 parseVipCounterFromIptables 解析 inRules 和 outRules 并验证
func (s *VipTestSuite) checkVipCounterRules(vip vipInfo, nicName string, shouldExist bool) {
	// 解析入向计数器
	inRules := ParseVipCounterFromIptables("vip.in.counter", false)
	// 解析出向计数器
	outRules := ParseVipCounterFromIptables("vip.out.counter", true)

	if shouldExist {
		// 验证 VIP UUID 存在于计数器中
		inRule, inExists := inRules[vip.VipUuid]
		outRule, outExists := outRules[vip.VipUuid]

		s.Require().True(inExists, "VIP UUID %s should exist in in-counter rules", vip.VipUuid)
		s.Require().True(outExists, "VIP UUID %s should exist in out-counter rules", vip.VipUuid)

		if inExists {
			log.Debugf("in rule: %+v", inRule)
			// 验证 IPv4 VIP
			if vip.Ip != "" {
				s.Require().Equal(vip.Ip, inRule.Destination, "In-counter destination should match IPv4 VIP %s", vip.Ip)
			}
			// 验证 IPv6 VIP
			if vip.Ip6 != "" {
				s.Require().Equal(vip.Ip6, inRule.Destination6, "In-counter destination should match IPv6 VIP %s", vip.Ip6)
			}
		}

		if outExists {
			// 验证 IPv4 VIP
			log.Debugf("out rule: %+v", outRule)
			if vip.Ip != "" {
				s.Require().Equal(vip.Ip, outRule.Source, "Out-counter source should match IPv4 VIP %s", vip.Ip)
			}
			// 验证 IPv6 VIP
			if vip.Ip6 != "" {
				s.Require().Equal(vip.Ip6, outRule.Source6, "Out-counter source should match IPv6 VIP %s", vip.Ip6)
			}
		}

		// 对于双栈 VIP，验证 IPv4 和 IPv6 的计数都被正确记录
		if vip.Ip != "" && vip.Ip6 != "" {
			log.Debugf("Dual-stack VIP %s verified: IPv4=%s, IPv6=%s", vip.VipUuid, vip.Ip, vip.Ip6)
		}
	} else {
		// 验证 VIP UUID 不存在于计数器中
		_, inExists := inRules[vip.VipUuid]
		_, outExists := outRules[vip.VipUuid]

		s.Require().False(inExists, "VIP UUID %s should not exist in in-counter rules after deletion", vip.VipUuid)
		s.Require().False(outExists, "VIP UUID %s should not exist in out-counter rules after deletion", vip.VipUuid)
	}
}
