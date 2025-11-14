package plugintest

import (
	"fmt"
	"net"
	"testing"
	"zstack-vyos/plugin"
	"zstack-vyos/utils"

	"github.com/stretchr/testify/suite"
)

// PolicyRouteTestSuite 策略路由测试套件
type PolicyRouteTestSuite struct {
	suite.Suite
	env *VpcTestEnv
}

// SetupTest 每个测试前的准备工作
func (s *PolicyRouteTestSuite) SetupTest() {
	s.env = NewVpcTestEnv()
	s.env.Setup()
}

// TearDownTest 每个测试后的清理工作
func (s *PolicyRouteTestSuite) TearDownTest() {
	s.env.Teardown()
}

// TestSystemPolicyRoute 测试系统策略路由
func (s *PolicyRouteTestSuite) TestSystemPolicyRoute() {
	var cmd plugin.SyncPolicyRouteCmd
	cmd.RuleSets = []plugin.PolicyRuleSetInfo{
		{RuleSetName: "ZS-PR-RS-180", System: true},
		{RuleSetName: "ZS-PR-RS-181", System: true},
	}
	addr1 := fmt.Sprintf("%v/24", s.env.AdditionalPubNic1.Ip)
	_, cidr1, _ := net.ParseCIDR(addr1)
	addr3 := fmt.Sprintf("%v/24", s.env.PriNic.Ip)
	_, cidr3, _ := net.ParseCIDR(addr3)
	addr4 := fmt.Sprintf("%v/24", s.env.PriNic1.Ip)
	_, cidr4, _ := net.ParseCIDR(addr4)

	cmd.Rules = []plugin.PolicyRuleInfo{
		{RuleSetName: "ZS-PR-RS-181", RuleNumber: 1, SourceIp: cidr1.String(), TableNumber: 181, State: "enable"},
	}
	cmd.TableNumbers = []int{181}
	cmd.Routes = []plugin.PolicyRouteInfo{
		{TableNumber: 181, DestinationCidr: cidr1.String(), NextHopIp: s.env.AdditionalPubNic1.Gateway},
		{TableNumber: 181, DestinationCidr: cidr3.String(), NextHopIp: s.env.PriNic.Gateway, OutNicMic: s.env.PriNic.Mac},
		{TableNumber: 181, DestinationCidr: cidr4.String(), NextHopIp: s.env.PriNic1.Gateway, OutNicMic: s.env.PriNic1.Mac},
		{TableNumber: 181, DestinationCidr: "0.0.0.0/0", NextHopIp: s.env.AdditionalPubNic1.Gateway},
	}
	cmd.Refs = []plugin.PolicyRuleSetNicRef{
		{RuleSetName: "ZS-PR-RS-181", Mac: s.env.AdditionalPubNic1.Mac},
	}
	cmd.MarkConntrack = true

	plugin.ApplyPolicyRoutes(&cmd)
	s.checkSystemPolicyRouteIpRule(true)
	s.checkSystemPolicyRouteRouteEntry(true)

	delCmd := plugin.SyncPolicyRouteCmd{}
	plugin.ApplyPolicyRoutes(&delCmd)
	s.checkSystemPolicyRouteIpRule(false)
	s.checkSystemPolicyRouteRouteEntry(false)
}

// checkSystemPolicyRouteIpRule 检查系统策略路由 IP 规则
func (s *PolicyRouteTestSuite) checkSystemPolicyRouteIpRule(exist bool) {
	rules := utils.GetZStackIpRules()

	cidr, err := utils.NetmaskToCIDR(s.env.AdditionalPubNic1.Netmask)
	s.Require().NoError(err)
	addr1 := fmt.Sprintf("%v/%v", s.env.AdditionalPubNic1.Ip, cidr)
	_, cidr1, _ := net.ParseCIDR(addr1)
	expectRules := []utils.ZStackIpRule{
		{Fwmark: 181, TableId: 181},
		{From: cidr1.String(), TableId: 181},
	}

	for _, r := range expectRules {
		found := false
		for _, o := range rules {
			if r.Equal(o) {
				found = true
				break
			}
		}

		if exist {
			s.True(found, fmt.Sprintf("ip rule not found %+v", r))
		} else {
			s.False(found, fmt.Sprintf("ip rule found %+v", r))
		}
	}
}

// checkSystemPolicyRouteRouteEntry 检查系统策略路由路由条目
func (s *PolicyRouteTestSuite) checkSystemPolicyRouteRouteEntry(exist bool) {
	routes := utils.GetCurrentRouteEntries(181)

	cidr, err := utils.NetmaskToCIDR(s.env.PriNic.Netmask)
	s.Require().NoError(err)
	addr1 := fmt.Sprintf("%v/%v", s.env.PriNic.Ip, cidr)
	_, cidr1, _ := net.ParseCIDR(addr1)

	cidr, err = utils.NetmaskToCIDR(s.env.PriNic1.Netmask)
	s.Require().NoError(err)
	addr2 := fmt.Sprintf("%v/%v", s.env.PriNic1.Ip, cidr)
	_, cidr2, _ := net.ParseCIDR(addr2)

	cidr, err = utils.NetmaskToCIDR(s.env.AdditionalPubNic1.Netmask)
	s.Require().NoError(err)
	addr3 := fmt.Sprintf("%v/%v", s.env.AdditionalPubNic1.Ip, cidr)
	_, cidr3, _ := net.ParseCIDR(addr3)

	expectRoutes := []utils.ZStackRouteEntry{
		{TableId: 181, DestinationCidr: "0.0.0.0/0", NextHopIp: s.env.AdditionalPubNic1.Gateway},
		{TableId: 181, DestinationCidr: cidr1.String(), NextHopIp: s.env.PriNic.Gateway},
		{TableId: 181, DestinationCidr: cidr2.String(), NextHopIp: s.env.PriNic1.Gateway},
		{TableId: 181, DestinationCidr: cidr3.String(), NextHopIp: s.env.AdditionalPubNic1.Gateway},
	}

	for _, r := range expectRoutes {
		found := false
		for _, o := range routes {
			if err := r.Equal(o); err == nil {
				found = true
				break
			}
		}

		if exist {
			s.True(found, fmt.Sprintf("route entry not found %+v", r))
		} else {
			s.False(found, fmt.Sprintf("route entry found %+v", r))
		}
	}
}

// TestPolicyRouteSuite 运行策略路由测试套件
func TestPolicyRouteSuite(t *testing.T) {
	suite.Run(t, new(PolicyRouteTestSuite))
}
