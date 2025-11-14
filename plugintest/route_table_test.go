package plugintest

import (
	"testing"
	"zstack-vyos/plugin"
	"zstack-vyos/utils"

	"github.com/stretchr/testify/suite"
)

// RouteTableTestSuite 路由表测试套件
type RouteTableTestSuite struct {
	suite.Suite
	env                    *VpcIp4Env
	r1, r2, r3, r4, r5, r6 plugin.RouteInfo
	r7, r8                 plugin.RouteInfo
}

// SetupTest 每个测试前的准备工作
func (s *RouteTableTestSuite) SetupTest() {
	s.env = NewVpcIpv4Env()
	s.env.SetupBootStrap()

	s.r1 = plugin.RouteInfo{Destination: "1.1.1.0/24", Target: "10.1.1.101", Distance: 100}
	s.r2 = plugin.RouteInfo{Destination: "1.1.2.0/24", Target: "10.1.1.101", Distance: 110}
	s.r3 = plugin.RouteInfo{Destination: "1.1.3.0/24", Target: "10.1.2.101", Distance: 120}
	s.r4 = plugin.RouteInfo{Destination: "1.1.4.0/24", Target: "10.1.2.101", Distance: 130}
	s.r5 = plugin.RouteInfo{Destination: "1.1.5.0/24", Target: "10.1.1.101", Distance: 80}
	s.r6 = plugin.RouteInfo{Destination: "1.1.6.0/24", Target: "10.1.1.101", Distance: 90}
	s.r7 = plugin.RouteInfo{Destination: "1.1.6.0/24"}
	s.r8 = plugin.RouteInfo{Destination: "1.1.5.0/24"}
}

// TearDownTest 每个测试后的清理工作
func (s *RouteTableTestSuite) TearDownTest() {
	s.env.DestroyBootStrap()
}

// isRouteExisted 检查路由是否存在
func (s *RouteTableTestSuite) isRouteExisted(rts []utils.ZStackRouteEntry, rinfo plugin.RouteInfo) bool {
	for _, rt := range rts {
		if rt.DestinationCidr == rinfo.Destination &&
			rt.NextHopIp == rinfo.Target &&
			rt.Distance == rinfo.Distance {
			return true
		}
	}
	return false
}

// TestSetZebraRoutes 测试设置路由
func (s *RouteTableTestSuite) TestSetZebraRoutes() {
	// 添加所有路由
	routes := []plugin.RouteInfo{s.r1, s.r2, s.r3, s.r4, s.r5, s.r6}
	plugin.SetZebraRoutes(routes)

	rts := utils.GetCurrentRouteEntries(utils.ROUTETABLE_ID_MAIN)
	s.True(s.isRouteExisted(rts, s.r1), "r1 should be added")
	s.True(s.isRouteExisted(rts, s.r2), "r2 should be added")
	s.True(s.isRouteExisted(rts, s.r3), "r3 should be added")
	s.True(s.isRouteExisted(rts, s.r4), "r4 should be added")
	s.True(s.isRouteExisted(rts, s.r5), "r5 should be added")
	s.True(s.isRouteExisted(rts, s.r6), "r6 should be added")
	s.False(s.isRouteExisted(rts, s.r7), "r7 should not be added")
	s.False(s.isRouteExisted(rts, s.r8), "r8 should not be added")
}

// TestBlackHoleRoutes 测试黑洞路由
func (s *RouteTableTestSuite) TestBlackHoleRoutes() {
	// 先添加所有路由
	routes := []plugin.RouteInfo{s.r1, s.r2, s.r3, s.r4, s.r5, s.r6}
	plugin.SetZebraRoutes(routes)

	// 设置黑洞路由
	routes = []plugin.RouteInfo{s.r7, s.r8}
	plugin.SetZebraRoutes(routes)

	plugin.GetLinuxRoutes()
}

// TestSyncRoutes 测试同步路由（删除部分路由）
func (s *RouteTableTestSuite) TestSyncRoutes() {
	// 先添加所有路由
	routes := []plugin.RouteInfo{s.r1, s.r2, s.r3, s.r4, s.r5, s.r6}
	plugin.SetZebraRoutes(routes)

	// 只保留 r1 和 r2
	routes = []plugin.RouteInfo{s.r1, s.r2}
	plugin.SetZebraRoutes(routes)

	rts := utils.GetCurrentRouteEntries(utils.ROUTETABLE_ID_MAIN)
	s.True(s.isRouteExisted(rts, s.r1), "r1 should exist")
	s.True(s.isRouteExisted(rts, s.r2), "r2 should exist")
	s.False(s.isRouteExisted(rts, s.r3), "r3 should be deleted")
	s.False(s.isRouteExisted(rts, s.r4), "r4 should be deleted")
	s.False(s.isRouteExisted(rts, s.r5), "r5 should be deleted")
	s.False(s.isRouteExisted(rts, s.r6), "r6 should be deleted")
	s.False(s.isRouteExisted(rts, s.r7), "r7 should not exist")
	s.False(s.isRouteExisted(rts, s.r8), "r8 should not exist")
}

// TestAddBlackHoleRoutes 测试添加黑洞路由
func (s *RouteTableTestSuite) TestAddBlackHoleRoutes() {
	// 先设置部分路由
	routes := []plugin.RouteInfo{s.r1, s.r2}
	plugin.SetZebraRoutes(routes)

	// 添加黑洞路由
	routes = []plugin.RouteInfo{s.r1, s.r2, s.r7, s.r8}
	plugin.SetZebraRoutes(routes)

	rts := utils.GetCurrentRouteEntries(utils.ROUTETABLE_ID_MAIN)
	s.True(s.isRouteExisted(rts, s.r1), "r1 should exist")
	s.True(s.isRouteExisted(rts, s.r2), "r2 should exist")
	s.True(s.isRouteExisted(rts, s.r7), "r7 should be added")
	s.True(s.isRouteExisted(rts, s.r8), "r8 should be added")
}

// TestClearAllRoutes 测试清除所有路由
func (s *RouteTableTestSuite) TestClearAllRoutes() {
	// 先添加路由
	routes := []plugin.RouteInfo{s.r1, s.r2, s.r7, s.r8}
	plugin.SetZebraRoutes(routes)

	// 清空所有路由
	routes = []plugin.RouteInfo{}
	plugin.SetZebraRoutes(routes)

	rts := utils.GetCurrentRouteEntries(utils.ROUTETABLE_ID_MAIN)
	s.False(s.isRouteExisted(rts, s.r1), "r1 should be deleted")
	s.False(s.isRouteExisted(rts, s.r2), "r2 should be deleted")
	s.False(s.isRouteExisted(rts, s.r7), "r7 should be deleted")
	s.False(s.isRouteExisted(rts, s.r8), "r8 should be deleted")
}

// TestRouteTableSuite 运行路由表测试套件
func TestRouteTableSuite(t *testing.T) {
	suite.Run(t, new(RouteTableTestSuite))
}
