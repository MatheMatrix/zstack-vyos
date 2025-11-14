package plugintest

import (
	"context"
	"testing"
	"time"
	"zstack-vyos/plugin"
	"zstack-vyos/utils"

	"github.com/stretchr/testify/suite"
)

// IpvsTestSuite IPVS 负载均衡测试套件
type IpvsTestSuite struct {
	suite.Suite
	env *SlbHaTestEnv
}

// SetupTest 每个测试前的准备工作
func (s *IpvsTestSuite) SetupTest() {
	s.env = NewSlbHaTestEnv()
	_ = s.env.Setup()
	_ = s.env.SetupLoadBalancer()
}

// TearDownTest 每个测试后的清理工作
func (s *IpvsTestSuite) TearDownTest() {
	_ = s.env.TeardownLoadBalancer
	_ = s.env.Teardown()
}

// TestInitIpvs 测试初始化 IPVS
func (s *IpvsTestSuite) TestInitIpvs() {
	table := utils.NewIpTables(utils.NatTable)
	s.Suite.True(table.CheckChain(plugin.IPVS_LOG_CHAIN_NAME), "ipvs log chain should be created")
	s.Suite.True(table.CheckChain(plugin.IPVS_FULL_NAT_CHAIN_NAME), "ipvs full nat chain should be created")
}

// TestRefreshIpvsService 测试刷新 IPVS 服务
func (s *IpvsTestSuite) TestRefreshIpvsService() {
	s.env.AddPeerAddr("ut-pri", "192.168.3.10/24")
	s.env.AddPeerAddr("ut-pri", "192.168.3.11/24")

	ctx1, cancel1 := context.WithCancel(context.Background())
	ctx2, cancel2 := context.WithCancel(context.Background())
	go utils.StartUdpServer("192.168.3.10", 8080, ctx1)
	go utils.StartUdpServer("192.168.3.11", 8080, ctx2)

	plugin.RefreshIpvsService(map[string]plugin.LbInfo{s.env.Lb.ListenerUuid: s.env.Lb}, true)

	// 等待健康检查
	wait := 5
	time.Sleep(time.Duration(wait) * time.Second)

	// 检查 ipvs 配置
	ipvs, _ := plugin.NewIpvsConfFromSave()
	s.Require().Len(ipvs.Services, 1, "should have 1 ipvs front service")

	for _, fs := range ipvs.Services {
		s.Len(fs.BackendServers, 2, "should have 2 backend servers")
		for _, bs := range fs.BackendServers {
			s.Equal("192.168.2.100", bs.FrontIp)
			s.Equal("80", bs.FrontPort)
			s.Equal("-u", bs.ProtocolType)
			s.Equal("-m", bs.ConnectionType)
			s.Equal("rr", bs.Scheduler)
			s.Contains([]string{"192.168.3.10", "192.168.3.11"}, bs.BackendIp)
			s.Equal("8080", bs.BackendPort)
		}
	}

	// 检查后端服务器健康状态
	plugin.UpdateIpvsCounters()
	fs := plugin.GetIpvsFrontService(s.env.Lb.ListenerUuid)
	for _, bs := range fs.BackendServers {
		s.Equal(1, bs.Counter.Status, "backend server should be up")
	}

	// 停止一个后端服务器
	cancel2()
	time.Sleep(time.Duration(wait) * time.Second)
	plugin.UpdateIpvsCounters()
	for _, bs := range fs.BackendServers {
		if bs.BackendIp == "192.168.3.10" {
			s.Equal(1, bs.Counter.Status, "backend server 192.168.3.10 should be up")
		} else {
			s.Equal(0, bs.Counter.Status, "backend server 192.168.3.11 should be down")
		}
	}

	cancel1()
	time.Sleep(2 * time.Second)
}

// TestAddBackendServer 测试添加后端服务器
func (s *IpvsTestSuite) TestAddBackendServer() {
	s.env.AddPeerAddr("ut-pri", "192.168.3.10/24")
	s.env.AddPeerAddr("ut-pri", "192.168.3.11/24")
	s.env.AddPeerAddr("ut-pri", "192.168.3.12/24")

	s.env.Lb.ServerGroups = append(s.env.Lb.ServerGroups, s.env.SG1)
	ctx1, cancel1 := context.WithCancel(context.Background())
	ctx2, cancel2 := context.WithCancel(context.Background())
	ctx3, cancel3 := context.WithCancel(context.Background())
	go utils.StartUdpServer("192.168.3.10", 8080, ctx1)
	go utils.StartUdpServer("192.168.3.11", 8080, ctx2)
	go utils.StartUdpServer("192.168.3.12", 8080, ctx3)

	s.env.Lb.ServerGroups[0].BackendServers = []plugin.BackendServerInfo{s.env.BS1, s.env.BS2, s.env.BS3}
	plugin.RefreshIpvsService(map[string]plugin.LbInfo{s.env.Lb.ListenerUuid: s.env.Lb}, true)

	wait := 6
	time.Sleep(time.Duration(wait) * time.Second)

	// 检查 ipvs 配置
	ipvs, _ := plugin.NewIpvsConfFromSave()
	s.Require().Len(ipvs.Services, 1)
	for _, fs := range ipvs.Services {
		s.Len(fs.BackendServers, 3, "should have 3 backend servers")
	}

	// 检查健康状态
	plugin.UpdateIpvsCounters()
	fs := plugin.GetIpvsFrontService(s.env.Lb.ListenerUuid)
	for _, bs := range fs.BackendServers {
		s.Equal(1, bs.Counter.Status, "all backend servers should be up")
	}

	// 不做任何改变，再次刷新
	plugin.RefreshIpvsService(map[string]plugin.LbInfo{s.env.Lb.ListenerUuid: s.env.Lb}, true)
	time.Sleep(time.Duration(wait) * time.Second)

	ipvs, _ = plugin.NewIpvsConfFromSave()
	s.Require().Len(ipvs.Services, 1)
	for _, fs := range ipvs.Services {
		s.Len(fs.BackendServers, 3, "should still have 3 backend servers")
	}

	cancel1()
	cancel2()
	cancel3()
	time.Sleep(2 * time.Second)
}

// TestRemoveBackendServer 测试删除后端服务器
func (s *IpvsTestSuite) TestRemoveBackendServer() {
	// 先添加3个后端服务器
	s.env.AddPeerAddr("ut-pri", "192.168.3.10/24")
	s.env.AddPeerAddr("ut-pri", "192.168.3.11/24")
	s.env.AddPeerAddr("ut-pri", "192.168.3.12/24")

	s.env.Lb.ServerGroups = []plugin.ServerGroupInfo{s.env.SG1}
	s.env.SG1.BackendServers = []plugin.BackendServerInfo{s.env.BS1, s.env.BS2, s.env.BS3}
	s.env.Lb.ServerGroups[0].BackendServers = s.env.SG1.BackendServers

	ctx1, cancel1 := context.WithCancel(context.Background())
	ctx2, cancel2 := context.WithCancel(context.Background())
	ctx3, cancel3 := context.WithCancel(context.Background())
	go utils.StartUdpServer("192.168.3.10", 8080, ctx1)
	go utils.StartUdpServer("192.168.3.11", 8080, ctx2)
	go utils.StartUdpServer("192.168.3.12", 8080, ctx3)

	plugin.RefreshIpvsService(map[string]plugin.LbInfo{s.env.Lb.ListenerUuid: s.env.Lb}, true)
	time.Sleep(6 * time.Second)

	// 删除一个后端服务器
	cancel3()
	s.env.SG1.BackendServers = []plugin.BackendServerInfo{s.env.BS1, s.env.BS2}
	s.env.Lb.ServerGroups = []plugin.ServerGroupInfo{s.env.SG1}
	plugin.RefreshIpvsService(map[string]plugin.LbInfo{s.env.Lb.ListenerUuid: s.env.Lb}, true)

	wait := 6
	time.Sleep(time.Duration(wait) * time.Second)

	ipvs, _ := plugin.NewIpvsConfFromSave()
	s.Require().Len(ipvs.Services, 1)
	for _, fs := range ipvs.Services {
		s.Len(fs.BackendServers, 2, "should have 2 backend servers after deletion")
	}

	plugin.UpdateIpvsCounters()
	fs := plugin.GetIpvsFrontService(s.env.Lb.ListenerUuid)
	for _, bs := range fs.BackendServers {
		s.Equal(1, bs.Counter.Status, "remaining backend servers should be up")
	}

	cancel1()
	cancel2()
	time.Sleep(2 * time.Second)
}

// TestAddFrontService 测试添加前端服务
func (s *IpvsTestSuite) TestAddFrontService() {
	ctx1, cancel1 := context.WithCancel(context.Background())
	ctx2, cancel2 := context.WithCancel(context.Background())
	ctx3, cancel3 := context.WithCancel(context.Background())
	go utils.StartUdpServer(s.env.BS1.Ip, s.env.Lb.InstancePort, ctx1)
	go utils.StartUdpServer(s.env.BS2.Ip, s.env.Lb.InstancePort, ctx2)
	go utils.StartUdpServer(s.env.BS3.Ip, s.env.Lb1.InstancePort, ctx3)

	plugin.RefreshIpvsService(map[string]plugin.LbInfo{
		s.env.Lb.ListenerUuid:  s.env.Lb,
		s.env.Lb1.ListenerUuid: s.env.Lb1,
	}, false)

	wait := 6
	time.Sleep(time.Duration(wait) * time.Second)

	ipvs, _ := plugin.NewIpvsConfFromSave()
	s.Len(ipvs.Services, 2, "should have 2 front services")

	// 检查健康状态
	plugin.UpdateIpvsCounters()
	fs := plugin.GetIpvsFrontService(s.env.Lb.ListenerUuid)
	for _, bs := range fs.BackendServers {
		s.Equal(1, bs.Counter.Status)
	}

	fs = plugin.GetIpvsFrontService(s.env.Lb1.ListenerUuid)
	for _, bs := range fs.BackendServers {
		s.Equal(1, bs.Counter.Status)
	}

	cancel1()
	cancel2()
	cancel3()
	time.Sleep(2 * time.Second)
}

// TestRefreshWithEmptyNicIps 测试空 NicIps 刷新
func (s *IpvsTestSuite) TestRefreshWithEmptyNicIps() {
	ctx3, cancel3 := context.WithCancel(context.Background())
	go utils.StartUdpServer(s.env.BS3.Ip, s.env.Lb1.InstancePort, ctx3)

	// 设置 lb 的 NicIps 为空
	s.env.Lb.NicIps = []string{}
	plugin.RefreshIpvsService(map[string]plugin.LbInfo{
		s.env.Lb.ListenerUuid:  s.env.Lb,
		s.env.Lb1.ListenerUuid: s.env.Lb1,
	}, false)

	wait := 6
	time.Sleep(time.Duration(wait) * time.Second)

	ipvs, _ := plugin.NewIpvsConfFromSave()
	s.Nil(plugin.GetIpvsFrontService(s.env.Lb.ListenerUuid), "lb should be deleted")
	s.Len(ipvs.Services, 1, "should only have 1 service")

	plugin.UpdateIpvsCounters()
	s.Nil(plugin.GetIpvsFrontService(s.env.Lb.ListenerUuid), "lb should be deleted")

	fs := plugin.GetIpvsFrontService(s.env.Lb1.ListenerUuid)
	for _, bs := range fs.BackendServers {
		s.Equal(1, bs.Counter.Status)
	}

	s.env.Lb.NicIps = []string{s.env.BS1.Ip, s.env.BS2.Ip}
	cancel3()
	time.Sleep(2 * time.Second)
}

// TestDelLb 测试删除负载均衡
func (s *IpvsTestSuite) TestDelLb() {
	bs := plugin.BackendServerInfo{
		Ip:     "192.168.3.10",
		Weight: 100,
	}
	sg := plugin.ServerGroupInfo{
		Name:            "default-server-group",
		ServerGroupUuid: "8e52bcc526074521894162aa8db73c24",
		BackendServers:  []plugin.BackendServerInfo{bs},
		IsDefault:       false,
	}
	s.env.Lb.ServerGroups = []plugin.ServerGroupInfo{sg}
	s.env.Lb.RedirectRules = nil

	plugin.DelIpvsService(map[string]plugin.LbInfo{
		s.env.Lb.ListenerUuid:  s.env.Lb,
		s.env.Lb1.ListenerUuid: s.env.Lb1,
	})

	wait := 6
	time.Sleep(time.Duration(wait) * time.Second)

	ipvs, _ := plugin.NewIpvsConfFromSave()
	s.Len(ipvs.Services, 0, "all ipvs services should be deleted")

	plugin.UpdateIpvsCounters()
	fs := plugin.GetIpvsFrontService(s.env.Lb.ListenerUuid)
	s.Nil(fs, "front service should be deleted")
}

// TestIpvsSuite 运行 IPVS 测试套件
func TestIpvsSuite(t *testing.T) {
	suite.Run(t, new(IpvsTestSuite))
}
