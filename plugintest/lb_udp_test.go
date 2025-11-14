package plugintest

import (
	"testing"
	"zstack-vyos/plugin"

	"github.com/stretchr/testify/suite"
)

// LbUdpTestSuite UDP 负载均衡测试套件
type LbUdpTestSuite struct {
	suite.Suite
	env *SlbHaIp4Env
}

// SetupTest 每个测试前的准备工作
func (s *LbUdpTestSuite) SetupTest() {
	s.env = NewSlbHaIp4Env()
	s.env.SetupStrap()
	s.env.SetupLb()
	s.env.SetupVyosHa()
}

// TearDownTest 每个测试后的清理工作
func (s *LbUdpTestSuite) TearDownTest() {
	s.env.DestroyBootStrap()
	s.env.DestroyLb()
}

// TestRefreshUdpLb 测试刷新 UDP 负载均衡
func (s *LbUdpTestSuite) TestRefreshUdpLb() {
	cmd := plugin.RefreshLbCmd{
		Lbs:              []plugin.LbInfo{s.env.lb},
		EnableHaproxyLog: true,
	}
	plugin.RefreshLbInternal(&cmd)

	// TODO: 添加验证逻辑，检查 UDP LB 是否配置成功
	// 可以检查：
	// 1. haproxy 配置文件是否正确
	// 2. haproxy 进程是否运行
	// 3. VIP 是否配置成功
}

// TestLbUdpSuite 运行 UDP 负载均衡测试套件
func TestLbUdpSuite(t *testing.T) {
	suite.Run(t, new(LbUdpTestSuite))
}
