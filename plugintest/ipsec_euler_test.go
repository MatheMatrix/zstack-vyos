package plugintest

import (
	"testing"
	"zstack-vyos/plugin"

	"github.com/stretchr/testify/suite"
)

// IpsecEulerTestSuite IPsec 测试套件（针对 Euler 22.03）
type IpsecEulerTestSuite struct {
	suite.Suite
	env *VpcTestEnv
}

// SetupTest 每个测试前的准备工作
func (s *IpsecEulerTestSuite) SetupTest() {
	s.env = NewVpcTestEnv()
	s.env.Setup()
	s.env.SetupIPsec()
}

// TearDownTest 每个测试后的清理工作
func (s *IpsecEulerTestSuite) TearDownTest() {
	s.env.TeardownIPsec()
	s.env.Teardown()
}

// TestCreateIPsecConnection 测试创建 IPsec 连接
func (s *IpsecEulerTestSuite) TestCreateIPsecConnection() {
	s.env.AddPeerAddr("ut-pub", "192.168.2.102/24")
	cmd := plugin.CreateIPsecCmd{
		Infos:          []plugin.IpsecInfo{s.env.IpsecConfig},
		AutoRestartVpn: false,
	}
	plugin.CreateIPsecConnection(&cmd)

	// TODO: 添加验证逻辑，检查 IPsec 连接是否创建成功
}

// TestDeleteIPsecConnection 测试删除 IPsec 连接
func (s *IpsecEulerTestSuite) TestDeleteIPsecConnection() {
	// 先创建连接
	s.env.AddPeerAddr("ut-pub", "192.168.2.102/24")
	createCmd := plugin.CreateIPsecCmd{
		Infos:          []plugin.IpsecInfo{s.env.IpsecConfig},
		AutoRestartVpn: false,
	}
	plugin.CreateIPsecConnection(&createCmd)

	// 删除连接
	cmd := plugin.DeleteIPsecCmd{
		Infos: []plugin.IpsecInfo{s.env.IpsecConfig},
	}
	plugin.DeleteIPsecConnection(&cmd)

	// TODO: 添加验证逻辑，检查 IPsec 连接是否删除成功
}

// TestSyncIPsecConnection 测试同步 IPsec 连接
func (s *IpsecEulerTestSuite) TestSyncIPsecConnection() {
	s.env.AddPeerAddr("ut-pub", "192.168.2.102/24")
	cmd := plugin.SyncIPsecCmd{
		Infos:          []plugin.IpsecInfo{s.env.IpsecConfig},
		AutoRestartVpn: false,
	}
	plugin.SyncIPsecConnection(&cmd)

	// TODO: 添加验证逻辑，检查 IPsec 连接是否同步成功
}

// TestDeleteAfterSync 测试同步后删除 IPsec 连接
func (s *IpsecEulerTestSuite) TestDeleteAfterSync() {
	// 先同步
	s.env.AddPeerAddr("ut-pub", "192.168.2.102/24")
	syncCmd := plugin.SyncIPsecCmd{
		Infos:          []plugin.IpsecInfo{s.env.IpsecConfig},
		AutoRestartVpn: false,
	}
	plugin.SyncIPsecConnection(&syncCmd)

	// 再删除
	deleteCmd := plugin.DeleteIPsecCmd{
		Infos: []plugin.IpsecInfo{s.env.IpsecConfig},
	}
	plugin.DeleteIPsecConnection(&deleteCmd)

	// TODO: 添加验证逻辑
}

// TestIpsecEulerSuite 运行 IPsec 测试套件
func TestIpsecEulerSuite(t *testing.T) {
	suite.Run(t, new(IpsecEulerTestSuite))
}
