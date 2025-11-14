package plugintest

import (
	"testing"
	"zstack-vyos/plugin"

	"github.com/stretchr/testify/suite"
)

// SnatTestSuite SNAT功能测试套件
type SnatTestSuite struct {
	suite.Suite
	env *VpcTestEnv
}

// SetupTest 每个测试前的准备工作
func (s *SnatTestSuite) SetupTest() {
	s.env = NewVpcTestEnv()
	s.env.Setup()
	s.env.SetupSNAT()
}

// TearDownTest 每个测试后的清理工作
func (s *SnatTestSuite) TearDownTest() {
	s.env.Teardown()
}

// TestSetSnat 测试设置 SNAT 规则
func (s *SnatTestSuite) TestSetSnat() {
	cmd := plugin.SetSnatCmd{
		Snat: s.env.Snat1,
	}
	plugin.SetSnat(&cmd)

	// TODO: check result

	cmd = plugin.SetSnatCmd{
		Snat: s.env.Snat2,
	}
	plugin.SetSnat(&cmd)

	// TODO: check result
}

// TestRemoveSnat 测试移除 SNAT 规则
func (s *SnatTestSuite) TestRemoveSnat() {
	// 先设置 SNAT
	cmd := plugin.SetSnatCmd{Snat: s.env.Snat1}
	plugin.SetSnat(&cmd)
	cmd = plugin.SetSnatCmd{Snat: s.env.Snat2}
	plugin.SetSnat(&cmd)

	// 移除 SNAT
	removeCmd := plugin.RemoveSnatCmd{
		NatInfo: []plugin.SnatInfo{s.env.Snat1, s.env.Snat2},
	}
	plugin.RemoveSnat(&removeCmd)
	// TODO: check result
}

// TestSyncSnat 测试同步 SNAT 规则
func (s *SnatTestSuite) TestSyncSnat() {
	cmd := plugin.SyncSnatCmd{
		Snats:  []plugin.SnatInfo{s.env.Snat1, s.env.Snat2, s.env.Snat3, s.env.Snat4},
		Enable: true,
	}
	plugin.SyncSnat(&cmd)
	// TODO: check result

	cmd = plugin.SyncSnatCmd{
		Snats:  []plugin.SnatInfo{s.env.Snat1, s.env.Snat2},
		Enable: true,
	}
	plugin.SyncSnat(&cmd)
	// TODO: check result
}

// TestSetSnatState 测试设置 SNAT 状态
func (s *SnatTestSuite) TestSetSnatState() {
	cmd := plugin.SetSnatStateCmd{
		Snats:  []plugin.SnatInfo{s.env.Snat1, s.env.Snat2, s.env.Snat3, s.env.Snat4},
		Enable: true,
	}
	plugin.SetSnatState(&cmd)
	// TODO: check result

	cmd = plugin.SetSnatStateCmd{
		Snats:  []plugin.SnatInfo{s.env.Snat1, s.env.Snat2},
		Enable: false,
	}
	plugin.SetSnatState(&cmd)
	// TODO: check result
}

// TestSnatSuite 运行 SNAT 测试套件
func TestSnatSuite(t *testing.T) {
	suite.Run(t, new(SnatTestSuite))
}
