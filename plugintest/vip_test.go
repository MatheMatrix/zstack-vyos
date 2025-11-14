package plugintest

import (
	"fmt"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/suite"
	"zstack-vyos/plugin"
	"zstack-vyos/server"
	"zstack-vyos/utils"
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

	vips := []plugin.VipInfo{s.env.Vip1, s.env.Vip2}
	nicIps := []plugin.NicIpInfo{s.env.PubNicIp}

	cmd := &plugin.SetVipCmd{
		SyncVip: false,
		Vips:    vips,
		NicIps:  nicIps,
	}

	log.Debugf("TestSetVipForNoHA: setting VIP %+v", cmd)
	plugin.SetVip(cmd)
	s.checkVipConfig(vips, s.env.PubNic, utils.NOHA)

	// 再次设置，验证幂等性
	plugin.SetVip(cmd)
	s.checkVipConfig(vips, s.env.PubNic, utils.NOHA)

	// 删除 VIP
	removeCmd := &plugin.RemoveVipCmd{Vips: vips}
	plugin.RemoveVip(removeCmd)
	s.checkVipDelete(vips, s.env.PubNic)

	// 再次删除，验证幂等性
	plugin.RemoveVip(removeCmd)
	s.checkVipDelete(vips, s.env.PubNic)
}

// TestSetVipForBackup 测试在 HA Backup 模式下设置 VIP
func (s *VipTestSuite) TestSetVipForBackup() {
	oldHaStatus := utils.GetHaStatus()
	utils.SetHaStatus(utils.HABACKUP)
	defer utils.SetHaStatus(oldHaStatus)

	vips := []plugin.VipInfo{s.env.Vip1, s.env.Vip2}
	nicIps := []plugin.NicIpInfo{s.env.PubNicIp}

	cmd := &plugin.SetVipCmd{
		SyncVip: false,
		Vips:    vips,
		NicIps:  nicIps,
	}

	log.Debugf("TestSetVipForBackup: setting VIP %+v", cmd)
	plugin.SetVip(cmd)
	s.checkVipConfig(vips, s.env.PubNic, utils.HABACKUP)

	// 再次设置，验证幂等性
	plugin.SetVip(cmd)
	s.checkVipConfig(vips, s.env.PubNic, utils.HABACKUP)

	// 删除 VIP
	removeCmd := &plugin.RemoveVipCmd{Vips: vips}
	plugin.RemoveVip(removeCmd)
	s.checkVipDelete(vips, s.env.PubNic)

	// 再次删除，验证幂等性
	plugin.RemoveVip(removeCmd)
	s.checkVipDelete(vips, s.env.PubNic)
}

// TestSetVipWithSync 测试同步模式设置 VIP
func (s *VipTestSuite) TestSetVipWithSync() {
	oldHaStatus := utils.GetHaStatus()
	utils.SetHaStatus(utils.HABACKUP)
	defer utils.SetHaStatus(oldHaStatus)

	vips := []plugin.VipInfo{s.env.Vip1, s.env.Vip2}
	nicIps := []plugin.NicIpInfo{s.env.PubNicIp}

	cmd := &plugin.SetVipCmd{
		SyncVip: true,
		Vips:    vips,
		NicIps:  nicIps,
	}

	log.Debugf("TestSetVipWithSync: setting VIP with sync %+v", cmd)
	plugin.SetVip(cmd)
	s.checkVipConfig(vips, s.env.PubNic, utils.HABACKUP)

	// 删除网卡 IP 地址，测试同步功能
	cidr, err := utils.NetmaskToCIDR(s.env.PubNic.Netmask)
	s.NoError(err)
	addr := fmt.Sprintf("%v/%v", s.env.PubNic.Ip, cidr)
	bash := utils.Bash{
		Command: fmt.Sprintf("ip address del %s dev %s", addr, s.env.PubNic.Name),
	}
	bash.Run()

	// 再次设置 VIP，应该恢复网卡 IP
	plugin.SetVip(cmd)
	s.checkVipConfig(vips, s.env.PubNic, utils.HABACKUP)

	// 删除 VIP
	removeCmd := &plugin.RemoveVipCmd{Vips: vips}
	plugin.RemoveVip(removeCmd)
	s.checkVipDelete(vips, s.env.PubNic)
}

// TestSetVipMultipleNics 测试多网卡 VIP 配置
func (s *VipTestSuite) TestSetVipMultipleNics() {
	oldHaStatus := utils.GetHaStatus()
	utils.SetHaStatus(utils.NOHA)
	defer utils.SetHaStatus(oldHaStatus)

	// 在公网网卡上设置 VIP
	vipsPub := []plugin.VipInfo{s.env.Vip1, s.env.Vip2}
	nicIpsPub := []plugin.NicIpInfo{s.env.PubNicIp}

	cmdPub := &plugin.SetVipCmd{
		SyncVip: false,
		Vips:    vipsPub,
		NicIps:  nicIpsPub,
	}

	plugin.SetVip(cmdPub)
	s.checkVipConfig(vipsPub, s.env.PubNic, utils.NOHA)

	// 在私网网卡上设置 VIP
	vipsPri := []plugin.VipInfo{s.env.Vip3}
	nicIpsPri := []plugin.NicIpInfo{s.env.PriNicIp}

	cmdPri := &plugin.SetVipCmd{
		SyncVip: false,
		Vips:    vipsPri,
		NicIps:  nicIpsPri,
	}

	plugin.SetVip(cmdPri)
	s.checkVipConfig(vipsPri, s.env.PriNic, utils.NOHA)

	// 删除所有 VIP
	removeCmd1 := &plugin.RemoveVipCmd{Vips: vipsPub}
	plugin.RemoveVip(removeCmd1)
	s.checkVipDelete(vipsPub, s.env.PubNic)

	removeCmd2 := &plugin.RemoveVipCmd{Vips: vipsPri}
	plugin.RemoveVip(removeCmd2)
	s.checkVipDelete(vipsPri, s.env.PriNic)
}

// TestVipSuite 运行 VIP 测试套件
func TestVipSuite(t *testing.T) {
	suite.Run(t, new(VipTestSuite))
}

// checkVipConfig 检查 VIP 是否正确配置
func (s *VipTestSuite) checkVipConfig(vips []plugin.VipInfo, nic utils.NicInfo, haStatus string) {
	tree := server.NewParserFromShowConfiguration().Tree

	// 获取 Linux 上的 IP 地址
	ipsInLinux := s.getLinuxNicVips(nic.Name)

	// 检查网卡 IP 必须是第一个
	s.Contains(ipsInLinux[0], nic.Ip, "check ip[%s] in linux failed on interface %s, result %s", nic.Ip, nic.Name, ipsInLinux)

	// 构建 IP 映射
	ipMaps := make(map[string]string)
	for _, ip := range ipsInLinux {
		iip := strings.Split(ip, "/")[0]
		ipMaps[iip] = iip
	}

	// 检查每个 VIP
	for _, vip := range vips {
		cidr, err := utils.NetmaskToCIDR(vip.Netmask)
		s.NoError(err)
		addr := fmt.Sprintf("%v/%v", vip.Ip, cidr)

		// 检查 VyOS 配置
		n := tree.Getf("interfaces ethernet %s address %v", nic.Name, addr)
		if nic.Category == "Private" {
			// 私网网卡上的 VIP 应该在 VyOS 中
			s.NotNil(n, "check vip[%s] failed on interface %s", vip.Ip, nic.Name)
		}

		// 检查 Linux IP 配置（非 HA Backup 的管理网卡）
		if haStatus != utils.HABACKUP || nic.Category != "Management" {
			_, ok := ipMaps[vip.Ip]
			s.True(ok, "check ip[%s] in linux failed on interface %s, ipMaps %+v", vip.Ip, nic.Name, ipMaps)
		}
	}
}

// checkVipDelete 检查 VIP 是否正确删除
func (s *VipTestSuite) checkVipDelete(vips []plugin.VipInfo, nic utils.NicInfo) {
	tree := server.NewParserFromShowConfiguration().Tree

	// 获取 Linux 上的 IP 地址
	ipsInLinux := s.getLinuxNicVips(nic.Name)
	s.Contains(ipsInLinux[0], nic.Ip, "check ip[%s] in linux failed on interface %s", nic.Ip, nic.Name)

	// 构建 IP 映射
	ipMaps := make(map[string]string)
	for _, ip := range ipsInLinux {
		iip := strings.Split(ip, "/")[0]
		ipMaps[ip] = iip
	}

	// 检查每个 VIP 已被删除
	for _, vip := range vips {
		// 检查 VyOS 配置中已删除
		cidr, err := utils.NetmaskToCIDR(vip.Netmask)
		s.NoError(err)
		addr := fmt.Sprintf("%v/%v", vip.Ip, cidr)
		n := tree.Getf("interfaces ethernet %s address %v", nic.Name, addr)
		s.Nil(n, "check vip[%s] delete failed on interface %s", vip.Ip, nic.Name)

		// 检查 Linux IP 已删除
		_, ok := ipMaps[vip.Ip]
		s.False(ok, "check delete ip[%s] in linux failed on interface %s", vip.Ip, nic.Name)
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
