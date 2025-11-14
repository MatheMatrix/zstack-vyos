package plugintest

import (
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"
	"zstack-vyos/plugin"
	"zstack-vyos/utils"
)

// TestEnvBase 测试环境基类，提供通用功能
type TestEnvBase struct {
	envCreated bool
	envLock    sync.Mutex

	// 网卡配置
	MgtNic  utils.NicInfo
	PubNic  utils.NicInfo
	PriNic  utils.NicInfo
	PriNic1 utils.NicInfo

	AdditionalPubNic1 utils.NicInfo
	AdditionalPubNic2 utils.NicInfo

	// 配置选项
	ConfigTcForVipQos bool
	EnableVyosCmd     bool
	SkipVyosIptables  bool
}

// TestEnv 测试环境接口
type TestEnv interface {
	Setup() error
	Teardown() error
	IsReady() bool
	GetNicByName(name string) *utils.NicInfo
	AddPeerAddr(nicName, addr string) error
}

// IsReady 检查环境是否已创建
func (env *TestEnvBase) IsReady() bool {
	env.envLock.Lock()
	defer env.envLock.Unlock()
	return env.envCreated
}

// GetNicByName 根据名称获取网卡信息
func (env *TestEnvBase) GetNicByName(name string) *utils.NicInfo {
	switch name {
	case "mgt", "mgmt", "management":
		return &env.MgtNic
	case "pub", "public":
		return &env.PubNic
	case "pri", "private":
		return &env.PriNic
	case "pri1", "private1":
		return &env.PriNic1
	case "pub1", "public1":
		return &env.AdditionalPubNic1
	case "pub2", "public2":
		return &env.AdditionalPubNic2
	default:
		return nil
	}
}

// GetNicMac 获取网卡 MAC 地址
func (env *TestEnvBase) GetNicMac(nicName string) string {
	nic := env.GetNicByName(nicName)
	if nic != nil {
		return nic.Mac
	}
	log.Warnf("cannot find nic: %s", nicName)
	return ""
}

// AddPeerAddr 添加 peer 地址
func (env *TestEnvBase) AddPeerAddr(nicName, addr string) error {
	peerName := nicName + "-peer"
	if err := utils.IpAddrAdd(peerName, addr); err != nil {
		return fmt.Errorf("failed to add peer addr %s to %s: %w", addr, peerName, err)
	}
	log.Debugf("added peer addr: %s to %s", addr, peerName)
	return nil
}

// createVethNic 创建 veth 网卡并获取配置
func (env *TestEnvBase) createVethNic(name, ip, netmask, gateway, category string, mtu int) (utils.NicInfo, error) {
	if err := utils.IpLinkAdd(name, utils.IpLinkTypeVeth.String()); err != nil {
		return utils.NicInfo{}, fmt.Errorf("failed to create veth %s: %w", name, err)
	}

	mac, err := utils.IpLinkGetMAC(name)
	if err != nil {
		return utils.NicInfo{}, fmt.Errorf("failed to get MAC for %s: %w", name, err)
	}

	return utils.NicInfo{
		Name:                  name,
		Ip:                    ip,
		Netmask:               netmask,
		Gateway:               gateway,
		Mac:                   mac,
		Category:              category,
		L2Type:                "L2NoVlanNetwork",
		PhysicalInterface:     "ens3",
		Vni:                   0,
		FirewallDefaultAction: "drop",
		Mtu:                   mtu,
		IsDefault:             false,
	}, nil
}

// configureNic 配置网卡
func (env *TestEnvBase) configureNic(nic utils.NicInfo) error {
	nicCmd := &plugin.ConfigureNicCmd{
		Nics: []utils.NicInfo{nic},
	}
	return plugin.ConfigureNic(nicCmd)
}

// removeNic 移除网卡
func (env *TestEnvBase) removeNic(nic utils.NicInfo) error {
	nicCmd := &plugin.ConfigureNicCmd{
		Nics: []utils.NicInfo{nic},
	}
	return plugin.RemoveNic(nicCmd)
}

// setupBootstrapInfo 设置 Bootstrap 信息
func (env *TestEnvBase) setupBootstrapInfo(applianceType, haStatus string) {
	utils.BootstrapInfo["ConfigTcForVipQos"] = env.ConfigTcForVipQos
	utils.BootstrapInfo["EnableVyosCmd"] = env.EnableVyosCmd
	utils.BootstrapInfo["SkipVyosIptables"] = env.SkipVyosIptables
	utils.BootstrapInfo["abnormalFileMaxSize"] = 100
	utils.BootstrapInfo["applianceVmSubType"] = applianceType
	utils.BootstrapInfo["haStatus"] = haStatus
	utils.BootstrapInfo["managementNodeCidr"] = "172.25.0.0/16"
	utils.BootstrapInfo["managementNodeIp"] = "172.25.116.181"
	utils.BootstrapInfo["publicKey"] = ""
	utils.BootstrapInfo["sshPort"] = 22
	utils.BootstrapInfo["uuid"] = "test-uuid-" + applianceType
	utils.BootstrapInfo["vyosPassword"] = "vrouter12#"

	// 管理网卡
	utils.BootstrapInfo["managementNic"] = map[string]interface{}{
		"category":          env.MgtNic.Category,
		"deviceName":        env.MgtNic.Name,
		"gateway":           env.MgtNic.Gateway,
		"ip":                env.MgtNic.Ip,
		"isDefaultRoute":    false,
		"l2type":            env.MgtNic.L2Type,
		"mac":               env.MgtNic.Mac,
		"mtu":               env.MgtNic.Mtu,
		"netmask":           env.MgtNic.Netmask,
		"physicalInterface": env.MgtNic.PhysicalInterface,
		"vni":               env.MgtNic.Vni,
	}

	// 附加网卡
	var additionalNics []map[string]interface{}
	if env.PubNic.Name != "" {
		additionalNics = append(additionalNics, env.nicInfoToMap(env.PubNic, true))
	}
	if env.PriNic.Name != "" {
		additionalNics = append(additionalNics, env.nicInfoToMap(env.PriNic, false))
	}
	utils.BootstrapInfo["additionalNics"] = additionalNics
}

// nicInfoToMap 将 NicInfo 转换为 map
func (env *TestEnvBase) nicInfoToMap(nic utils.NicInfo, isDefault bool) map[string]interface{} {
	return map[string]interface{}{
		"addressMode":       "Stateful-DHCP",
		"category":          nic.Category,
		"deviceName":        nic.Name,
		"gateway":           nic.Gateway,
		"gateway6":          nic.Gateway6,
		"ip":                nic.Ip,
		"ip6":               nic.Ip6,
		"isDefaultRoute":    isDefault,
		"l2type":            nic.L2Type,
		"mac":               nic.Mac,
		"mtu":               nic.Mtu,
		"netmask":           nic.Netmask,
		"physicalInterface": nic.PhysicalInterface,
		"prefixLength":      nic.PrefixLength,
		"vni":               nic.Vni,
	}
}

// destroyVethNic 销毁 veth 网卡
func (env *TestEnvBase) destroyVethNic(name string) {
	if err := utils.IpLinkDel(name); err != nil {
		log.Warnf("failed to delete veth %s: %v", name, err)
	}
}
