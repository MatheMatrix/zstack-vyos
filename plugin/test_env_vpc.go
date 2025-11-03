package plugin

import (
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"zstack-vyos/utils"
)

// VpcTestEnv VPC 测试环境
type VpcTestEnv struct {
	TestEnvBase

	// IPsec 配置
	IpsecConfig IpsecInfo

	// SNAT 配置
	Snat1        SnatInfo
	Snat2        SnatInfo
	Snat3        SnatInfo
	Snat4        SnatInfo
	SetSnatState SetSnatStateCmd

	// VIP 配置
	Vip1     vipInfo
	Vip2     vipInfo
	Vip3     vipInfo
	Vip4     vipInfo // IPv6 VIP 1
	Vip5     vipInfo // IPv6 VIP 2
	Vip6     vipInfo // IPv4+IPv6 双栈 VIP
	PubNicIp nicIpInfo
	PriNicIp nicIpInfo
}

// NewVpcTestEnv 创建 VPC 测试环境
func NewVpcTestEnv() *VpcTestEnv {
	return &VpcTestEnv{
		TestEnvBase: TestEnvBase{
			ConfigTcForVipQos: false,
			EnableVyosCmd:     false,
			SkipVyosIptables:  true,
		},
	}
}

// Setup 设置测试环境
func (env *VpcTestEnv) Setup() error {
	utils.InitLog(utils.GetVyosUtLogDir()+"vpc.log", true)
	utils.InitVyosVersion()

	env.envLock.Lock()
	defer env.envLock.Unlock()

	var err error

	// 创建管理网卡
	env.MgtNic, err = env.createVethNic(
		"ut-mgt",
		"192.168.1.100",
		"255.255.255.0",
		"192.168.1.1",
		"Public",
		1400,
	)
	if err != nil {
		return err
	}

	// 创建公网网卡
	env.PubNic, err = env.createVethNic(
		"ut-pub",
		"10.1.1.100",
		"255.255.255.0",
		"10.1.1.1",
		"Public",
		1400,
	)
	if err != nil {
		return err
	}

	// 创建私网网卡
	env.PriNic, err = env.createVethNic(
		"ut-pri",
		"10.2.1.1",
		"255.255.255.0",
		"10.2.1.1",
		"Private",
		1400,
	)
	if err != nil {
		return err
	}

	// 创建附加公网网卡 1
	env.AdditionalPubNic1, err = env.createVethNic(
		"ut-pub1",
		"10.1.2.100",
		"255.255.255.0",
		"10.1.2.1",
		"Public",
		1400,
	)
	if err != nil {
		return err
	}

	// 创建附加公网网卡 2
	env.AdditionalPubNic2, err = env.createVethNic(
		"ut-pub2",
		"10.1.3.100",
		"255.255.255.0",
		"10.1.3.1",
		"Public",
		1400,
	)
	if err != nil {
		return err
	}

	// 创建附加私网网卡 1
	env.PriNic1, err = env.createVethNic(
		"ut-pri1",
		"10.2.2.1",
		"255.255.255.0",
		"10.2.2.1",
		"Private",
		1400,
	)
	if err != nil {
		return err
	}

	// 设置 PrivateNicsForUT
	utils.PrivateNicsForUT = []utils.NicInfo{env.PriNic}

	// 设置 Bootstrap 信息
	env.setupBootstrapInfo(utils.APPLIANCETYPE_VPC, utils.NOHA)

	// 配置网卡
	if err := env.configureNic(env.MgtNic); err != nil {
		return fmt.Errorf("create management nic failed")
	}
	if err := env.configureNic(env.PubNic); err != nil {
		return fmt.Errorf("create public nic failed")
	}
	if err := env.configureNic(env.PriNic); err != nil {
		return fmt.Errorf("create private nic failed")
	}
	if err := env.configureNic(env.AdditionalPubNic1); err != nil {
		return fmt.Errorf("create public nic1 failed")
	}
	if err := env.configureNic(env.AdditionalPubNic2); err != nil {
		return fmt.Errorf("create public nic2 failed")
	}
	if err := env.configureNic(env.PriNic1); err != nil {
		return fmt.Errorf("create private nic1 failed")
	}

	env.envCreated = true
	log.Debugf("VPC test environment setup completed")
	return nil
}

// Teardown 清理测试环境
func (env *VpcTestEnv) Teardown() error {
	env.envLock.Lock()
	defer env.envLock.Unlock()

	// 移除网卡配置
	env.removeNic(env.MgtNic)
	env.removeNic(env.PubNic)
	env.removeNic(env.PriNic)

	utils.DestroySlbHaBootStrap()

	// 删除 veth 接口
	env.destroyVethNic("ut-mgt")
	env.destroyVethNic("ut-pub")
	env.destroyVethNic("ut-pri")
	env.destroyVethNic("ut-pub1")
	env.destroyVethNic("ut-pub2")
	env.destroyVethNic("ut-pri1")

	env.envCreated = false
	log.Debugf("VPC test environment teardown completed")
	return nil
}

// SetupIPsec 设置 IPsec 配置
func (env *VpcTestEnv) SetupIPsec() error {
	if utils.IsEuler2203() {
		b := &utils.Bash{
			Command: "systemctl restart strongswan",
			Sudo:    true,
		}
		if err := b.Run(); err != nil {
			return err
		}
	}

	IPsecEntryPoint()
	if err := IpsecInit(); err != nil {
		return err
	}

	env.IpsecConfig = IpsecInfo{
		Uuid:                      "a6c89c57c0684cb4926b346b68eaee3a",
		PublicNic:                 env.PriNic.Mac,
		Vip:                       "192.168.2.101",
		LocalCidrs:                []string{"192.167.100.0/24"},
		PeerAddress:               "192.168.2.102",
		PeerCidrs:                 []string{"192.168.1.0/24"},
		IdType:                    "ip",
		AuthMode:                  "psk",
		AuthKey:                   "123456",
		IkeVersion:                "ikev2",
		IkeLifeTime:               86400,
		LifeTime:                  3600,
		IkeAuthAlgorithm:          "sha256",
		IkeEncryptionAlgorithm:    "aes256",
		IkeDhGroup:                2,
		PolicyAuthAlgorithm:       "sha256",
		PolicyEncryptionAlgorithm: "aes256",
		Pfs:                       "dh-group14",
		PolicyMode:                "tunnel",
		TransformProtocol:         "esp",
		ExcludeSnat:               true,
	}

	log.Debugf("IPsec configuration setup completed")
	return nil
}

// TeardownIPsec 清理 IPsec 配置
func (env *VpcTestEnv) TeardownIPsec() error {
	if utils.IsEuler2203() {
		b := &utils.Bash{
			Command: "systemctl stop strongswan",
			Sudo:    true,
		}
		if err := b.Run(); err != nil {
			return err
		}

		os.ReadDir(SwanConnectionConfPath)
	}

	log.Debugf("IPsec configuration teardown completed")
	return nil
}

// SetupSNAT 设置 SNAT 配置
func (env *VpcTestEnv) SetupSNAT() {
	env.SetSnatState.Enable = true

	env.Snat1 = SnatInfo{
		PublicNicMac:     env.PubNic.Mac,
		PublicIp:         env.PubNic.Ip,
		PrivateNicMac:    env.PriNic.Mac,
		PrivateNicIp:     env.PriNic.Ip,
		PrivateGatewayIp: env.PriNic.Gateway,
		SnatNetmask:      env.PriNic.Netmask,
		State:            true,
	}

	env.Snat2 = SnatInfo{
		PublicNicMac:     env.PubNic.Mac,
		PublicIp:         env.PubNic.Ip,
		PrivateNicMac:    env.PriNic1.Mac,
		PrivateNicIp:     env.PriNic1.Ip,
		PrivateGatewayIp: env.PriNic1.Gateway,
		SnatNetmask:      env.PriNic1.Netmask,
		State:            true,
	}

	env.Snat3 = SnatInfo{
		PublicNicMac:     env.AdditionalPubNic1.Mac,
		PublicIp:         env.AdditionalPubNic1.Ip,
		PrivateNicMac:    env.PriNic.Mac,
		PrivateNicIp:     env.PriNic.Ip,
		PrivateGatewayIp: env.PriNic.Gateway,
		SnatNetmask:      env.PriNic.Netmask,
		State:            true,
	}

	env.Snat4 = SnatInfo{
		PublicNicMac:     env.AdditionalPubNic1.Mac,
		PublicIp:         env.AdditionalPubNic1.Ip,
		PrivateNicMac:    env.PriNic1.Mac,
		PrivateNicIp:     env.PriNic1.Ip,
		PrivateGatewayIp: env.PriNic1.Gateway,
		SnatNetmask:      env.PriNic1.Netmask,
		State:            true,
	}

	log.Debugf("SNAT configuration setup completed")
}

// SetupVIP 设置 VIP 配置
func (env *VpcTestEnv) SetupVIP() {
	// 配置公网网卡 IP 信息
	env.PubNicIp = nicIpInfo{
		Ip:               env.PubNic.Ip,
		Netmask:          env.PubNic.Netmask,
		OwnerEthernetMac: env.PubNic.Mac,
	}

	// 配置私网网卡 IP 信息
	env.PriNicIp = nicIpInfo{
		Ip:               env.PriNic.Ip,
		Netmask:          env.PriNic.Netmask,
		OwnerEthernetMac: env.PriNic.Mac,
	}

	// 配置公网 VIP 1 (IPv4)
	env.Vip1 = vipInfo{
		Ip:               "10.1.1.200",
		Netmask:          env.PubNic.Netmask,
		Gateway:          env.PubNic.Gateway,
		OwnerEthernetMac: env.PubNic.Mac,
		VipUuid:          "vip-uuid-test-001",
	}

	// 配置公网 VIP 2 (IPv4)
	env.Vip2 = vipInfo{
		Ip:               "10.1.1.201",
		Netmask:          env.PubNic.Netmask,
		Gateway:          env.PubNic.Gateway,
		OwnerEthernetMac: env.PubNic.Mac,
		VipUuid:          "vip-uuid-test-002",
	}

	// 配置私网 VIP (IPv4)
	env.Vip3 = vipInfo{
		Ip:               "10.2.1.200",
		Netmask:          env.PriNic.Netmask,
		Gateway:          env.PriNic.Gateway,
		OwnerEthernetMac: env.PriNic.Mac,
		VipUuid:          "vip-uuid-test-003",
	}

	// 配置公网 IPv6 VIP 1
	env.Vip4 = vipInfo{
		Ip6:              "fd00:1::200",
		PrefixLength:     64,
		Gateway6:         "fd00:1::1",
		OwnerEthernetMac: env.PubNic.Mac,
		VipUuid:          "vip-uuid-test-004",
		AddressMode:      "Stateful-DHCP",
	}

	// 配置公网 IPv6 VIP 2
	env.Vip5 = vipInfo{
		Ip6:              "fd00:1::201",
		PrefixLength:     64,
		Gateway6:         "fd00:1::1",
		OwnerEthernetMac: env.PubNic.Mac,
		VipUuid:          "vip-uuid-test-005",
		AddressMode:      "Stateful-DHCP",
	}

	// 配置公网双栈 VIP (IPv4 + IPv6)
	env.Vip6 = vipInfo{
		Ip:               "10.1.1.202",
		Netmask:          env.PubNic.Netmask,
		Gateway:          env.PubNic.Gateway,
		Ip6:              "fd00:1::202",
		PrefixLength:     64,
		Gateway6:         "fd00:1::1",
		OwnerEthernetMac: env.PubNic.Mac,
		VipUuid:          "vip-uuid-test-006",
		AddressMode:      "Stateful-DHCP",
	}

	log.Debugf("VIP configuration setup completed")
}
