package plugintest

import (
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"zstack-vyos/plugin"
	"zstack-vyos/utils"
)

// SlbHaTestEnv SLB HA 测试环境
type SlbHaTestEnv struct {
	TestEnvBase

	// Load Balancer 配置
	Lb  plugin.LbInfo
	Lb1 plugin.LbInfo

	// Server Group 配置
	SG  plugin.ServerGroupInfo
	SG1 plugin.ServerGroupInfo

	// Backend Server 配置
	BS1 plugin.BackendServerInfo
	BS2 plugin.BackendServerInfo
	BS3 plugin.BackendServerInfo
	BS4 plugin.BackendServerInfo
}

// NewSlbHaTestEnv 创建 SLB HA 测试环境
func NewSlbHaTestEnv() *SlbHaTestEnv {
	return &SlbHaTestEnv{
		TestEnvBase: TestEnvBase{
			ConfigTcForVipQos: false,
			EnableVyosCmd:     false,
			SkipVyosIptables:  true,
		},
	}
}

// Setup 设置测试环境
func (env *SlbHaTestEnv) Setup() error {
	utils.InitLog(utils.GetVyosUtLogDir()+"slbha.log", true)
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
		"192.168.2.100",
		"255.255.255.0",
		"192.168.2.1",
		"Public",
		1400,
	)
	if err != nil {
		return err
	}

	// 创建私网网卡
	env.PriNic, err = env.createVethNic(
		"ut-pri",
		"192.168.3.1",
		"255.255.255.0",
		"192.168.3.1",
		"Private",
		1400,
	)
	if err != nil {
		return err
	}

	// 设置 PrivateNicsForUT
	utils.PrivateNicsForUT = []utils.NicInfo{env.PriNic}

	// 设置 Bootstrap 信息（SLB 类型，Backup 状态）
	env.setupBootstrapInfo(utils.APPLIANCETYPE_SLB, utils.HABACKUP)

	// 配置网卡
	if err := env.configureNic(env.MgtNic); err != nil {
		return fmt.Errorf("configure management nic failed")
	}
	if err := env.configureNic(env.PubNic); err != nil {
		return fmt.Errorf("configure public nic failed")
	}
	if err := env.configureNic(env.PriNic); err != nil {
		return fmt.Errorf("configure private nic failed")
	}

	env.envCreated = true
	log.Debugf("SLB HA test environment setup completed")
	return nil
}

// Teardown 清理测试环境
func (env *SlbHaTestEnv) Teardown() error {
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

	env.envCreated = false
	log.Debugf("SLB HA test environment teardown completed")
	return nil
}

// SetupVyosHA 设置 VyOS HA 配置
func (env *SlbHaTestEnv) SetupVyosHA() interface{} {
	vip4 := plugin.MacVipPair{
		NicMac:  env.PubNic.Mac,
		NicVip:  "169.254.2.102",
		Netmask: "255.255.255.0",
	}

	vip6 := plugin.MacVipPair{
		NicMac:    env.PubNic.Mac,
		NicVip:    "234e:0:4568::75:cf18",
		PrefixLen: 64,
	}

	vyosHaCmd := &plugin.SetVyosHaCmd{
		Keepalive:    5,
		HeartbeatNic: env.PubNic.Mac,
		LocalIp:      "169.254.2.100",
		PeerIp:       "169.254.2.101",
		LocalIpV6:    "234e:0:4568::19:9e8a",
		PeerIpV6:     "234e:0:4568::52:90dc",
		Monitors:     []string{},
		Vips:         []plugin.MacVipPair{vip4, vip6},
	}

	return plugin.SetVyosHa(vyosHaCmd)
}

// SetupLoadBalancer 设置负载均衡配置
func (env *SlbHaTestEnv) SetupLoadBalancer() error {
	plugin.InitLb()
	os.Remove(plugin.IPVS_HEALTH_CHECK_CONFIG_FILE)
	plugin.InitIpvs()

	// 配置第一个 LB
	env.Lb.LbUuid = "f2c7b2ff2f834e1ea20363f49122a3b4"
	env.Lb.ListenerUuid = "23fb656e4f324e74a4889582104fcbf0"
	env.Lb.InstancePort = 8080
	env.Lb.LoadBalancerPort = 80
	env.Lb.Vip = "192.168.2.100"
	env.Lb.NicIps = []string{"192.168.3.10"}
	env.Lb.Mode = "udp"
	env.Lb.PublicNic = env.GetNicMac("pub")
	env.Lb.Parameters = []string{
		"balancerWeight::192.168.3.10::100",
		"connectionIdleTimeout::60",
		"Nbprocess::1",
		"balancerAlgorithm::roundrobin",
		"healthCheckTimeout::2",
		"healthCheckTarget::udp:default",
		"maxConnection::2000000",
		"httpMode::http-server-close",
		"accessControlStatus::enable",
		"healthyThreshold::2",
		"healthCheckInterval::1",
		"unhealthyThreshold::2",
	}

	// 配置 Backend Servers
	env.BS1 = plugin.BackendServerInfo{
		Ip:     "192.168.3.10",
		Weight: 100,
	}

	env.BS2 = plugin.BackendServerInfo{
		Ip:     "192.168.3.11",
		Weight: 100,
	}

	// 配置 Server Group
	env.SG = plugin.ServerGroupInfo{
		Name:            "default-server-group",
		ServerGroupUuid: "8e52bcc526074521894162aa8db73c24",
		BackendServers:  []plugin.BackendServerInfo{env.BS1, env.BS2},
		IsDefault:       false,
	}

	env.Lb.ServerGroups = []plugin.ServerGroupInfo{env.SG}
	env.Lb.RedirectRules = nil

	// 配置第二个 LB
	env.Lb1 = env.Lb
	env.Lb1.ListenerUuid = "23fb656e4f324e74a4889582104fcbf1"
	env.Lb1.LoadBalancerPort = 81

	env.BS3 = plugin.BackendServerInfo{
		Ip:     "192.168.3.12",
		Weight: 100,
	}

	env.SG1 = plugin.ServerGroupInfo{
		Name:            "server-group-1",
		ServerGroupUuid: "8e52bcc526074521894162aa8db73c25",
		BackendServers:  []plugin.BackendServerInfo{env.BS3},
		IsDefault:       false,
	}

	env.Lb1.ServerGroups = []plugin.ServerGroupInfo{env.SG1}
	env.Lb1.RedirectRules = nil

	log.Debugf("Load balancer configuration setup completed")
	return nil
}

// TeardownLoadBalancer 清理负载均衡配置
func (env *SlbHaTestEnv) TeardownLoadBalancer() {
	plugin.StopIpvsHealthCheck()
	log.Debugf("Load balancer configuration teardown completed")
}
