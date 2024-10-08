package plugin_test

import (
	. "github.com/onsi/ginkgo/v2"
)

var _ = Describe("slb ha udp test", func() {
/*
	It("UDP_LB:test prepare env", func() {
		utils.InitLog(utils.GetVyosUtLogDir()+"lb_test.log", true)
		utils.GetSlbHaBootStrap()
		plugin.InitLb()
		nicCmd := &plugin.ConfigureNicCmd {
			Nics: []utils.NicInfo{utils.MgtNicForUT},
		}
		plugin.ConfigureNic(nicCmd)
		
		nicCmd = &plugin.ConfigureNicCmd {
			Nics: []utils.NicInfo{utils.PubNicForUT},
		}
		plugin.ConfigureNic(nicCmd)
		
		
		nicCmd = &plugin.ConfigureNicCmd {
			Nics: []utils.NicInfo{utils.PriNicForUT},
		}
		plugin.ConfigureNic(nicCmd)

		utils.CreateFileIfNotExists(plugin.GetKeepalivedConfigFile(), os.O_CREATE, 0600)
		utils.CreateFileIfNotExists(filepath.Join(plugin.GetKeepalivedScriptPath(), "check_zvr.sh"), os.O_CREATE, 0600)
	})

	It("UDP_LB: set up slb ha", func() {
		vip4 := plugin.MacVipPair{
			NicMac: utils.PubNicForUT.Mac,
			NicVip: "169.254.2.102",
			Netmask: "255.255.255.0",
		}
		vip6 := plugin.MacVipPair{
			NicMac: utils.PubNicForUT.Mac,
			NicVip: "234e:0:4568::75:cf18",
			PrefixLen: 64,
		}
		vyoshacmd := &plugin.SetVyosHaCmd {
			Keepalive: 5,
			HeartbeatNic: utils.PubNicForUT.Mac,
			LocalIp: "169.254.2.100",
			PeerIp: "169.254.2.101",
			LocalIpV6: "234e:0:4568::19:9e8a",
			PeerIpV6: "234e:0:4568::52:90dc",
			Monitors: []string{},
			Vips: []plugin.MacVipPair{vip4, vip6},
		}

		log.Debugf("set slb ha cmd: %+v", vyoshacmd)
		plugin.SetVyosHa(vyoshacmd)
	})

	It("UDP_LB:", func() {
		lb := &plugin.LbInfo{}
		lb.LbUuid = "f2c7b2ff2f834e1ea20363f49122a3b4"
		lb.ListenerUuid = "23fb656e4f324e74a4889582104fcbf0"
		lb.InstancePort = 8080
		lb.LoadBalancerPort = 8080
		lb.Vip = "192.168.2.100"
		lb.NicIps = append(lb.NicIps, "192.168.3.10")
		lb.Mode = "udp"
		lb.PublicNic = utils.PubNicForUT.Mac
		lb.Parameters = append(lb.Parameters,
			"balancerWeight::192.168.3.10::100",
			"connectionIdleTimeout::60",
			"Nbprocess::1",
			"balancerAlgorithm::roundrobin",
			"healthCheckTimeout::2",
			"healthCheckTarget::tcp:default",
			"maxConnection::2000000",
			"httpMode::http-server-close",
			"accessControlStatus::enable",
			"healthyThreshold::2",
			"healthCheckInterval::5",
			"unhealthyThreshold::2")

		bs := plugin.BackendServerInfo{
			Ip:     "192.168.3.10",
			Weight: 100,
		}
		sg := plugin.ServerGroupInfo{Name: "default-server-group",
			ServerGroupUuid: "8e52bcc526074521894162aa8db73c24",
			BackendServers:  []plugin.BackendServerInfo{bs},
			IsDefault:       false,
		}
		lb.ServerGroups = []plugin.ServerGroupInfo{sg}
		lb.RedirectRules = nil

		listener := plugin.GetListener(*lb)
		plugin.AddLbs([]plugin.Listener{listener})
	})

	*/
})
