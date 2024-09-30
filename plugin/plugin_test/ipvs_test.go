package plugin_test

import (
	"fmt"
	"time"

	"zstack-vyos/plugin"
	"zstack-vyos/utils"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ipvs test", func() {

	var mgtNicForUT, pubNicForUT, priNicForUT utils.NicInfo
	lb := &plugin.LbInfo{}
		lb.LbUuid = "f2c7b2ff2f834e1ea20363f49122a3b4"
		lb.ListenerUuid = "23fb656e4f324e74a4889582104fcbf0"
		lb.InstancePort = 8080
		lb.LoadBalancerPort = 80
		lb.Vip = "192.168.2.100"
		lb.NicIps = append(lb.NicIps, "192.168.3.10")
		lb.Mode = "udp"
		lb.PublicNic = pubNicForUT.Mac
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
			"healthCheckInterval::1",
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
	
	It("ipvs :test prepare env", func() {
		utils.InitLog(utils.GetVyosUtLogDir()+"ipvs.log", true)
		mgtNicForUT, pubNicForUT, priNicForUT = utils.SetupSlbHaBootStrap()
		nicCmd := &plugin.ConfigureNicCmd {
			Nics: []utils.NicInfo{mgtNicForUT},
		}
		plugin.ConfigureNic(nicCmd)
		
		nicCmd = &plugin.ConfigureNicCmd {
			Nics: []utils.NicInfo{pubNicForUT},
		}
		plugin.ConfigureNic(nicCmd)
		
		nicCmd = &plugin.ConfigureNicCmd {
			Nics: []utils.NicInfo{priNicForUT},
		}
		plugin.ConfigureNic(nicCmd)
	})

	It("ipvs :test InitIpvs", func() {
		plugin.InitIpvs()
		ipsetGroup := utils.GetIpSet(plugin.IPVS_LOG_IPSET_NAME)
		Expect(ipsetGroup).ToNot(BeNil(), "ipvs log ipset created", ipsetGroup)
		
		table := utils.NewIpTables(utils.NatTable)
		Expect(table.CheckChain(plugin.IPVS_LOG_CHAIN_NAME)).NotTo(BeFalse(), "ipvs log chain created")
	})

	It("ipvs: add lb", func() {
		plugin.RefreshIpvsService(map[string]plugin.LbInfo{lb.ListenerUuid: *lb})
		
		/* check ipset config */
		ipsetGroup := utils.GetIpSet(plugin.IPVS_LOG_IPSET_NAME)
		Expect(ipsetGroup.CheckMember(lb.Vip + ",udp:" + fmt.Sprintf("%d", lb.LoadBalancerPort))).To(BeTrue(), "ipvs log ipset member added", ipsetGroup)

		/* check ipvs config */
		ipvs := plugin.NewIpvsConfFromSave()
		Expect(len(ipvs.Services) == 1).To(BeTrue(), "ipvs frond service added")
		for _, fs := range ipvs.Services {
			Expect(len(fs.BackendServers) == 1).To(BeTrue(), "ipvs backend server added")
			for _, bs := range fs.BackendServers {
				Expect(bs.FrontIp == "192.168.2.100").To(BeTrue(), "ipvs backend server added")
				Expect(bs.FrontPort == "80").To(BeTrue(), "ipvs backend server added")
				Expect(bs.ProtocolType == "-u").To(BeTrue(), "ipvs backend server added")
				Expect(bs.ConnectionType == "-m").To(BeTrue(), "ipvs backend server added")
				Expect(bs.Scheduler == "rr").To(BeTrue(), "ipvs backend server added")
				Expect(bs.BackendIp == "192.168.3.10").To(BeTrue(), "ipvs backend server added")
				Expect(bs.BackendPort == "8080").To(BeTrue(), "ipvs backend server added")
			}
		}
		
		/* check ipvs metrics */
		plugin.UpdateIpvsCounters()
		fs := plugin.GetIpvsFrontService(lb.ListenerUuid)
		for _, bs := range fs.BackendServers {
			cnt := bs.Counter
			Expect(cnt.Status == 1).To(BeTrue(), "ipvs backend server is up")
		}
		time.Sleep(10)
		plugin.UpdateIpvsCounters()
		for _, bs := range fs.BackendServers {
			cnt := bs.Counter
			/* TODO enable health check, it should be down */
			Expect(cnt.Status == 1).To(BeTrue(), "ipvs backend server is down")
		}
	})

	It("ipvs: del lb", func() {
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

		plugin.DelIpvsService(map[string]plugin.LbInfo{lb.ListenerUuid: *lb})

		/* check ipset config */
		ipsetGroup := utils.GetIpSet(plugin.IPVS_LOG_IPSET_NAME)
		Expect(ipsetGroup.CheckMember(lb.Vip + ",udp:" + fmt.Sprintf("%d", lb.LoadBalancerPort))).To(BeFalse(), "ipvs log ipset member added", ipsetGroup)

		/* check ipvs config */
		ipvs := plugin.NewIpvsConfFromSave()
		Expect(len(ipvs.Services) == 0).To(BeTrue(), "ipvs frond service added")

		/* check ipvs metrics */
		plugin.UpdateIpvsCounters()
		fs := plugin.GetIpvsFrontService(lb.ListenerUuid)
		Expect(fs).To(BeNil(), "ipvs frond service added")
	})


	It("ipvs: test destroy env", func() {
		nicCmd := &plugin.ConfigureNicCmd {
			Nics: []utils.NicInfo{mgtNicForUT},
		}
		plugin.RemoveNic(nicCmd)
		
		nicCmd = &plugin.ConfigureNicCmd {
			Nics: []utils.NicInfo{pubNicForUT},
		}
		plugin.RemoveNic(nicCmd)
		
		nicCmd = &plugin.ConfigureNicCmd {
			Nics: []utils.NicInfo{priNicForUT},
		}
		plugin.RemoveNic(nicCmd)

		utils.DestroySlbHaBootStrap()
	})
})


