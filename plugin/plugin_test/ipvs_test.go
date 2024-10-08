package plugin_test

import (
	"context"
	"fmt"
	"time"

	"zstack-vyos/plugin"
	"zstack-vyos/utils"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ipvs test", func() {
	Context("slbha ipvs test", func() {
		var mgtNicForUT, pubNicForUT, priNicForUT utils.NicInfo
		lb := plugin.LbInfo{}
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
			"healthCheckTarget::udp:default",
			"maxConnection::2000000",
			"httpMode::http-server-close",
			"accessControlStatus::enable",
			"healthyThreshold::2",
			"healthCheckInterval::1",
			"unhealthyThreshold::2")
			
		lb1 := lb
		lb1.ListenerUuid = "23fb656e4f324e74a4889582104fcbf1"
		lb1.LoadBalancerPort = 81
		
		bs1 := plugin.BackendServerInfo{
			Ip:     "192.168.3.10",
			Weight: 100,
		}

		bs2 := plugin.BackendServerInfo{
			Ip:     "192.168.3.11",
			Weight: 100,
		}

		bs3 := plugin.BackendServerInfo{
			Ip:     "192.168.3.12",
			Weight: 100,
		}
		
		sg := plugin.ServerGroupInfo{Name: "default-server-group",
			ServerGroupUuid: "8e52bcc526074521894162aa8db73c24",
			BackendServers:  []plugin.BackendServerInfo{bs1, bs2},
			IsDefault:       false,
		}
		lb.ServerGroups = []plugin.ServerGroupInfo{sg}
		lb.RedirectRules = nil
		
		lb1.ServerGroups = []plugin.ServerGroupInfo{sg}
		lb1.RedirectRules = nil

		sg1 := plugin.ServerGroupInfo{Name: "server-group-1",
			ServerGroupUuid: "8e52bcc526074521894162aa8db73c25",
			BackendServers:  []plugin.BackendServerInfo{bs3},
			IsDefault:       false,
		}
		
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

		It("ipvs: RefreshIpvsService", func() {
			err := utils.IpAddrAdd(priNicForUT.Name + "-peer", "192.168.3.10/24")
			utils.PanicOnError(err)
			err = utils.IpAddrAdd(priNicForUT.Name + "-peer", "192.168.3.11/24")
			utils.PanicOnError(err)
			ctx1, cancel1 := context.WithCancel(context.Background())
			ctx2, cancel2 := context.WithCancel(context.Background())
			go utils.StartUdpServer("192.168.3.10", 8080, ctx1)
			go utils.StartUdpServer("192.168.3.11", 8080, ctx2)
			
			plugin.RefreshIpvsService(map[string]plugin.LbInfo{lb.ListenerUuid: lb})
			
			// check ipset config 
			ipsetGroup := utils.GetIpSet(plugin.IPVS_LOG_IPSET_NAME)
			Expect(ipsetGroup.CheckMember(lb.Vip + ",udp:" + fmt.Sprintf("%d", lb.LoadBalancerPort))).To(BeTrue(), "ipvs log ipset member added", ipsetGroup)

			// check ipvs config 
			wait := 6 // 
			time.Sleep(time.Duration(wait) * time.Second)
			ipvs := plugin.NewIpvsConfFromSave()
			Expect(len(ipvs.Services) == 1).To(BeTrue(), "ipvs frond service added")
			for _, fs := range ipvs.Services {
				Expect(len(fs.BackendServers) == 2).To(BeTrue(), "2 ipvs backend server added")
				for _, bs := range fs.BackendServers {
					Expect(bs.FrontIp == "192.168.2.100").To(BeTrue(), "ipvs backend server added")
					Expect(bs.FrontPort == "80").To(BeTrue(), "ipvs backend server added")
					Expect(bs.ProtocolType == "-u").To(BeTrue(), "ipvs backend server added")
					Expect(bs.ConnectionType == "-m").To(BeTrue(), "ipvs backend server added")
					Expect(bs.Scheduler == "rr").To(BeTrue(), "ipvs backend server added")
					Expect(bs.BackendIp == "192.168.3.10" || bs.BackendIp == "192.168.3.11").To(BeTrue(), "ipvs backend server is up")
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
			cancel2()
			time.Sleep(time.Duration(wait) * time.Second)
			plugin.UpdateIpvsCounters()
			for _, bs := range fs.BackendServers {
				cnt := bs.Counter
				if bs.BackendIp == "192.168.3.10" {
					Expect(cnt.Status == 1).To(BeTrue(), "ipvs backend server(192.168.3.10) is up")
				} else {
					Expect(cnt.Status == 0).To(BeTrue(), "ipvs backend server(192.168.3.11) is down")
				}
			}
			cancel1()
			//wait udp server down
			time.Sleep(time.Duration(2) * time.Second)
		})

		It("ipvs: RefreshIpvsService to add 1 backend server", func() {
			err := utils.IpAddrAdd(priNicForUT.Name + "-peer", "192.168.3.12/24")
			utils.PanicOnError(err)
			lb.ServerGroups = append(lb.ServerGroups, sg1)
			ctx1, cancel1 := context.WithCancel(context.Background())
			ctx2, cancel2 := context.WithCancel(context.Background())
			ctx3, cancel3 := context.WithCancel(context.Background())
			go utils.StartUdpServer("192.168.3.10", 8080, ctx1)
			go utils.StartUdpServer("192.168.3.11", 8080, ctx2)
			go utils.StartUdpServer("192.168.3.12", 8080, ctx3)

			plugin.RefreshIpvsService(map[string]plugin.LbInfo{lb.ListenerUuid: lb})
			
			// check ipset config 
			ipsetGroup := utils.GetIpSet(plugin.IPVS_LOG_IPSET_NAME)
			Expect(ipsetGroup.CheckMember(lb.Vip + ",udp:" + fmt.Sprintf("%d", lb.LoadBalancerPort))).To(BeTrue(), "ipvs log ipset member added", ipsetGroup)

			// check ipvs config 
			wait := 6 // 
			time.Sleep(time.Duration(wait) * time.Second)
			ipvs := plugin.NewIpvsConfFromSave()
			Expect(len(ipvs.Services) == 1).To(BeTrue(), "ipvs frond service added")
			for _, fs := range ipvs.Services {
				Expect(len(fs.BackendServers) == 3).To(BeTrue(), "3 ipvs backend server added")
				for _, bs := range fs.BackendServers {
					Expect(bs.FrontIp == "192.168.2.100").To(BeTrue(), "ipvs backend server added")
					Expect(bs.FrontPort == "80").To(BeTrue(), "ipvs backend server added")
					Expect(bs.ProtocolType == "-u").To(BeTrue(), "ipvs backend server added")
					Expect(bs.ConnectionType == "-m").To(BeTrue(), "ipvs backend server added")
					Expect(bs.Scheduler == "rr").To(BeTrue(), "ipvs backend server added")
					Expect(bs.BackendIp == "192.168.3.10" || bs.BackendIp == "192.168.3.11" || bs.BackendIp == "192.168.3.12").To(BeTrue(), "ipvs backend server is up")
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
			
			// refresh ipvs without any change
			plugin.RefreshIpvsService(map[string]plugin.LbInfo{lb.ListenerUuid: lb})
			
			// check ipset config 
			ipsetGroup = utils.GetIpSet(plugin.IPVS_LOG_IPSET_NAME)
			Expect(ipsetGroup.CheckMember(lb.Vip + ",udp:" + fmt.Sprintf("%d", lb.LoadBalancerPort))).To(BeTrue(), "ipvs log ipset member added", ipsetGroup)

			// check ipvs config 
			time.Sleep(time.Duration(wait) * time.Second)
			ipvs = plugin.NewIpvsConfFromSave()
			Expect(len(ipvs.Services) == 1).To(BeTrue(), "ipvs frond service added")
			for _, fs := range ipvs.Services {
				Expect(len(fs.BackendServers) == 3).To(BeTrue(), "3 ipvs backend server added")
				for _, bs := range fs.BackendServers {
					Expect(bs.FrontIp == "192.168.2.100").To(BeTrue(), "ipvs backend server added")
					Expect(bs.FrontPort == "80").To(BeTrue(), "ipvs backend server added")
					Expect(bs.ProtocolType == "-u").To(BeTrue(), "ipvs backend server added")
					Expect(bs.ConnectionType == "-m").To(BeTrue(), "ipvs backend server added")
					Expect(bs.Scheduler == "rr").To(BeTrue(), "ipvs backend server added")
					Expect(bs.BackendIp == "192.168.3.10" || bs.BackendIp == "192.168.3.11" || bs.BackendIp == "192.168.3.12").To(BeTrue(), "ipvs backend server is up")
					Expect(bs.BackendPort == "8080").To(BeTrue(), "ipvs backend server added")
				}
			}
			
			/* check ipvs metrics */
			plugin.UpdateIpvsCounters()
			fs = plugin.GetIpvsFrontService(lb.ListenerUuid)
			for _, bs := range fs.BackendServers {
				cnt := bs.Counter
				Expect(cnt.Status == 1).To(BeTrue(), "ipvs backend server is up")
			}

			cancel1()
			cancel2()
			cancel3()
			//wait udp server down
			time.Sleep(time.Duration(2) * time.Second)
		})

		It("ipvs: RefreshIpvsService to del 1 backend server", func() {
			lb.ServerGroups = []plugin.ServerGroupInfo{sg}
			ctx1, cancel1 := context.WithCancel(context.Background())
			ctx2, cancel2 := context.WithCancel(context.Background())
			go utils.StartUdpServer("192.168.3.10", 8080, ctx1)
			go utils.StartUdpServer("192.168.3.11", 8080, ctx2)

			plugin.RefreshIpvsService(map[string]plugin.LbInfo{lb.ListenerUuid: lb})
			
			// check ipset config 
			ipsetGroup := utils.GetIpSet(plugin.IPVS_LOG_IPSET_NAME)
			Expect(ipsetGroup.CheckMember(lb.Vip + ",udp:" + fmt.Sprintf("%d", lb.LoadBalancerPort))).To(BeTrue(), "ipvs log ipset member added", ipsetGroup)

			// check ipvs config 
			wait := 6 // 
			time.Sleep(time.Duration(wait) * time.Second)
			ipvs := plugin.NewIpvsConfFromSave()
			Expect(len(ipvs.Services) == 1).To(BeTrue(), "ipvs frond service added")
			for _, fs := range ipvs.Services {
				Expect(len(fs.BackendServers) == 2).To(BeTrue(), "2 ipvs backend server added")
				for _, bs := range fs.BackendServers {
					Expect(bs.FrontIp == "192.168.2.100").To(BeTrue(), "ipvs backend server added")
					Expect(bs.FrontPort == "80").To(BeTrue(), "ipvs backend server added")
					Expect(bs.ProtocolType == "-u").To(BeTrue(), "ipvs backend server added")
					Expect(bs.ConnectionType == "-m").To(BeTrue(), "ipvs backend server added")
					Expect(bs.Scheduler == "rr").To(BeTrue(), "ipvs backend server added")
					Expect(bs.BackendIp == "192.168.3.10" || bs.BackendIp == "192.168.3.11").To(BeTrue(), "ipvs backend server is up")
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
			
			cancel1()
			cancel2()
			//wait udp server down
			time.Sleep(time.Duration(2) * time.Second)
		})

		It("ipvs: RefreshIpvsService to add 1 front service", func() {
			ctx1, cancel1 := context.WithCancel(context.Background())
			ctx2, cancel2 := context.WithCancel(context.Background())
			go utils.StartUdpServer("192.168.3.10", 8080, ctx1)
			go utils.StartUdpServer("192.168.3.11", 8080, ctx2)

			plugin.RefreshIpvsService(map[string]plugin.LbInfo{lb.ListenerUuid: lb, lb1.ListenerUuid: lb1})
			
			// check ipset config 
			ipsetGroup := utils.GetIpSet(plugin.IPVS_LOG_IPSET_NAME)
			Expect(ipsetGroup.CheckMember(lb.Vip + ",udp:" + fmt.Sprintf("%d", lb.LoadBalancerPort))).To(BeTrue(), "ipvs log ipset member added", ipsetGroup)
			Expect(ipsetGroup.CheckMember(lb1.Vip + ",udp:" + fmt.Sprintf("%d", lb1.LoadBalancerPort))).To(BeTrue(), "ipvs log ipset member added", ipsetGroup)
			
			// check ipvs config 
			wait := 6 // 
			time.Sleep(time.Duration(wait) * time.Second)
			ipvs := plugin.NewIpvsConfFromSave()
			Expect(len(ipvs.Services) == 2).To(BeTrue(), "ipvs frond service added")
			for _, fs := range ipvs.Services {
				Expect(len(fs.BackendServers) == 2).To(BeTrue(), "2 ipvs backend server added")
				for _, bs := range fs.BackendServers {
					Expect(bs.FrontIp == "192.168.2.100").To(BeTrue(), "ipvs backend server added")
					Expect(bs.FrontPort == "80" ||  bs.FrontPort == "81").To(BeTrue(), "ipvs backend server added")
					Expect(bs.ProtocolType == "-u").To(BeTrue(), "ipvs backend server added")
					Expect(bs.ConnectionType == "-m").To(BeTrue(), "ipvs backend server added")
					Expect(bs.Scheduler == "rr").To(BeTrue(), "ipvs backend server added")
					Expect(bs.BackendIp == "192.168.3.10" || bs.BackendIp == "192.168.3.11").To(BeTrue(), "ipvs backend server is up")
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

			fs = plugin.GetIpvsFrontService(lb1.ListenerUuid)
			for _, bs := range fs.BackendServers {
				cnt := bs.Counter
				Expect(cnt.Status == 1).To(BeTrue(), "ipvs backend server is up")
			}
			
			cancel1()
			cancel2()
			//wait udp server down
			time.Sleep(time.Duration(2) * time.Second)
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

			plugin.DelIpvsService(map[string]plugin.LbInfo{lb.ListenerUuid: lb})

			// check ipset config 
			ipsetGroup := utils.GetIpSet(plugin.IPVS_LOG_IPSET_NAME)
			Expect(ipsetGroup.CheckMember(lb.Vip + ",udp:" + fmt.Sprintf("%d", lb.LoadBalancerPort))).To(BeFalse(), "ipvs log ipset member added", ipsetGroup)

			wait := 6 
			time.Sleep(time.Duration(wait) * time.Second)
			
			// check ipvs config 
			ipvs := plugin.NewIpvsConfFromSave()
			Expect(len(ipvs.Services) == 0).To(BeTrue(), "ipvs frond service added")

			// check ipvs metrics 
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
			
			plugin.StopIpvsHealthCheck()
		})
    })
})
