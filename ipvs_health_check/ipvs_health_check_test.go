package main

import (
	"context"
	"fmt"
	"time"
	"zstack-vyos/plugin"
	"zstack-vyos/utils"

	"github.com/fsnotify/fsnotify"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	log "github.com/sirupsen/logrus"
)

var _ = Describe("ipvs health check test", func() {

	var mgtNicForUT, pubNicForUT, priNicForUT utils.NicInfo
	bs1 := IpvsHealthCheckBackendServer{}
	bs1.LbUuid ="lbUuid"
	bs1.ListenerUuid = "listenerUuid"
	bs1.ConnectionType = plugin.IpvsConnectionTypeNAT.String()
	bs1.ProtocolType = "udp"
	bs1.Scheduler = plugin.IpvsSchedulerRR.String()
	bs1.FrontIp = "192.168.2.100"
	bs1.FrontPort=  "80"
	bs1.Weight =  "1"
	bs1.BackendIp = "192.168.3.10"
	bs1.BackendPort = "8080"
	bs1.HealthCheckProtocl = "udp"
	bs1.HealthCheckPort = 8080
	bs1.HealthCheckInterval = 1
	bs1.HealthCheckTimeout = 2
	bs1.HealthyThreshold = 2
	bs1.UnhealthyThreshold = 2
	bs1.MaxConnection = 2000000
	bs1.MinConnection = 1

	// bs1, bs2 has same front ip and port
	// bs3, bs4 has same front ip and port
	bs2 := bs1
	bs2.BackendIp = "192.168.3.11"
	bs2.BackendPort = "8081"

	bs3 := bs1
	bs3.ListenerUuid = "listenerUuid2"
	bs3.FrontPort=  "81"

	bs4 := bs2
	bs4.ListenerUuid = "listenerUuid2"
	bs4.FrontPort=  "81"
	
	ctx1, cancel1 := context.WithCancel(context.Background())
	ctx2, cancel2 := context.WithCancel(context.Background())
	bsMap  := map[string]*IpvsHealthCheckBackendServer{}
	bsMap[bs1.getBackendKey()] = &bs1
	bsMap[bs2.getBackendKey()] = &bs2
	bsMap[bs3.getBackendKey()] = &bs3
	bsMap[bs4.getBackendKey()] = &bs4
	
	It("ipvs health check: prepare env", func() {
		utils.InitLog(utils.GetVyosUtLogDir()+"ipvs_health_check.log", true)
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

		err := utils.IpAddrAdd(priNicForUT.Name + "-peer", bs1.BackendIp+"/24")
		utils.PanicOnError(err)
		err = utils.IpAddrAdd(priNicForUT.Name + "-peer", bs2.BackendIp+"/24")
		utils.PanicOnError(err)
	})

	It("ipvs health check: test start process", func() {
		binPath := plugin.IPVS_HEALTH_CHECK_BIN_FILE
		if utils.IsVYOS() {
			binPath = plugin.IPVS_HEALTH_CHECK_BIN_FILE_VYOS
		}
	
		b := utils.Bash{
			Command: fmt.Sprintf("nohup %s -f %s -log %s -p %s > /dev/null 2>&1 &", binPath, 
				plugin.IPVS_HEALTH_CHECK_CONFIG_FILE, plugin.IPVS_HEALTH_CHECK_LOG_FILE,
				plugin.IPVS_HEALTH_CHECK_PID_FILE),
			Sudo: true,
		}
		err := b.Run()
		Expect(err).To(BeNil(), "start ipvs health check again failed")
		pid, _ := utils.FindFirstPID(binPath)
		Expect(pid > 0).To(BeTrue(), "pid should be greater than 0")
		
		b.Run()
		pid1, _ := utils.FindFirstPID(binPath)
		Expect(pid == pid1).To(BeTrue(), "same process")

		b = utils.Bash{
			Command: fmt.Sprintf("pkill -9 ipvsHealthCheck; nohup %s -f %s -log %s -p %s > /dev/null 2>&1 &", binPath, 
				plugin.IPVS_HEALTH_CHECK_CONFIG_FILE, plugin.IPVS_HEALTH_CHECK_LOG_FILE,
				plugin.IPVS_HEALTH_CHECK_PID_FILE),
			Sudo: true,
		}
		b.Run()
		pid, _ = utils.FindFirstPID(binPath)
		Expect(pid > 0).To(BeTrue(), "pid should be greater than 0")

		b = utils.Bash{
			Command: "pkill -9 ipvsHealthCheck",
			Sudo: true,
		}
		b.Run()
	})

	It("ipvs health check: test loadAndStartHealthChecker", func() {
		setHealthCheckMapForUT(map[string]*IpvsHealthCheckBackendServer{})
		fs := plugin.IpvsHealthCheckFrontService{
			LbUuid: bs1.LbUuid,
			ListenerUuid: bs1.ListenerUuid,
			
			ConnectionType: plugin.IpvsConnectionTypeNAT.String(),
			ProtocolType: "udp",
			Scheduler: plugin.IpvsSchedulerRR.String(),
			FrontIp: bs1.FrontIp,
			FrontPort: bs1.FrontPort,
			BackendServers: []*plugin.IpvsHealthCheckBackendServer{&bs1.IpvsHealthCheckBackendServer,
				&bs2.IpvsHealthCheckBackendServer},
		}

		fs1 := plugin.IpvsHealthCheckFrontService{
			LbUuid: bs3.LbUuid,
			ListenerUuid: bs3.ListenerUuid,
			
			ConnectionType: plugin.IpvsConnectionTypeNAT.String(),
			ProtocolType: "udp",
			Scheduler: plugin.IpvsSchedulerRR.String(),
			FrontIp: bs3.FrontIp,
			FrontPort: bs3.FrontPort,
			BackendServers: []*plugin.IpvsHealthCheckBackendServer{&bs3.IpvsHealthCheckBackendServer,
				&bs4.IpvsHealthCheckBackendServer},
		}
		
		conf := plugin.IpvsHealthCheckConf{
			Services: []*plugin.IpvsHealthCheckFrontService{&fs, &fs1}}
			
		watcher, err := fsnotify.NewWatcher()
		utils.PanicOnError(err)
		defer watcher.Close()

		setConfFileForUT(plugin.IPVS_HEALTH_CHECK_CONFIG_FILE)
		watcher.Add(plugin.IPVS_HEALTH_CHECK_CONFIG_FILE)
		
		go handleEvents(watcher.Events, watcher.Errors)
		/* 更新 配置文件 */
		utils.JsonStoreConfig(plugin.IPVS_HEALTH_CHECK_CONFIG_FILE, conf)
		time.Sleep(time.Duration(2*time.Second))
		Expect( len(getHealthCheckMapForUT()) == 4).To(BeTrue(), fmt.Sprintf("4 backend server, actual %d", len(gHealthCheckMap)))
		
		fs.BackendServers = []*plugin.IpvsHealthCheckBackendServer{&bs2.IpvsHealthCheckBackendServer}
		/* 更新 配置文件 */
		utils.JsonStoreConfig(plugin.IPVS_HEALTH_CHECK_CONFIG_FILE, conf)
		time.Sleep(time.Duration(2*time.Second))
		Expect( len(getHealthCheckMapForUT()) == 3).To(BeTrue(), fmt.Sprintf("1 backend server, actual %d", len(gHealthCheckMap)))
		
		fs.BackendServers = []*plugin.IpvsHealthCheckBackendServer{&bs2.IpvsHealthCheckBackendServer, 
			&bs1.IpvsHealthCheckBackendServer}
		/* 更新 配置文件 */
		utils.JsonStoreConfig(plugin.IPVS_HEALTH_CHECK_CONFIG_FILE, conf)
		time.Sleep(time.Duration(2*time.Second))
		Expect( len(getHealthCheckMapForUT()) == 4).To(BeTrue(), fmt.Sprintf("2 backend server, actual %d", len(gHealthCheckMap)))
		
		bs2.HealthCheckPort = 9090
		utils.JsonStoreConfig(plugin.IPVS_HEALTH_CHECK_CONFIG_FILE, conf)
		time.Sleep(time.Duration(2*time.Second))
		Expect( len(getHealthCheckMapForUT()) == 4).To(BeTrue(), fmt.Sprintf("2 backend server, actual %d", len(gHealthCheckMap)))
		for _, bs := range getHealthCheckMapForUT() {
			if bs.getBackendKey() == bs2.getBackendKey() {
				Expect(bs.HealthCheckPort == 9090).To(BeTrue(), fmt.Sprintf("bs2 HealthCheckPort should be 9090 , actual %d", bs.HealthCheckPort))
			}
		}

		fs.BackendServers = []*plugin.IpvsHealthCheckBackendServer{}
		fs1.BackendServers = []*plugin.IpvsHealthCheckBackendServer{}
		/* 更新 配置文件 */
		utils.JsonStoreConfig(plugin.IPVS_HEALTH_CHECK_CONFIG_FILE, conf)
		time.Sleep(time.Duration(2*time.Second))
		Expect( len(getHealthCheckMapForUT()) == 0).To(BeTrue(), fmt.Sprintf("0 backend server, actual %d", len(gHealthCheckMap)))
	})

	It("ipvs health check: test health check task", func() {
		setHealthCheckMapForUT(bsMap)
		
		go bs1.Start()
		go bs2.Start()

		wait := bs1.HealthCheckInterval * (bs1.HealthyThreshold + 2)
		if  wait < bs1.HealthCheckInterval * (bs1.UnhealthyThreshold + 2) {
			wait = bs1.HealthCheckInterval * (bs1.UnhealthyThreshold + 2)
		}
		
		/* start udp server for bs1 */
		go utils.StartUdpServer(bs1.BackendIp, 8080, ctx1)
		time.Sleep(time.Duration(wait) * time.Second)
		Expect(bs1.status).To(BeTrue(), "bs1 is up")
		Expect(bs2.status).To(BeFalse(), "bs2 is down")
		ipvsConf := plugin.NewIpvsConfFromSave()
		Expect( len(ipvsConf.Services) == 1).To(BeTrue(), "1 ipvs service")
		for _, fs := range ipvsConf.Services {
			Expect( len(fs.BackendServers) == 1).To(BeTrue(), "1 backend is up")
			for _, bs := range fs.BackendServers {
				Expect(bs.BackendIp == bs1.BackendIp).To(BeTrue(), "backend 1 is up")
				Expect(bs.BackendPort == bs1.BackendPort).To(BeTrue(), "backend 1 is up")
			}
		}
		
		/* start udp server for bs2 */
		go utils.StartUdpServer(bs2.BackendIp, 8081, ctx2)
		time.Sleep(time.Duration(wait) * time.Second)
		Expect(bs1.status).To(BeTrue(), "bs1 is up")
		Expect(bs2.status).To(BeTrue(), "bs2 is ip")
		ipvsConf = plugin.NewIpvsConfFromSave()
		Expect( len(ipvsConf.Services) == 1).To(BeTrue(), "1 ipvs service")
		foundBs1 := false
		foundBs2 := false
		for _, fs := range ipvsConf.Services {
			for _, bs := range fs.BackendServers {
				if bs.BackendIp == bs1.BackendIp && bs.BackendPort == bs1.BackendPort {
					foundBs1 = true
				} else if bs.BackendIp == bs2.BackendIp && bs.BackendPort == bs2.BackendPort {
					foundBs2 = true
				} 
			}
			Expect( len(fs.BackendServers) == 2).To(BeTrue(), "2 backends is up")
		}
		Expect( foundBs1).To(BeTrue(), "bs1 is up")
		Expect( foundBs2).To(BeTrue(), "bs2 is up")

		/* stop udp server for bs1 */
		cancel1()
		time.Sleep(time.Duration(wait) * time.Second)
		Expect(bs1.status).To(BeFalse(), "bs1 is down")
		Expect(bs2.status).To(BeTrue(), "bs2 is ip")
		ipvsConf = plugin.NewIpvsConfFromSave()
		Expect( len(ipvsConf.Services) == 1).To(BeTrue(), "1 ipvs service")
		foundBs1 = false
		foundBs2 = false
		for _, fs := range ipvsConf.Services {
			for _, bs := range fs.BackendServers {
				if bs.BackendIp == bs1.BackendIp && bs.BackendPort == bs1.BackendPort {
					foundBs1 = true
				} else if bs.BackendIp == bs2.BackendIp && bs.BackendPort == bs2.BackendPort {
					foundBs2 = true
				} 
			}
			Expect( len(fs.BackendServers) == 1).To(BeTrue(), "1 backends is up")
		}
		Expect( foundBs1).To(BeFalse(), "bs1 is down")
		Expect( foundBs2).To(BeTrue(), "bs2 is up")
		
		/* start udp server for bs1 again */
		ctx1, cancel1 = context.WithCancel(context.Background())
		go utils.StartUdpServer(bs1.BackendIp, 8080, ctx1)
		time.Sleep(time.Duration(wait) * time.Second)
		Expect(bs1.status).To(BeTrue(), "bs1 is up")
		Expect(bs2.status).To(BeTrue(), "bs2 is ip")
		ipvsConf = plugin.NewIpvsConfFromSave()
		Expect( len(ipvsConf.Services) == 1).To(BeTrue(), "1 ipvs service")
		foundBs1 = false
		foundBs2 = false
		for _, fs := range ipvsConf.Services {
			for _, bs := range fs.BackendServers {
				if bs.BackendIp == bs1.BackendIp && bs.BackendPort == bs1.BackendPort {
					foundBs1 = true
				} else if bs.BackendIp == bs2.BackendIp && bs.BackendPort == bs2.BackendPort {
					foundBs2 = true
				}
			}
			Expect( len(fs.BackendServers) == 2).To(BeTrue(), "2 backends is up")
		}
		Expect( foundBs1).To(BeTrue(), "bs1 is up")
		Expect( foundBs2).To(BeTrue(), "bs2 is up")
		
		/* stop udp server for bs1, bs2 */
		cancel1()
		cancel2()
		time.Sleep(time.Duration(wait) * time.Second)
		Expect(bs1.status).To(BeFalse(), "bs1 is down")
		Expect(bs2.status).To(BeFalse(), "bs2 is down")
		ipvsConf = plugin.NewIpvsConfFromSave()
		Expect( len(ipvsConf.Services) == 0).To(BeTrue(), "0 ipvs service")

		/*start udp server for bs1, bs2 again */
		go bs3.Start()
		go bs4.Start()
		
		ctx1, cancel1 = context.WithCancel(context.Background())
		ctx2, cancel2 = context.WithCancel(context.Background())
		go utils.StartUdpServer(bs1.BackendIp, 8080, ctx1)
		go utils.StartUdpServer(bs2.BackendIp, 8081, ctx2)
		time.Sleep(time.Duration(wait) * time.Second)
		Expect(bs1.status).To(BeTrue(), "bs1 is up")
		Expect(bs2.status).To(BeTrue(), "bs2 is ip")
		Expect(bs3.status).To(BeTrue(), "bs3 is ip")
		Expect(bs4.status).To(BeTrue(), "bs4 is ip")
		ipvsConf = plugin.NewIpvsConfFromSave()
		Expect( len(ipvsConf.Services) == 2).To(BeTrue(), "2 ipvs service")
		foundBs1 = false
		foundBs2 = false
		foundBs3 := false
		foundBs4 := false
		for _, fs := range ipvsConf.Services {
			for _, bs := range fs.BackendServers {
				log.Debugf("bs key: %s: bs1 key: %s", bs.GetBackendKey(), bs1.getBackendKey())
				if bs.GetBackendKey() == bs1.getBackendKey() {
					foundBs1 = true
				} else if bs.GetBackendKey() == bs2.getBackendKey() {
					foundBs2 = true
				} else if bs.GetBackendKey() == bs3.getBackendKey() {
					foundBs3 = true
				} else if bs.GetBackendKey() == bs4.getBackendKey() {
					foundBs4 = true
				}
			}
			Expect( len(fs.BackendServers) == 2).To(BeTrue(), "2 backends is up")
		}
		Expect( foundBs1).To(BeTrue(), "bs1 is up")
		Expect( foundBs2).To(BeTrue(), "bs2 is up")
		Expect( foundBs3).To(BeTrue(), "bs3 is up")
		Expect( foundBs4).To(BeTrue(), "bs4 is up")
		
		/*stop bs1, bs2 */
		bs1.Stop()
		bs2.Stop()
		bs3.Stop()
		bs4.Stop()
		time.Sleep(time.Duration(wait) * time.Second)
		Expect(bs1.status).To(BeFalse(), "bs1 is down")
		Expect(bs2.status).To(BeFalse(), "bs2 is down")
		Expect(bs3.status).To(BeFalse(), "bs1 is down")
		Expect(bs4.status).To(BeFalse(), "bs2 is down")
		ipvsConf = plugin.NewIpvsConfFromSave()
		Expect( len(ipvsConf.Services) == 0).To(BeTrue(), fmt.Sprintf("0 ipvs service, actual %d", len(ipvsConf.Services)))
	})

	/*
	It("ipvs health check: test ipv6", func() {
		setHealthCheckMapForUT(bsMap)
		bs1.FrontIp = "2024:09:29:86:01::100"
		bs1.BackendIp = "2024:09:29:86:02::100"
		bs2.BackendIp = "2024:09:29:86:02::101"

		err := utils.IpAddrAdd(priNicForUT.Name + "-peer", bs1.BackendIp+"/64")
		utils.PanicOnError(err)
		err = utils.IpAddrAdd(priNicForUT.Name + "-peer", bs2.BackendIp+"/64")
		utils.PanicOnError(err)

		go bs1.Start()
		go bs2.Start()

		wait := bs1.HealthCheckInterval * (bs1.HealthyThreshold + 2)
		if  wait < bs1.HealthCheckInterval * (bs1.UnhealthyThreshold + 2) {
			wait = bs1.HealthCheckInterval * (bs1.UnhealthyThreshold + 2)
		}
		
		// start udp server for bs1 
		go utils.StartUdpServer(bs1.BackendIp, 8080, ctx1)
		time.Sleep(time.Duration(wait) * time.Second)
		Expect(bs1.status).To(BeTrue(), "bs1 is up")
		Expect(bs2.status).To(BeFalse(), "bs2 is down")
		ipvsConf := plugin.NewIpvsConfFromSave()
		Expect( len(ipvsConf.Services) == 1).To(BeTrue(), "1 ipvs service")
		for _, fs := range ipvsConf.Services {
			Expect( len(fs.BackendServers) == 1).To(BeTrue(), "1 backend is up")
			for _, bs := range fs.BackendServers {
				Expect(bs.BackendIp == bs1.BackendIp).To(BeTrue(), "backend 1 is up")
				Expect(bs.BackendPort == bs1.BackendPort).To(BeTrue(), "backend 1 is up")
			}
		}
		
		// start udp server for bs2 
		go utils.StartUdpServer(bs2.BackendIp, 8081, ctx2)
		time.Sleep(time.Duration(wait) * time.Second)
		Expect(bs1.status).To(BeTrue(), "bs1 is up")
		Expect(bs2.status).To(BeTrue(), "bs2 is ip")
		ipvsConf = plugin.NewIpvsConfFromSave()
		Expect( len(ipvsConf.Services) == 1).To(BeTrue(), "1 ipvs service")
		foundBs1 := false
		foundBs2 := false
		for _, fs := range ipvsConf.Services {
			for _, bs := range fs.BackendServers {
				if bs.BackendIp == bs1.BackendIp && bs.BackendPort == bs1.BackendPort {
					foundBs1 = true
				} else if bs.BackendIp == bs2.BackendIp && bs.BackendPort == bs2.BackendPort {
					foundBs2 = true
				} 
			}
			Expect( len(fs.BackendServers) == 3).To(BeTrue(), "2 backends is up")
		}
		Expect( foundBs1).To(BeTrue(), "bs1 is up")
		Expect( foundBs2).To(BeTrue(), "bs2 is up")

		// stop udp server for bs1 
		cancel1()
		time.Sleep(time.Duration(wait) * time.Second)
		Expect(bs1.status).To(BeFalse(), "bs1 is down")
		Expect(bs2.status).To(BeTrue(), "bs2 is ip")
		ipvsConf = plugin.NewIpvsConfFromSave()
		Expect( len(ipvsConf.Services) == 1).To(BeTrue(), "1 ipvs service")
		foundBs1 = false
		foundBs2 = false
		for _, fs := range ipvsConf.Services {
			for _, bs := range fs.BackendServers {
				if bs.BackendIp == bs1.BackendIp && bs.BackendPort == bs1.BackendPort {
					foundBs1 = true
				} else if bs.BackendIp == bs2.BackendIp && bs.BackendPort == bs2.BackendPort {
					foundBs2 = true
				} 
			}
			Expect( len(fs.BackendServers) == 1).To(BeTrue(), "1 backends is up")
		}
		Expect( foundBs1).To(BeFalse(), "bs1 is down")
		Expect( foundBs2).To(BeTrue(), "bs2 is up")
		
		// start udp server for bs1 again 
		ctx1, cancel1 = context.WithCancel(context.Background())
		go utils.StartUdpServer(bs1.BackendIp, 8080, ctx1)
		time.Sleep(time.Duration(wait) * time.Second)
		Expect(bs1.status).To(BeTrue(), "bs1 is up")
		Expect(bs2.status).To(BeTrue(), "bs2 is ip")
		ipvsConf = plugin.NewIpvsConfFromSave()
		Expect( len(ipvsConf.Services) == 1).To(BeTrue(), "1 ipvs service")
		foundBs1 = false
		foundBs2 = false
		for _, fs := range ipvsConf.Services {
			for _, bs := range fs.BackendServers {
				if bs.BackendIp == bs1.BackendIp && bs.BackendPort == bs1.BackendPort {
					foundBs1 = true
				} else if bs.BackendIp == bs2.BackendIp && bs.BackendPort == bs2.BackendPort {
					foundBs2 = true
				}
			}
			Expect( len(fs.BackendServers) == 2).To(BeTrue(), "2 backends is up")
		}
		Expect( foundBs1).To(BeTrue(), "bs1 is up")
		Expect( foundBs2).To(BeTrue(), "bs2 is up")
		
		// stop udp server for bs1, bs2
		cancel1()
		cancel2()
		time.Sleep(time.Duration(wait) * time.Second)
		Expect(bs1.status).To(BeFalse(), "bs1 is down")
		Expect(bs2.status).To(BeFalse(), "bs2 is down")
		ipvsConf = plugin.NewIpvsConfFromSave()
		Expect( len(ipvsConf.Services) == 0).To(BeTrue(), "0 ipvs service")

		//start udp server for bs1, bs2 again 
		ctx1, cancel1 = context.WithCancel(context.Background())
		ctx2, cancel2 = context.WithCancel(context.Background())
		go utils.StartUdpServer(bs1.BackendIp, 8080, ctx1)
		go utils.StartUdpServer(bs2.BackendIp, 8081, ctx2)
		time.Sleep(time.Duration(wait) * time.Second)
		Expect(bs1.status).To(BeTrue(), "bs1 is up")
		Expect(bs2.status).To(BeTrue(), "bs2 is ip")
		ipvsConf = plugin.NewIpvsConfFromSave()
		Expect( len(ipvsConf.Services) == 1).To(BeTrue(), "1 ipvs service")
		foundBs1 = false
		foundBs2 = false
		for _, fs := range ipvsConf.Services {
			for _, bs := range fs.BackendServers {
				if bs.BackendIp == bs1.BackendIp && bs.BackendPort == bs1.BackendPort {
					foundBs1 = true
				} else if bs.BackendIp == bs2.BackendIp && bs.BackendPort == bs2.BackendPort {
					foundBs2 = true
				}
			}
			Expect( len(fs.BackendServers) == 2).To(BeTrue(), "2 backends is up")
		}
		Expect( foundBs1).To(BeTrue(), "bs1 is up")
		Expect( foundBs2).To(BeTrue(), "bs2 is up")
		
		// stop bs1, bs2
		bs1.Stop()
		bs2.Stop()
		time.Sleep(time.Duration(wait) * time.Second)
		Expect(bs1.status).To(BeFalse(), "bs1 is down")
		Expect(bs2.status).To(BeFalse(), "bs2 is down")
		ipvsConf = plugin.NewIpvsConfFromSave()
		Expect( len(ipvsConf.Services) == 0).To(BeTrue(), fmt.Sprintf("0 ipvs service, actual %d", len(ipvsConf.Services)))
	}) */
	
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