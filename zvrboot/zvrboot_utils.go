package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"zstack-vyos/utils"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

var (
	nicsMap map[string]*utils.NicInfo = make(map[string]*utils.NicInfo)
	mgmtNic *utils.NicInfo            = &utils.NicInfo{}
)

func renameNic() {
	log.Debugf("[configure: rename nics]")
	type deviceName struct {
		expected string
		actual   string
		swap     string
		isSlave  bool // true if this is a slave interface in bond scenario
	}
	err := utils.Retry(func() error {
		devNames := make([]*deviceName, 0)

		for _, nic := range nicsMap {
			// For bond scenario, handle multiple NICs with same MAC
			if nic.BondMode != "" && nic.BondMode != "none" {
				nicnames, err := utils.GetAllNicNamesByMac(nic.Mac)
				if err != nil {
					return err
				}

				if len(nicnames) < 2 {
					return fmt.Errorf("bond interface %s requires at least 2 NICs with MAC %s, but only found %d",
						nic.Name, nic.Mac, len(nicnames))
				}

				// Bond scenario: rename physical NICs to ethX-phy0, ethX-phy1
				// Later we will create bond interface with name ethX
				for i, nicname := range nicnames {
					expectedName := fmt.Sprintf("%s-phy%d", nic.Name, i)
					isSlave := true // All physical NICs are slaves in bond scenario

					if nicname != expectedName {
						devNames = append(devNames, &deviceName{
							expected: expectedName,
							actual:   nicname,
							isSlave:  isSlave,
						})
					}
				}
			} else {
				// Normal scenario: single NIC with unique MAC
				nicname, err := utils.GetNicNameByMac(nic.Mac)
				if err != nil {
					return err
				}
				if nicname != nic.Name {
					devNames = append(devNames, &deviceName{
						expected: nic.Name,
						actual:   nicname,
						isSlave:  false,
					})
				}
			}
		}
		if len(devNames) == 0 {
			return nil
		}

		// Step 1: Rename all to temporary names
		for i, devname := range devNames {
			devnum := 1000 + i
			devname.swap = fmt.Sprintf("eth%v", devnum)

			err := utils.IpLinkSetDown(devname.actual)
			if err != nil {
				return fmt.Errorf("set actual link[%s] down: %v", devname.actual, err)
			}

			err = utils.IpLinkSetName(devname.actual, devname.swap)
			if err != nil {
				return fmt.Errorf("change actual link[%s] name to swap name[%s]: %v",
					devname.actual, devname.swap, err)
			}
		}

		// Step 2: Rename from temporary names to expected names
		for _, devname := range devNames {
			err := utils.IpLinkSetName(devname.swap, devname.expected)
			if err != nil {
				return fmt.Errorf("change swap name[%s] to expected name[%s]: %v",
					devname.swap, devname.expected, err)
			}
			err = utils.IpLinkSetUp(devname.expected)
			if err != nil {
				return fmt.Errorf("set expected link[%s] up: %v", devname.expected, err)
			}

			if devname.isSlave {
				log.Debugf("renamed bond slave interface: %s -> %s", devname.actual, devname.expected)
			} else {
				log.Debugf("renamed interface: %s -> %s", devname.actual, devname.expected)
			}
		}
		return nil
	}, 60, 3)

	utils.PanicOnError(err)

}

func parseNicInfo(targetNic map[string]interface{}) *utils.NicInfo {
	var ok bool
	nicInfo := &utils.NicInfo{}

	nicInfo.Name, ok = targetNic["deviceName"].(string)
	utils.PanicIfError(ok, fmt.Errorf("cannot find 'deviceName' field for the nic"))

	nicInfo.Mac, ok = targetNic["mac"].(string)
	utils.PanicIfError(ok, errors.New("cannot find 'mac' field for the nic"))

	ip, ok := targetNic["ip"].(string)
	ip6, ok6 := targetNic["ip6"].(string)
	utils.PanicIfError(ok || ok6, fmt.Errorf("cannot find 'ip' field for the nic[name:%s]", nicInfo.Name))

	if ip != "" {
		nicInfo.Ip = ip
		nicInfo.Netmask, ok = targetNic["netmask"].(string)
		utils.PanicIfError(ok, fmt.Errorf("cannot find 'netmask' field for the nic[name:%s]", nicInfo.Name))
		nicInfo.Gateway = targetNic["gateway"].(string)

	}
	if ip6 != "" {
		nicInfo.Ip6 = ip6
		prefixLength, ok := targetNic["prefixLength"].(float64)
		utils.PanicIfError(ok, fmt.Errorf("cannot find 'prefixLength' field for the nic[name:%s]", nicInfo.Name))
		nicInfo.PrefixLength = int(prefixLength)
		nicInfo.Gateway6 = targetNic["gateway6"].(string)
		nicInfo.AddressMode, ok = targetNic["addressMode"].(string)
		utils.PanicIfError(ok, fmt.Errorf("cannot find 'addressMode' field for the nic[name:%s]", nicInfo.Name))
	}

	nicInfo.IsDefault = targetNic["isDefaultRoute"].(bool)
	if mtuFloat, ok := targetNic["mtu"].(float64); ok {
		nicInfo.Mtu = int(mtuFloat)
	}
	if targetNic["l2type"] != nil {
		nicInfo.L2Type = targetNic["l2type"].(string)
		nicInfo.Category = targetNic["category"].(string)
	}
	if targetNic["vni"] != nil {
		nicInfo.Vni = int(targetNic["vni"].(float64))
	}
	if targetNic["physicalInterface"] != nil {
		nicInfo.PhysicalInterface = targetNic["physicalInterface"].(string)
	}

	// Parse bond configuration
	if targetNic["bondMode"] != nil {
		nicInfo.BondMode, _ = targetNic["bondMode"].(string)
	} else {
		nicInfo.BondMode = "none" // default to non-bond
	}

	return nicInfo
}

func configureSshServer() {
	log.Debugf("[configure: SSH Server and publicKey]")
	sshkey := utils.BootstrapInfo["publicKey"].(string)
	utils.Assert(sshkey != "", "cannot find 'publicKey' in bootstrap info")
	sshport := utils.BootstrapInfo["sshPort"].(float64)
	address := mgmtNic.Ip
	utils.Assert(address != "", "cannot find eth0 ip address in bootstrap info")
	passwordAuthentication := "no"
	if _, ok := utils.BootstrapInfo["allowPasswordAuth"].(string); ok {
		passwordAuthentication = utils.BootstrapInfo["allowPasswordAuth"].(string)
	}

	sshInfo := utils.NewSshServer().SetListen(address).SetPorts(int(sshport)).SetKeys(sshkey)
	sshInfo.SetPasswordAuthentication(passwordAuthentication)
	err := sshInfo.ConfigService()
	utils.Assertf(err == nil, "configure SSH Server error: %s", err)
}

func configureRadvdServer() {
	log.Debugf("[configure: radvd service]")
	radvdMap := make(utils.RadvdAttrsMap)
	if utils.IsSLB() {
		_ = radvdMap.StopService()
		log.Debugf("skip configure radvd service with SLB")
	} else {
		for _, nic := range nicsMap {
			if nic.Ip6 != "" && nic.PrefixLength > 0 && nic.Category == "Private" {
				radvdAttr := utils.NewRadvdAttrs().SetNicName(nic.Name).SetIp6(nic.Ip6, nic.PrefixLength).SetMode(nic.AddressMode)
				radvdMap[nic.Name] = radvdAttr
			}
		}

		if err := radvdMap.ConfigService(); err != nil {
			log.Debugf("configure radvd service error: %+v", err)
		}
	}
}

func configurePassword() {
	log.Debugf("[configure: vyos password]")
	password, found := utils.BootstrapInfo["vyosPassword"]
	log.Debugf("[configure: %s", password)
	utils.Assert(found && password != "", "vyosPassword cannot be empty")
	if !isOnVMwareHypervisor() {
		log.Debugf("not vmware")
		err := utils.SetUserPasswd(utils.GetZvrUser(), fmt.Sprintf("%s", password))
		utils.Assertf(err == nil, "configure vpc password error: %s", err)

	}
}

func configureTimeZone() {
	log.Debugf("[configure: system configuration]")
	if err := utils.SetTimeZone("Asia/Shanghai"); err != nil {
		log.Debugf("configure time zone error: %+v", err)
	}
}

func configureSshMonitor() {
	if utils.IsEuler2203() {
		/* use systemd to restart sshd */
		return
	}

	log.Debugf("[configure: create sshd monitor]")
	cronJobMap := make(utils.CronjobMap)
	newJob := utils.NewCronjob().SetId(1).SetCommand(utils.GetCronjobFileSsh()).SetMinute("*/1")
	cronJobMap[1] = newJob
	err := cronJobMap.ConfigService()
	utils.Assertf(err == nil, "configure ssh monitor error: %s", err)
}

func configureBondNic(nic *utils.NicInfo) {
	var err error

	// Get slave interface names (eth1-phy0 and eth1-phy1)
	// Physical NICs have been renamed to ethX-phy0, ethX-phy1 in renameNic()
	slave0 := fmt.Sprintf("%s-phy0", nic.Name)
	slave1 := fmt.Sprintf("%s-phy1", nic.Name)
	slaves := []string{slave0, slave1}

	// Use nic.Name (ethX) as bond interface name
	// This ensures all plugin code works without modification
	bondName := nic.Name

	log.Debugf("[configure: creating bond %s with slaves %v, mode %s]", bondName, slaves, nic.BondMode)

	// 1. Create bond and attach slaves
	//    - If IPv4 is present, reuse SetupBondWithSlaves (creates bond, adds slaves, configures IPv4, and brings link up)
	//    - If no IPv4 (IPv6-only or L2-only), explicitly create bond and add slaves
	if nic.Ip != "" {
		err = utils.SetupBondWithSlaves(bondName, nic.BondMode, slaves, nic.Ip, nic.Netmask)
		utils.Assertf(err == nil, "SetupBondWithSlaves[%s] error: %+v", bondName, err)
	} else {
		// IPv6-only or pure L2 bond scenario
		err = utils.CreateBondInterface(bondName, nic.BondMode)
		utils.Assertf(err == nil, "CreateBondInterface[%s] error: %+v", bondName, err)

		for _, slave := range slaves {
			err = utils.AddSlaveToBond(slave, bondName)
			utils.Assertf(err == nil, "AddSlaveToBond[%s, %s] error: %+v", slave, bondName, err)
		}
	}

	// 2. Configure IPv6 if present (support IPv4/IPv6 dual-stack)
	if nic.Ip6 != "" {
		// Flush old IPv6 addresses first to avoid stale entries when reconfiguring
		err = utils.Ip6AddrFlush(bondName)
		utils.Assertf(err == nil, "IpAddr6Flush[%s] error: %+v", bondName, err)

		ip6String := fmt.Sprintf("%s/%d", nic.Ip6, nic.PrefixLength)
		log.Debugf("bond [%s] add ipv6 address %s", bondName, ip6String)
		err = utils.IpAddrAdd(bondName, ip6String)
		utils.Assertf(err == nil, "IpAddrAdd[%s, %s] error: %+v", bondName, ip6String, err)
	}

	// 3. Ensure bond is up (calling "up" multiple times is harmless)
	bash := utils.Bash{
		Command: fmt.Sprintf("sudo ip link set %s up", bondName),
	}
	err = bash.Run()
	utils.Assertf(err == nil, "bring up bond %s error: %+v", bondName, err)

	// Set MTU if specified
	if nic.Mtu != 0 {
		if err := utils.IpLinkSetMTU(bondName, nic.Mtu); err != nil {
			log.Debugf("IpLinkSetMTU[%s, %d] error: %+v", bondName, nic.Mtu, err)
		}
	}

	// Configure default route if this is the default interface
	if nic.IsDefault {
		if utils.IsEuler2203() {
			err = utils.AddDefaultRouteEuler2203(nic.Gateway, nic.Gateway6, bondName)
			utils.PanicOnError(err)
		} else {
			if nic.Gateway != "" {
				routeEntry := utils.NewIpRoute().SetGW(nic.Gateway).SetDev(bondName).SetTable(utils.RT_TABLES_MAIN).SetProto(utils.RT_PROTOS_STATIC)
				err := utils.IpRouteAdd(routeEntry)
				utils.Assertf(err == nil, "IpRouteAdd[%+v] error: %+v", routeEntry, err)
			}
			if nic.Gateway6 != "" {
				route6Entry := utils.NewIpRoute().SetGW(nic.Gateway6).SetDev(bondName).SetTable(utils.RT_TABLES_MAIN).SetProto(utils.RT_PROTOS_STATIC)
				err := utils.IpRouteAdd(route6Entry)
				utils.Assertf(err == nil, "IpRouteAdd[%+v] error: %+v", route6Entry, err)
			}
		}
	}

	// Set alias for bond interface
	if nic.L2Type != "" {
		err := utils.IpLinkSetAlias(bondName, utils.MakeIfaceAlias(nic))
		utils.Assertf(err == nil, "IpLinkSetAlias[%s] error: %+v", bondName, err)
	}

	// Handle HA scenario
	if utils.GetHaStatus() != utils.NOHA && !utils.IsSLB() {
		err := utils.IpLinkSetDown(bondName)
		utils.Assertf(err == nil, "IpLinkSetDown[%s] error: %+v", bondName, err)
	}

	// Initialize firewall for bond interface
	if nic.Category == "Private" {
		err = utils.InitNicFirewall(bondName, nic.Ip, false, utils.IPTABLES_ACTION_REJECT)
	} else {
		err = utils.InitNicFirewall(bondName, nic.Ip, true, utils.IPTABLES_ACTION_REJECT)
	}
	if err != nil {
		log.Debugf("InitNicFirewall for bond: %s failed", err.Error())
	}

	// Add SNAT rule for private bond interface
	if nic.Category == "Private" {
		utils.AddSnatRuleForPrivateNic(bondName, nic.Ip, nic.Netmask)
	}

	log.Debugf("[configure: bond %s configured successfully]", bondName)
}

func configureNicInfo(nic *utils.NicInfo) {
	var err error
	// TODO ....
	//setNicTree.SetNicSmpAffinity(nic.name, "auto")

	// Handle bond scenario
	if nic.BondMode != "" && nic.BondMode != "none" {
		log.Debugf("[configure: bond interface %s with mode %s]", nic.Name, nic.BondMode)
		configureBondNic(nic)
		return
	}

	//set kernel arguments for specific nic
	err = os.WriteFile(fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/keep_addr_on_down", nic.Name), []byte("1"), 0644)
	if err != nil {
		log.Warningf("enable nic %s keep_addr_on_down failed: %s!", nic.Name, err)
	}

	err = os.WriteFile(fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/accept_dad", nic.Name), []byte("0"), 0644)
	if err != nil {
		log.Warningf("disable nic %s accept_dad failed: %s!", nic.Name, err)
	}

	utils.SetNicOption(nic.Name)
	err = utils.IpLinkSetUp(nic.Name)
	utils.Assertf(err == nil, "IpLinkSetUp[%s] error: %s", nic.Name, err)
	if nic.Ip != "" {
		log.Debugf("[flush-nic]")
		err := utils.Ip4AddrFlush(nic.Name)
		utils.Assertf(err == nil, "IpAddr4Flush[%s] error: %+v", nic.Name, err)
		log.Debugf("[flush-route]")
		err = utils.FlushNicRoute(nic.Name)
		utils.Assertf(err == nil, "Flush nic[%s] route error: %+v", nic.Name, err)
		log.Debugf("[getcidr]")
		cidr, err := utils.NetmaskToCIDR(nic.Netmask)
		utils.PanicOnError(err)
		ipString := fmt.Sprintf("%v/%v", nic.Ip, cidr)
		log.Debugf("[addip]")
		log.Debugf("nic [%s] add ipv4 address %s", nic.Name, ipString)
		err = utils.IpAddrAdd(nic.Name, ipString)
		utils.Assertf(err == nil, "IpAddrAdd[%s, %s] error: %+v", nic.Name, ipString, err)
	}
	if nic.Ip6 != "" {
		err := utils.Ip6AddrFlush(nic.Name)
		utils.Assertf(err == nil, "IpAddr6Flush[%s] error: %+v", nic.Name, err)
		ip6String := fmt.Sprintf("%s/%d", nic.Ip6, nic.PrefixLength)
		log.Debugf("nic [%s] add ipv6 address %s", nic.Name, ip6String)
		err = utils.IpAddrAdd(nic.Name, ip6String)
		utils.Assertf(err == nil, "IpAddrAdd[%s, %s] error: %+v", nic.Name, ip6String, err)
	}
	if nic.Mtu != 0 {
		if err := utils.IpLinkSetMTU(nic.Name, nic.Mtu); err != nil {
			log.Debugf("IpLinkSetMTU[%s, %d] error: %+v", nic.Name, nic.Mtu, err)
		}
	}
	if nic.IsDefault {
		if utils.IsEuler2203() {
			err = utils.AddDefaultRouteEuler2203(nic.Gateway, nic.Gateway6, nic.Name)
			utils.PanicOnError(err)
		} else {
			if nic.Gateway != "" {
				routeEntry := utils.NewIpRoute().SetGW(nic.Gateway).SetDev(nic.Name).SetTable(utils.RT_TABLES_MAIN).SetProto(utils.RT_PROTOS_STATIC)
				err := utils.IpRouteAdd(routeEntry)
				utils.Assertf(err == nil, "IpRouteAdd[%+v] error: %+v", routeEntry, err)
			}
			if nic.Gateway6 != "" {
				route6Entry := utils.NewIpRoute().SetGW(nic.Gateway6).SetDev(nic.Name).SetTable(utils.RT_TABLES_MAIN).SetProto(utils.RT_PROTOS_STATIC)
				err := utils.IpRouteAdd(route6Entry)
				utils.Assertf(err == nil, "IpRouteAdd[%+v] error: %+v", route6Entry, err)
			}
		}
	}
	if nic.L2Type != "" {
		err := utils.IpLinkSetAlias(nic.Name, utils.MakeIfaceAlias(nic))
		utils.Assertf(err == nil, "IpLinkSetAlias[%s] error: %+v", nic.Name, err)
	}
	if utils.GetHaStatus() != utils.NOHA && nic.Name != "eth0" && !utils.IsSLB() {
		err := utils.IpLinkSetDown(nic.Name)
		utils.Assertf(err == nil, "IpLinkSetDown[%s] error: %+v", nic.Name, err)
	}
	if nic.Name == "eth0" {
		mgmtNodeCidr := utils.BootstrapInfo["managementNodeCidr"]
		if mgmtNodeCidr != nil {
			mgmtNodeCidrStr := mgmtNodeCidr.(string)
			if utils.IsEuler2203() {
				_ = utils.AddRouteForMgmtEuler2203(mgmtNodeCidrStr, nic.Name, nic.Gateway)
			} else {
				nexthop, _ := utils.IpRouteGet(mgmtNodeCidrStr)
				if nexthop != nic.Gateway {
					defaultRoute := utils.NewIpRoute().SetDst(mgmtNodeCidrStr).SetGW(nic.Gateway)
					if err = utils.IpRouteAdd(defaultRoute); err != nil {
						log.Debugf("IpRouteAdd route entry[Dst:%s gateway:%s] error: %+v", mgmtNodeCidrStr, nic.Gateway, err)
					}
					utils.AddRoute(mgmtNodeCidrStr, nic.Gateway)
				}
			}
		}
	}

	if nic.Category == "Private" {
		err = utils.InitNicFirewall(nic.Name, nic.Ip, false, utils.IPTABLES_ACTION_REJECT)
	} else {
		err = utils.InitNicFirewall(nic.Name, nic.Ip, true, utils.IPTABLES_ACTION_REJECT)
	}
	if err != nil {
		log.Debugf("InitNicFirewall for nic: %s failed", err.Error())
	}

	if nic.Category == "Private" {
		utils.AddSnatRuleForPrivateNic(nic.Name, nic.Ip, nic.Netmask)
	}
}

func configureMgmtNic() {
	log.Debugf("[configure: interfaces[%s] ... ", mgmtNic.Name)

	configureNicInfo(mgmtNic)
}

func configureAdditionNic() {
	for name, nic := range nicsMap {
		if name != mgmtNic.Name {
			log.Debugf("[configure: interfaces[%s] ... ", name)
			configureNicInfo(nic)
		}
	}
}

func parseNicFromBootstrap() {
	log.Debugf("[configure: parse managenent nic info]")
	nicInfo := utils.BootstrapInfo["managementNic"].(map[string]interface{})
	if nicInfo == nil {
		panic(errors.New("no field 'managementNic' in bootstrap info"))
	}
	mgmtNic = parseNicInfo(nicInfo)
	nicsMap[mgmtNic.Name] = mgmtNic

	log.Debugf("[configure: parse additional nic info]")
	otherNics := utils.BootstrapInfo["additionalNics"].([]interface{})
	if otherNics != nil {
		for _, o := range otherNics {
			onic := o.(map[string]interface{})
			n := parseNicInfo(onic)
			nicsMap[n.Name] = n
		}
	}
}

func printBootStrapInfo() {
	SkipVyosIptables := utils.IsSkipVyosIptables()
	utils.Assert(SkipVyosIptables == true, "disable vyos cli has been set, but SkipVyosIptables is disable")
	applianceTypeTmp, found := utils.BootstrapInfo["applianceVmSubType"]
	if !found {
		applianceTypeTmp = "None"
	}
	applianceType := applianceTypeTmp.(string)

	log.Debugf("bootstrapInfo: %+v", utils.BootstrapInfo)
	log.Debugf("EnableVyosCli: %+v", utils.IsEnableVyosCmd())
	log.Debugf("SkipVyosIptables: %+v", SkipVyosIptables)
	log.Debugf("applianceType: %+v", applianceType)
}

func checkNicAddress() {
	log.Debugf("[configure: check nic's ip address]")
	haStatus := utils.NOHA
	if v, ok := utils.BootstrapInfo["haStatus"]; ok {
		haStatus = v.(string)
	}

	if strings.EqualFold(haStatus, utils.NOHA) {
		dupinfo := ""
		for _, nic := range nicsMap {
			if nic.Ip != "" && utils.CheckIpDuplicate(nic.Name, nic.Ip) {
				dupinfo = fmt.Sprintf("%s duplicate ip %s in nic %s\n", dupinfo, nic.Ip, nic.Mac)
			}
		}
		if !strings.EqualFold(dupinfo, "") {
			log.Error(dupinfo)
			err := utils.MkdirForFile(getNetworkHealthStatusPath(), 0755)
			utils.PanicOnError(err)
			err = ioutil.WriteFile(getNetworkHealthStatusPath(), []byte(dupinfo), 0755)
			utils.PanicOnError(err)
		}
	}

	for _, nic := range nicsMap {
		utils.Arping(nic.Name, nic.Ip, nic.Gateway)
	}
}

func configureHaScript() {
	log.Debugf("[configure: write default Ha script]")
	for _, nic := range nicsMap {
		if nic.IsDefault {
			defaultNic := utils.Nic{Name: nic.Name, Mac: nic.Mac, Ip: nic.Ip, Ip6: nic.Ip6,
				Gateway: nic.Gateway, Gateway6: nic.Gateway6}

			utils.WriteDefaultHaScript(&defaultNic)
		}
	}
}

func configureSystem() {
	if utils.IsVYOS() {
		resetVyos()
	}
	printBootStrapInfo()
	configureTimeZone()
	parseNicFromBootstrap()
	renameNic()
	configureMgmtNic()
	configurePassword()
	configureSshServer()
	configureAdditionNic()
	configureRadvdServer()
	configureSshMonitor()
	checkNicAddress()
	configureHaScript()
}
