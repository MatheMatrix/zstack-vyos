package plugin

import (
	"fmt"
	"regexp"
	"strings"

	"zstack-vyos/utils"

	log "github.com/sirupsen/logrus"
)

func configureNicByLinux(nicList []utils.NicInfo) interface{} {
	var nicname string
	for _, nic := range nicList {
		err := utils.Retry(func() error {
			var e error
			nicname, e = utils.GetNicNameByMac(nic.Mac)
			if e != nil {
				return e
			} else {
				return nil
			}
		}, 5, 1)
		utils.PanicOnError(err)
		utils.SetNicOption(nicname)
		/* avoid both master and backup interface up when add nic */
		if !IsMaster() && !utils.IsSLB() { /* slb don't need set interface down */
			log.Debugf("set interface %s down", nicname)
			err := utils.IpLinkSetDown(nicname)
			utils.Assertf(err == nil, "IpLinkSetDown[%s] error: %+v", nicname, err)
		} else {
			log.Debugf("set interface %s up", nicname)
			err := utils.IpLinkSetUp(nicname)
			utils.Assertf(err == nil, "IpLinkSetUp[%s] error: %+v", nicname, err)
			checkNicIsUp(nicname, true)
		}

		if nic.Ip != "" {
			err := utils.Ip4AddrFlush(nicname)
			utils.Assertf(err == nil, "IpAddr4Flush[%s] error: %+v", nicname, err)
			cidr, err := utils.NetmaskToCIDR(nic.Netmask)
			utils.PanicOnError(err)
			ipString := fmt.Sprintf("%v/%v", nic.Ip, cidr)
			log.Debugf("nic [%s] add ipv4 address %s", nicname, ipString)
			err = utils.IpAddrAdd(nicname, ipString)
			utils.Assertf(err == nil, "IpAddrAdd[%s, %s] error: %+v", nicname, ipString, err)
		}
		if nic.Ip6 != "" {
			err := utils.Ip6AddrFlush(nicname)
			utils.Assertf(err == nil, "IpAddr6Flush[%s] error: %+v", nicname, err)
			ip6String := fmt.Sprintf("%s/%d", nic.Ip6, nic.PrefixLength)
			log.Debugf("nic [%s] add ipv6 address %s", nicname, ip6String)
			err = utils.IpAddrAdd(nicname, ip6String)
			utils.Assertf(err == nil, "IpAddrAdd[%s, %s] error: %+v", nicname, ip6String, err)
		}
		mtu := 1500
		if nic.Mtu != 0 {
			mtu = nic.Mtu
		}
		if err := utils.IpLinkSetMTU(nicname, mtu); err != nil {
			log.Debugf("IpLinkSetMTU[%s, %d] error: %+v", nicname, mtu, err)
		}

		if nic.L2Type != "" {
			err := utils.IpLinkSetAlias(nicname, utils.MakeIfaceAlias(&nic))
			utils.Assertf(err == nil, "IpLinkSetAlias[%s] error: %+v", nicname, err)
		}
	}

	return nil
}

func configureNicDefaultActionByLinux(cmd *ConfigureNicCmd) interface{} {
	var nicname string
	for _, nic := range cmd.Nics {
		err := utils.Retry(func() error {
			var e error
			nicname, e = utils.GetNicNameByMac(nic.Mac)
			if e != nil {
				return e
			} else {
				return nil
			}
		}, 5, 1)
		utils.PanicOnError(err)

		err = utils.SetNicDefaultFirewallRule(nicname, nic.FirewallDefaultAction)
		utils.PanicOnError(err)
	}

	return nil
}

func changeDefaultNicByLinux(cmd *ChangeDefaultNicCmd) interface{} {
	pubNic, err := utils.GetNicNameByMac(cmd.NewNic.Mac)
	utils.PanicOnError(err)

	if utils.IsEuler2203() {
		nicName, _ := utils.GetNicNameByIp(cmd.NewNic.Ip)
		err = utils.AddDefaultRouteEuler2203(cmd.NewNic.Gateway, cmd.NewNic.Gateway6, nicName)
		return err
	} else {
		if cmd.NewNic.Gateway != "" {
			err := utils.Ip4RouteDelDefault(utils.RT_TABLES_MAIN)
			utils.Assertf(err == nil, "IpRoute4DelDefault[] error: %+v", err)
			routeEntry := utils.NewIpRoute().SetGW(cmd.NewNic.Gateway).SetDev(pubNic).SetProto(utils.RT_PROTOS_STATIC).SetTable(utils.RT_TABLES_MAIN)
			err = utils.IpRouteAdd(routeEntry)
			utils.Assertf(err == nil, "IpRouteAdd[%+v] error: %+v", routeEntry, err)
		}
		if cmd.NewNic.Gateway6 != "" {
			err := utils.Ip6RouteDelDefault(utils.RT_TABLES_MAIN)
			utils.Assertf(err == nil, "IpRoute6DelDefault[] error: %+v", err)
			routeEntry := utils.NewIpRoute().SetGW(cmd.NewNic.Gateway6).SetDev(pubNic).SetProto(utils.RT_PROTOS_STATIC).SetTable(utils.RT_TABLES_MAIN)
			err = utils.IpRouteAdd(routeEntry)
			utils.Assertf(err == nil, "IpRouteAdd[%+v] error: %+v", routeEntry, err)
		}
	}

	defaultNic := &utils.Nic{Name: pubNic, Gateway: cmd.NewNic.Gateway, Gateway6: cmd.NewNic.Gateway6, Mac: cmd.NewNic.Mac,
		Ip: cmd.NewNic.Ip, Ip6: cmd.NewNic.Ip6}
	if utils.IsHaEnabled() {
		utils.WriteDefaultHaScript(defaultNic)
	}

	return nil
}

func setVipByLinux(cmd *setVipCmd) interface{} {
	if cmd.SyncVip {
		for _, nicIp := range cmd.NicIps {
			nicname, err := utils.GetNicNameByMac(nicIp.OwnerEthernetMac)
			utils.PanicOnError(err)
			linuxNicIps, err := utils.IpAddrShow(nicname)
			utils.PanicOnError(err)
			cidr, err := utils.NetmaskToCIDR(nicIp.Netmask)
			utils.PanicOnError(err)
			addr := fmt.Sprintf("%v/%v", nicIp.Ip, cidr)

			if len(linuxNicIps) == 0 || linuxNicIps[0] != addr {
				/* nicIp is not the first ip, reconfigured linux nic */
				if len(linuxNicIps) > 0 {
					for _, linuxIp := range linuxNicIps {
						err := utils.IpAddrDel(nicname, linuxIp)
						utils.PanicOnError(err)
					}
					err := utils.IpAddrAdd(nicname, addr)
					utils.PanicOnError(err)
				}
			}
		}
	}

	if !utils.IsHaEnabled() {
		for _, vip := range cmd.Vips {
			nicname, err := utils.GetNicNameByMac(vip.OwnerEthernetMac)
			utils.PanicOnError(err)
			addr, _ := vip.GetIpWithCidr()
			err = utils.IpAddrAdd(nicname, addr)
			utils.PanicOnError(err)
		}
	} else {
		for _, vip := range cmd.Vips {
			nicname, err := utils.GetNicNameByMac(vip.OwnerEthernetMac)
			utils.PanicOnError(err)
			addr, _ := vip.GetIpWithCidr()

			/* vip on mgt nic will not configure in vyos config */
			if vip.Ip != "" && utils.IsInManagementCidr(vip.Ip) {
				if IsMaster() {
					err := utils.IpAddrAdd(nicname, addr)
					utils.PanicOnError(err)
				}
			} else {
				err := utils.IpAddrAdd(nicname, addr)
				utils.PanicOnError(err)
			}
		}
	}

	if utils.IsConfigTcForVipQos() {
		for _, vip := range cmd.Vips {
			publicInterface, err := utils.GetNicNameByMac(vip.OwnerEthernetMac)
			utils.PanicOnError(err)
			ip := vip.GetIpWithOutCidr()
			ingressrule := newQosRule(ip, 0, MAX_BINDWIDTH, vip.VipUuid)
			if biRule, ok := totalQosRules[publicInterface]; ok {
				if biRule[INGRESS].InterfaceQosRuleFind(ingressrule) == nil {
					addQosRule(publicInterface, INGRESS, ingressrule)
				}
			} else {
				addQosRule(publicInterface, INGRESS, ingressrule)
			}

			egressrule := newQosRule(ip, 0, MAX_BINDWIDTH, vip.VipUuid)
			if biRule, ok := totalQosRules[publicInterface]; ok {
				if biRule[EGRESS].InterfaceQosRuleFind(egressrule) == nil {
					addQosRule(publicInterface, EGRESS, egressrule)
				}
			} else {
				addQosRule(publicInterface, EGRESS, egressrule)
			}
		}
	}

	vyosVips := []nicVipPair{}
	for _, vip := range cmd.Vips {
		nicname, err := utils.GetNicNameByMac(vip.OwnerEthernetMac)
		utils.PanicOnError(err)
		ip := vip.GetIpWithOutCidr()
		_, cidr := vip.GetIpWithCidr()
		if utils.IsIpv4Address(ip) {
			vyosVips = append(vyosVips, nicVipPair{NicName: nicname, Vip: ip, Prefix: cidr})
		} else {
			vyosVips = append(vyosVips, nicVipPair{NicName: nicname, Vip6: ip, Prefix: cidr})
		}
	}

	if utils.IsHaEnabled() {
		addHaNicVipPair(vyosVips, false)
	}

	/* this is for debug, will be deleted */
	bash := utils.Bash{
		Command: fmt.Sprintf("ip add"),
	}
	bash.Run()

	go sendGARP(cmd)

	return nil
}

func removeVipByLinux(cmd *removeVipCmd) interface{} {
	for _, vip := range cmd.Vips {
		nicname, err := utils.GetNicNameByMac(vip.OwnerEthernetMac)
		utils.PanicOnError(err)
		addr, _ := vip.GetIpWithCidr()
		if err = utils.IpAddrDel(nicname, addr); err != nil {
			return fmt.Errorf("IpAddrDel[%s, %s] error: %v", nicname, addr, err)
		}
		deleteQosRulesOfVip(nicname, vip.Ip)
	}

	vyosVips := []nicVipPair{}
	for _, vip := range cmd.Vips {
		nicname, err := utils.GetNicNameByMac(vip.OwnerEthernetMac)
		utils.PanicOnError(err)
		_, cidr := vip.GetIpWithCidr()
		ip := vip.GetIpWithOutCidr()

		vyosVips = append(vyosVips, nicVipPair{NicName: nicname, Vip: ip, Prefix: cidr})
	}
	removeHaNicVipPair(vyosVips)

	/* this is for debug, will be deleted */
	bash := utils.Bash{
		Command: fmt.Sprintf("ip add"),
	}
	bash.Run()

	return nil
}

func SetZebraRoutes(infos []RouteInfo) {
	var (
		newEntry  *utils.ZebraRoute
		newRoutes []*utils.ZebraRoute
		oldRoutes []*utils.ZebraRoute
		err       error
	)

	changeDefaultRoute := false
	for _, info := range infos {
		if info.Destination == "0.0.0.0/0" {
			changeDefaultRoute = true
		}
	}

	changeDefaultRoute6 := false
	for _, info := range infos {
		if info.Destination == "::/0" {
			changeDefaultRoute6 = true
		}
	}

	// 1. get old routes by load json
	if utils.IsEuler2203() {
		routes := utils.GetCurrentRouteEntriesEuler2203(utils.ROUTETABLE_ID_MAIN)
		log.Debugf("old routes: %+v", routes)
		for _, route := range routes {
			zr := utils.ZebraRoute{
				Dst:      route.DestinationCidr,
				NextHop:  route.NextHopIp,
				OutDev:   route.NicName,
				Distance: route.Distance,
			}
			if zr.OutDev == "Null0" {
				zr.NextHop = ""
				zr.OutDev = ""
			}
			oldRoutes = append(oldRoutes, &zr)
		}
	} else {
		if err = utils.JsonLoadConfig(utils.GetZebraJsonFile(), &oldRoutes); err != nil {
			log.Debugf("load old zebra route error: %+v", err)
		}
	}

	// 2. delete old entry that is not in new routes
	for _, old := range oldRoutes {
		found := false
		for _, new := range infos {
			if new.Destination != old.Dst {
				continue
			}

			if new.Target != old.NextHop {
				continue
			}

			found = true
			break
		}

		if !found {
			if isManagementNodeRoute(old.Dst) {
				newRoutes = append(newRoutes, old)
				continue
			}

			if routes, retained := retainUnchangedDefaultRoute(newRoutes, old, changeDefaultRoute, changeDefaultRoute6); retained {
				// mn don't want to change default
				newRoutes = routes
				continue
			}

			if old.NextHop == "" {
				old.NextHop = "Null0"
			}
			if err = old.SetDelete().Apply(); err != nil {
				log.Debugf("delete old route entry[%+v] error: %+v", old, err)
			}
		}
	}

	// 3. apply new entry by vtysh
	for _, r := range infos {
		isDuplicate := false
		for _, old := range oldRoutes {
			if old.Dst == r.Destination &&
				((r.Target == "" && (old.NextHop == "" || old.NextHop == "Null0")) ||
					(r.Target == old.NextHop)) &&
				old.Distance == r.Distance {
				isDuplicate = true
				newRoutes = append(newRoutes, old)
				break
			}
		}

		if isDuplicate {
			log.Debugf("skip duplicate route: %+v", r)
			continue
		}

		if r.Target == "" {
			newEntry = utils.NewZebraRoute().SetDst(r.Destination).SetDistance(r.Distance).SetNextHop(utils.BLACKHOLE_ROUTE)
		} else {
			newEntry = utils.NewZebraRoute().SetDst(r.Destination).SetNextHop(r.Target).SetDistance(r.Distance)
		}

		if err = newEntry.Apply(); err != nil {
			log.Debugf("apply route[%+v] error: %+v", r, err)
			if !strings.Contains(err.Error(), "File exists") {
				utils.PanicOnError(err)
			}
		}

		newRoutes = append(newRoutes, newEntry)
	}

	// 4. store new routes
	if !utils.IsEuler2203() {
		if err = utils.JsonStoreConfig(utils.GetZebraJsonFile(), newRoutes); err != nil {
			log.Debugf("load old zebra route error: %+v", err)
		}
	}
}

func retainUnchangedDefaultRoute(routes []*utils.ZebraRoute, old *utils.ZebraRoute, changeDefaultRoute, changeDefaultRoute6 bool) ([]*utils.ZebraRoute, bool) {
	if (old.Dst == "0.0.0.0/0" && !changeDefaultRoute) ||
		(old.Dst == "::/0" && !changeDefaultRoute6) {
		return append(routes, old), true
	}

	return routes, false
}

func parseOspfToVtyshCmd(cmd *setOspfCmd) (*utils.VtyshOspfCmd, error) {
	v := utils.NewVtyshOspfCmd().SetRouteId(cmd.RouterId)
	for _, area := range cmd.AreaInfos {
		v.SetArea(area.AreaId, string(area.AreaType), string(area.AuthType))
	}
	for _, net := range cmd.NetworkInfos {
		v.AddNetwork(net.Network, net.AreaId)
		nicName, err := utils.GetNicNameByMac(net.NicMac)
		if err != nil {
			return nil, err
		}
		for _, area := range cmd.AreaInfos {
			if area.AreaId == net.AreaId {
				v.SetInterface(nicName, string(area.AuthType), area.AuthParam)
			}
		}
	}
	return v, nil
}

func configureOspfByVtysh(cmd *setOspfCmd) {
	var (
		oldCmd *utils.VtyshOspfCmd
		newCmd *utils.VtyshOspfCmd
		err    error
	)

	// 1. get old ospf cmd
	oldCmd, err = getCurrentOspfConfig()
	utils.PanicOnError(err)

	// 2. get new ospf cmd
	newCmd, err = parseOspfToVtyshCmd(cmd)
	utils.PanicOnError(err)

	if isOspfConfigEqual(oldCmd, newCmd) {
		log.Debugf("ospf config is equal")
		return
	}

	// 3. delete the same cmd in new and old
	oldCmd.SetDelete()

	// 4. delete old cmd, and apply new cmd
	log.Debugf("vtysh-ospf: start delete all old ospf config[%+v]", oldCmd)
	err = oldCmd.Apply()
	utils.PanicOnError(err)

	log.Debugf("vtysh-ospf: start apply new ospf config[%+v]", newCmd)
	err = newCmd.Apply()
	utils.PanicOnError(err)

}

func getCurrentOspfConfig() (*utils.VtyshOspfCmd, error) {

	bash := utils.Bash{
		Command: fmt.Sprintf("vtysh -c 'show running-config'"),
	}
	ret, output, _, err := bash.RunWithReturn()
	if err != nil {
		return nil, fmt.Errorf("execute vtysh command failed: %v", err)
	}
	if ret != 0 {
		return nil, fmt.Errorf("vtysh command returned non-zero: %d", ret)
	}

	return parseRunningOspfConfig([]byte(output))
}

// this func is Parse the current configuration for return comparison
func parseRunningOspfConfig(output []byte) (*utils.VtyshOspfCmd, error) {

	var (
		v     = utils.NewVtyshOspfCmd()
		lines = strings.Split(string(output), "\n")

		inOspfSection      bool
		inInterfaceSection bool
		currentInterface   string

		routerIdRegex  = regexp.MustCompile(`ospf router-id ([0-9.]+)`)
		networkRegex   = regexp.MustCompile(`network ([0-9./]+) area ([0-9.]+)`)
		areaAuthRegex  = regexp.MustCompile(`area ([0-9.]+) authentication( message-digest)?`)
		areaStubRegex  = regexp.MustCompile(`area ([0-9.]+) stub`)
		interfaceRegex = regexp.MustCompile(`interface (.+)`)
		authRegex      = regexp.MustCompile(`ip ospf authentication( message-digest)?`)
		authKeyRegex   = regexp.MustCompile(`ip ospf authentication-key (.+)`)
		md5KeyRegex    = regexp.MustCompile(`ip ospf message-digest-key (\d+) md5 (.+)`)

		stubAreas = make(map[string]bool)
	)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if matches := areaStubRegex.FindStringSubmatch(line); len(matches) > 1 {
			stubAreas[matches[1]] = true
			v.SetArea(matches[1], "Stub", string(None))
		} else if netmatches := networkRegex.FindStringSubmatch(line); len(netmatches) > 1 {
			v.SetArea(netmatches[2], "Standard", string(None))
		}
	}

	if len(output) == 0 {
		return nil, fmt.Errorf("empty configuration output")
	}
	//parse the configuration line by line
	for _, line := range lines {
		line = strings.TrimSpace(line)

		//determine whether to enter the corresponding position
		if strings.Contains(line, "router ospf") {
			inOspfSection = true
			inInterfaceSection = false
			continue
		}

		if matches := interfaceRegex.FindStringSubmatch(line); len(matches) > 1 {
			inOspfSection = false
			inInterfaceSection = true
			currentInterface = matches[1]
			continue
		}

		if line == "exit" || line == "!" {
			inOspfSection = false
			inInterfaceSection = false
			continue
		}

		// parse configuration
		if inOspfSection {
			if matches := routerIdRegex.FindStringSubmatch(line); len(matches) > 1 {
				v.SetRouteId(matches[1])
			}

			if matches := networkRegex.FindStringSubmatch(line); len(matches) > 1 {
				v.AddNetwork(matches[1], matches[2])
			}

			if matches := areaAuthRegex.FindStringSubmatch(line); len(matches) > 1 {
				authType := "Plaintext"
				if len(matches) > 2 && matches[2] != "" {
					authType = "MD5"
				}
				areaType := ""
				if stubAreas[matches[1]] {
					areaType = "Stub"
				}
				v.SetArea(matches[1], areaType, authType)
			}
		}

		if inInterfaceSection {
			if matches := authRegex.FindStringSubmatch(line); len(matches) > 0 {
				authType := "Plaintext"
				if len(matches) > 1 && matches[1] != "" {
					authType = "MD5"
				}
				v.SetInterface(currentInterface, authType, "1/1")
			}

			if matches := authKeyRegex.FindStringSubmatch(line); len(matches) > 1 {
				v.SetInterface(currentInterface, "Plaintext", matches[1])
			}

			if matches := md5KeyRegex.FindStringSubmatch(line); len(matches) > 2 {
				keyId := matches[1]
				password := matches[2]
				v.SetInterface(currentInterface, "MD5", fmt.Sprintf("%s/%s", keyId, password))
			}
		}
	}

	return v, nil
}

func isOspfConfigEqual(old, new *utils.VtyshOspfCmd) bool {
	if old == nil && new == nil {
		return true
	}

	if old == nil || new == nil {
		return false
	}

	// Compare Network config
	if len(old.NetworkCmd) != len(new.NetworkCmd) {
		return false
	}
	newNetworkMatched := make([]bool, len(new.NetworkCmd))

	for _, oldNetwork := range old.NetworkCmd {
		found := false
		for j, newNetwork := range new.NetworkCmd {
			if !newNetworkMatched[j] && oldNetwork == newNetwork {
				newNetworkMatched[j] = true
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	for _, matched := range newNetworkMatched {
		if !matched {
			return false
		}
	}

	// Compare Area
	if len(old.AreaCmd) != len(new.AreaCmd) {
		return false
	}
	for k, oldArea := range old.AreaCmd {
		if newArea, exists := new.AreaCmd[k]; !exists || oldArea != newArea {
			return false
		}
	}

	// Compare interface config
	if len(old.IfaceCmd) == 0 {
		// If old.IfaceCmd is None, check whether all configurations of new.IfaceCmd are None.
		allNone := true
		for _, newIface := range new.IfaceCmd {
			if newIface.Auth != "None" {
				allNone = false
				break
			}
		}
		if allNone {
			log.Debugf("all configurations of new.IfaceCmd are None")
			return true
		}
	}

	if len(old.IfaceCmd) != len(new.IfaceCmd) {
		return false
	}
	for k, oldIface := range old.IfaceCmd {
		if newIface, exists := new.IfaceCmd[k]; !exists || oldIface != newIface {
			return false
		}
	}

	return true
}

func configurePimdByVtysh(cmd *enablePimdCmd) error {

	var (
		oldCmd *utils.VtyshPimdCmd
		newCmd *utils.VtyshPimdCmd
		err    error
	)

	// 1. get current config
	oldCmd, err = getCurrentPimdConfig()
	if err != nil {
		return err
	}

	// 2. create new config
	newCmd = utils.NewVtyshPimdCmd()

	// add interface config
	nics, err := utils.GetAllNics()
	if err != nil {
		return err
	}
	for _, nic := range nics {
		newCmd.SetInterface(nic.Name)
	}

	// add RP config
	for _, rp := range cmd.Rps {
		newCmd.SetRp(rp.RpAddress, rp.GroupAddress)
	}

	if isPimdConfigEqual(oldCmd, newCmd) {
		return nil
	}

	// 3. delete same config
	for k, new := range newCmd.InterfaceCmd {
		if old, ok := oldCmd.InterfaceCmd[k]; ok && new == old {
			newCmd.DeleteInterface(k)
			oldCmd.DeleteInterface(k)
		}
	}

	for k, new := range newCmd.RpCmd {
		if old, ok := oldCmd.RpCmd[k]; ok && new == old {
			newCmd.DeleteRp(new.RpAddress, new.GroupAddress)
			oldCmd.DeleteRp(old.RpAddress, old.GroupAddress)
		}
	}

	// 4. apply config
	log.Debugf("vtysh-pimd: start delete pimd cmd[%+v]", oldCmd)
	oldCmd.SetDelete()
	err = oldCmd.Apply()
	if err != nil {
		return err
	}

	log.Debugf("vtysh-pimd: start apply pimd cmd[%+v]", newCmd)
	err = newCmd.Apply()
	if err != nil {
		return err
	}

	return nil
}

func getCurrentPimdConfig() (*utils.VtyshPimdCmd, error) {
	bash := utils.Bash{
		Command: fmt.Sprintf("vtysh -c 'show running-config'"),
	}
	ret, output, _, err := bash.RunWithReturn()
	if err != nil {
		return nil, fmt.Errorf("execute vtysh command failed: %v", err)
	}
	if ret != 0 {
		return nil, fmt.Errorf("vtysh command returned non-zero: %d", ret)
	}

	return parseRunningPimdConfig([]byte(output))
}

func parseRunningPimdConfig(output []byte) (*utils.VtyshPimdCmd, error) {
	var (
		v     = utils.NewVtyshPimdCmd()
		lines = strings.Split(string(output), "\n")

		inInterfaceSection bool
		currentInterface   string

		interfaceRegex = regexp.MustCompile(`interface (.+)`)
		rpRegex        = regexp.MustCompile(`ip pim rp ([0-9.]+) ([0-9./]+)`)
		pimRegex       = regexp.MustCompile(`ip pim`)
		igmpRegex      = regexp.MustCompile(`ip igmp`)
	)

	if len(output) == 0 {
		return nil, fmt.Errorf("empty configuration output")
	}

	// parse the configuration line by line
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// determine whether to enter the corresponding position
		if matches := interfaceRegex.FindStringSubmatch(line); len(matches) > 1 {
			inInterfaceSection = true
			currentInterface = matches[1]
			continue
		}

		// ! is end
		if strings.HasPrefix(line, "!") {
			inInterfaceSection = false
			continue
		}

		// parse interface config
		if inInterfaceSection {
			if pimRegex.MatchString(line) && igmpRegex.MatchString(line) {
				v.SetInterface(currentInterface)
			}
			continue
		}

		// parse PR config
		if matches := rpRegex.FindStringSubmatch(line); len(matches) > 1 {
			v.SetRp(matches[1], matches[2])
		}
	}

	return v, nil
}

func stopVtyshPimd() error {

	deleteCmd := utils.NewVtyshPimdCmd()
	deleteCmd.SetDelete()

	// 1. get current config and delete
	currentCmd, err := getCurrentPimdConfig()
	if err != nil {
		return fmt.Errorf("failed to get current PIMD config: %v", err)
	}

	for _, rp := range currentCmd.RpCmd {
		deleteCmd.SetRp(rp.RpAddress, rp.GroupAddress)
	}

	// 2. get all nics and delete
	nics, err := utils.GetAllNics()
	if err != nil {
		return fmt.Errorf("failed to get network interfaces: %v", err)
	}

	for _, nic := range nics {
		deleteCmd.SetInterface(nic.Name)
	}

	// 3. no match return
	if len(deleteCmd.InterfaceCmd) == 0 && len(deleteCmd.RpCmd) == 0 {
		log.Debug("No PIMD configuration to remove")
		return nil
	}

	// 4. Apply deletecmd
	log.Debugf("Removing PIMD configuration: %+v", deleteCmd)
	if err := deleteCmd.Apply(); err != nil {
		return fmt.Errorf("failed to remove PIMD configuration: %v", err)
	}

	return nil
}

func isPimdConfigEqual(old, new *utils.VtyshPimdCmd) bool {

	if old == nil && new == nil {
		return true
	}

	if old == nil || new == nil {
		return false
	}

	// compare Rp config
	if len(old.RpCmd) != len(new.RpCmd) {
		return false
	}
	oldRps := make(map[string]struct{})
	for _, rp := range old.RpCmd {
		key := fmt.Sprintf("%s-%s", rp.RpAddress, rp.GroupAddress)
		oldRps[key] = struct{}{}
	}
	for _, rp := range new.RpCmd {
		key := fmt.Sprintf("%s-%s", rp.RpAddress, rp.GroupAddress)
		if _, exists := oldRps[key]; !exists {
			return false
		}
	}

	// Compare interface config
	if len(old.InterfaceCmd) != len(new.InterfaceCmd) {
		return false
	}
	oldIfaces := make(map[string]struct{})
	for _, iface := range old.InterfaceCmd {
		oldIfaces[iface.Name] = struct{}{}
	}
	for _, iface := range new.InterfaceCmd {
		if _, exists := oldIfaces[iface.Name]; !exists {
			return false
		}
	}

	return true
}
