package utils

import (
	"encoding/json"
	"fmt"
	"net"
	neturl "net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

const (
	ZSTACK_ROUTE_PROTO            = "zstack"
	ZSTACK_ROUTE_PROTO_IDENTIFFER = "201"
	ZVR_ROUTE_PROTO               = "zvr"
	ZVR_ROUTE_PROTO_IDENTIFFER    = 202
)

func NetmaskToCIDR(netmask string) (int, error) {
	if strings.Contains(netmask, ".") {
		ipv4Mask := net.IPMask(net.ParseIP(netmask).To4())
		return calculateMaskLength(ipv4Mask), nil
	}

	if prefix, err := strconv.Atoi(netmask); err == nil {
		return prefix, nil
	}

	ipv6MaskIp := net.ParseIP(netmask)
	if ipv6MaskIp == nil {
		return 0, fmt.Errorf("invalid netmask %s", netmask)
	}
	ipv6Mask := net.IPMask(ipv6MaskIp.To16())
	return calculateMaskLength(ipv6Mask), nil
}

func calculateMaskLength(mask net.IPMask) int {
	maskBytes := []byte(mask)
	length := 0

	for _, byteValue := range maskBytes {
		for i := 7; i >= 0; i-- {
			if (byteValue>>i)&1 == 1 {
				length++
			}
		}
	}

	return length
}

func GetNetworkNumber(ip, netmask string) (string, error) {
	ips := strings.Split(ip, ".")
	masks := strings.Split(netmask, ".")

	ipInByte := make([]interface{}, 4)
	for i := 0; i < len(ips); i++ {
		p, err := strconv.ParseUint(ips[i], 10, 32)
		if err != nil {
			return "", errors.Wrap(err, fmt.Sprintf("unable to get network number[ip:%v, netmask:%v]", ip, netmask))
		}
		m, err := strconv.ParseUint(masks[i], 10, 32)
		PanicOnError(err)
		if err != nil {
			return "", errors.Wrap(err, fmt.Sprintf("unable to get network number[ip:%v, netmask:%v]", ip, netmask))
		}
		ipInByte[i] = p & m
	}

	cidr, err := NetmaskToCIDR(netmask)
	if err != nil {
		return "", errors.Wrap(err, fmt.Sprintf("unable to get network number[ip:%v, netmask:%v]", ip, netmask))
	}

	return fmt.Sprintf("%v.%v.%v.%v/%v", ipInByte[0], ipInByte[1], ipInByte[2], ipInByte[3], cidr), nil
}

type Nic struct {
	Name         string
	Mac          string
	Ip           string
	Ip6          string
	Gateway      string
	Gateway6     string
	IsDefault    bool
	Catatory     string
	Netmask      string
	PrefixLength int
}

func (nic Nic) String() string {
	s, _ := json.Marshal(nic)
	return string(s)
}

type nicArray []Nic

func (a nicArray) Len() int           { return len(a) }
func (a nicArray) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a nicArray) Less(i, j int) bool { return a[i].Name > a[j].Name }

func GetAllNics() (map[string]Nic, error) {
	const ROOT = "/sys/class/net"

	files, err := os.ReadDir(ROOT)
	if err != nil {
		return nil, err
	}

	nics := make(map[string]Nic)
	for _, f := range files {
		if f.Name() == "lo" || strings.Contains(f.Name(), "ifb") {
			continue
		}

		// Skip special sysfs entries such as bonding_masters that are files, not NICs
		entryPath := filepath.Join(ROOT, f.Name())
		info, err := os.Stat(entryPath)
		if err != nil {
			log.Debugf("skip sysfs entry %s: %v", entryPath, err)
			continue
		}
		if !info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
			continue
		}

		if f.Name() == "gre0" || f.Name() == "pimreg" || f.Name() == "mgmt" || strings.Contains(f.Name(), "ipsec") {
			continue
		}

		macfile := filepath.Join(entryPath, "address")
		mac, err := os.ReadFile(macfile)
		if err != nil {
			if os.IsNotExist(err) {
				log.Debugf("skip NIC %s without address file", f.Name())
				continue
			}
			return nil, errors.Wrap(err, fmt.Sprintf("unable to read the mac file[%s]", macfile))
		}
		nics[f.Name()] = Nic{
			Name: strings.TrimSpace(f.Name()),
			Mac:  strings.TrimSpace(string(mac)),
		}
	}

	return nics, nil
}

func GetNicNameByMac(mac string) (string, error) {
	nics, err := GetAllNics()
	if err != nil {
		return "", err
	}

	var matchedNics []string
	for _, nic := range nics {
		if nic.Mac == mac {
			name := strings.Split(nic.Name, ".")[0]
			matchedNics = append(matchedNics, name)
		}
	}

	if len(matchedNics) == 0 {
		return "", fmt.Errorf("cannot find any nic with the mac[%s]", mac)
	}

	// If multiple NICs found with same MAC, prefer non-phy interface
	// This handles bond scenario where eth1-phy1, eth1-phy2 exist, but we want eth1
	for _, name := range matchedNics {
		if !strings.Contains(name, "-phy") {
			return name, nil
		}
	}

	// Fallback: return first match
	return matchedNics[0], nil
}

// GetAllNicNamesByMac returns all NIC names with the same MAC address
// This is used for bond scenarios where two NICs share the same MAC
func GetAllNicNamesByMac(mac string) ([]string, error) {
	nics, err := GetAllNics()
	if err != nil {
		return nil, err
	}

	var nicNames []string
	for _, nic := range nics {
		if nic.Mac == mac {
			/* for vlan sub interface, nic.name is eth1.100 */
			name := strings.Split(nic.Name, ".")
			nicNames = append(nicNames, name[0])
		}
	}

	if len(nicNames) == 0 {
		return nil, fmt.Errorf("cannot find any nic with the mac[%s]", mac)
	}

	return nicNames, nil
}

func GetMacByNicName(nicName string) (string, error) {
	nics, err := GetAllNics()
	if err != nil {
		return "", err
	}

	for _, nic := range nics {
		if nic.Name == nicName {
			return nic.Mac, nil
		}
	}

	return "", fmt.Errorf("cannot find any mac with the nicName[%s]", nicName)
}

func GetNicNameByIp(ip string) (string, error) {
	bash := Bash{
		Command: fmt.Sprintf("ip addr | grep -w %s", ip),
	}
	ret, o, _, err := bash.RunWithReturn()
	if err != nil {
		return "", err
	}
	if ret != 0 {
		return "", errors.New(fmt.Sprintf("no nic with the IP[%s] found in the system", ip))
	}

	o = strings.TrimSpace(o)
	os := strings.Split(o, " ")
	return os[len(os)-1], nil
}

func GetIpByNicName(nic string) (string, error) {
	bash := Bash{
		Command: fmt.Sprintf("ip -o -f inet addr show %s | awk '/scope global/ {print $4}'", nic),
	}
	ret, o, _, err := bash.RunWithReturn()
	if err != nil {
		return "", err
	}
	if ret != 0 {
		return "", errors.New(fmt.Sprintf("no ip with the nic[%s] found in the system", nic))
	}

	o = strings.TrimSpace(o)
	os := strings.Split(o, "/")
	return os[0], nil
}

func GetIpFromUrl(rawUrl string) (string, error) {
	parsedUrl, err := neturl.Parse(rawUrl)
	if err != nil {
		return "", err
	}

	return parsedUrl.Hostname(), nil
}

func CheckIpDuplicate(nicname, ip string) bool {
	b := Bash{Command: fmt.Sprintf("sudo arping -D -w 2 -c 1 -I %s %s", nicname, ip)}
	err := b.Run()
	return err != nil
}

func CheckZStackRouteExists(ip string) bool {
	route := routeCidr(ip)
	bash := Bash{
		Command: fmt.Sprintf("%s list %s proto zstack", ipRouteCommand(ip), route),
	}
	_, o, _, _ := bash.RunWithReturn()
	if o == "" {
		return false
	}
	return true
}

func DeleteRouteIfExists(ip string) error {
	if CheckZStackRouteExists(ip) == true {
		route := routeCidr(ip)
		bash := Bash{
			Command: fmt.Sprintf("sudo %s del %s", ipRouteCommand(ip), route),
		}
		if IsEuler2203() {
			bash = Bash{
				Command: fmt.Sprintf("sudo vtysh -c 'configure terminal' -c 'no %s %s'", frrRouteCommand(ip), route),
			}
		}
		_, _, _, err := bash.RunWithReturn()
		if err != nil {
			return err
		}
	}

	return nil
}

func SetZStackRoute(ip string, nic string, gw string) error {
	SetZStackRouteProtoIdentifier()
	SetZvrRouteProtoIdentifier()
	DeleteRouteIfExists(ip)

	var bash Bash
	route := routeCidr(ip)
	if gw == "" {
		bash = Bash{
			Command: fmt.Sprintf("sudo %s add %s dev %s proto %s", ipRouteCommand(ip), route, nic, ZSTACK_ROUTE_PROTO),
		}
	} else {
		bash = Bash{
			Command: fmt.Sprintf("sudo %s add %s via %s dev %s proto %s", ipRouteCommand(ip), route, gw, nic, ZSTACK_ROUTE_PROTO),
		}
	}

	ret, _, _, err := bash.RunWithReturn()
	if err != nil {
		return err
	}
	// NOTE(WeiW): It will return 2 if exists
	if ret != 0 && ret != 2 {
		return errors.New(fmt.Sprintf("add route to %s via %s dev %s failed", route, gw, nic))
	}

	return nil
}

func GetOutingNicForIp(ip string) (string, error) {
	ipn := net.ParseIP(ip)
	if ipn == nil {
		return "", fmt.Errorf("invalid ip: %s", ip)
	}

	/* 这个接口可以获取信息如下：
	2024-10-10 18:02:59 DEBUG   IP 地址: 127.0.0.1
	2024-10-10 18:02:59 DEBUG   子网掩码: 255.0.0.0
	2024-10-10 18:02:59 DEBUG   IP 地址: ::1
	2024-10-10 18:02:59 DEBUG   子网掩码: ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
	2024-10-10 18:02:59 DEBUG   IP 地址: 172.25.116.190
	2024-10-10 18:02:59 DEBUG   子网掩码: 255.255.0.0
	2024-10-10 18:02:59 DEBUG   IP 地址: fe80::f85b:a0ff:fe50:6600
	2024-10-10 18:02:59 DEBUG   子网掩码: ffff:ffff:ffff:ffff::
	*/
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range interfaces {
		addrs, _ := iface.Addrs()

		for _, addr := range addrs {
			switch v := addr.(type) {
			case *net.IPNet:
				if v.Contains(ipn) {
					return iface.Name, nil
				}
			}
		}
	}

	return "", fmt.Errorf("can not found interface contain %s", ip)
}

func GetNicForRoute(ip string) string {

	dev := ""
	if IsRuingUT() {
		for _, nic := range PrivateNicsForUT {
			log.Debugf("PrivateNicForUT %+v", nic)
			cidr, _ := GetNetworkNumber(nic.Ip, nic.Netmask)
			ip := net.ParseIP(nic.Ip)
			_, cidrNet, _ := net.ParseCIDR(cidr)
			if cidrNet.Contains(ip) {
				dev = nic.Name
				break
			}
		}
	} else {
		dev, _ = GetOutingNicForIp(ip)
	}
	if dev != "" {
		return dev
	}

	/* exmaple:
	# ip r
	default via 172.25.0.1 dev eth0  默认路由
	169.254.169.254 via 172.25.116.191 dev eth0 proto static 静态路由
	172.25.0.0/16 dev eth0 proto kernel scope link src 172.25.116.190 直连路由
	# ip -o r get 169.254.169.254     ###静态路由
	169.254.169.254 via 172.25.116.191 dev eth0 src 172.25.116.190 uid 0 \    cache
	# ip -o r get 172.25.116.189        ###直连路由
	172.25.116.189 dev eth0 src 172.25.116.190 uid 0 \    cache
	# ip -o r get 192.168.3.10      ###默认路由
	192.168.3.10 via 172.25.0.1 dev eth0 src 172.25.116.190 uid 0 \    cache
	*/
	bash := Bash{Command: fmt.Sprintf("%s get %s", ipRouteCommand(ip), ip)}
	_, o, _, err := bash.RunWithReturn()
	if err != nil {
		return ""
	}

	dev = ""
	items := strings.Split(o, " ")
	for i, item := range items {
		if item == "dev" {
			dev = items[i+1]
			break
		}
	}

	return dev
}

func RemoveZStackRoute(ip string) error {
	SetZStackRouteProtoIdentifier()
	// DeleteRouteIfExists: delete only when the route exists and the type is ZSTACK_ROUTE_PROTO
	if err := DeleteRouteIfExists(ip); err != nil {
		return err
	}

	return nil
}

func SetZStackRouteProtoIdentifier() {
	bash := Bash{
		Command: "grep zstack /etc/iproute2/rt_protos",
	}
	check, _, _, _ := bash.RunWithReturn()

	if check != 0 {
		log.Debugf("no route proto zstack in /etc/iproute2/rt_protos")
		bash = Bash{
			Command: fmt.Sprintf("sudo bash -c \"echo -e '\n\n# Used by zstack\n%s     zstack' >> /etc/iproute2/rt_protos\"", ZSTACK_ROUTE_PROTO_IDENTIFFER),
		}
		bash.Run()
	}
}

func SetZvrRouteProtoIdentifier() {
	bash := Bash{
		Command: "grep zvr /etc/iproute2/rt_protos",
	}
	if check, _, _, _ := bash.RunWithReturn(); check != 0 {
		log.Debugf("no route proto zvr in /etc/iproute2/rt_protos")
		bash = Bash{
			Command: fmt.Sprintf("bash -c \"echo '%d     zvr' >> /etc/iproute2/rt_protos\"", ZVR_ROUTE_PROTO_IDENTIFFER),
			Sudo:    true,
		}
		bash.Run()
	}
}

func GetNicNumber(nic string) (int, error) {
	if IsRuingUT() {
		switch nic {
		case "ut-mgt":
			return 1, nil
		case "ut-pub":
			return 2, nil
		case "ut-pub1":
			return 3, nil
		case "ut-pub2":
			return 4, nil
		case "ut-pri":
			return 5, nil
		case "ut-pri1":
			return 6, nil
		case "ut-pri2":
			return 7, nil
		}
		return -1, fmt.Errorf("nic %s not existed", nic)
	}
	num, err := strconv.ParseInt(strings.Split(nic, "eth")[1], 10, 64)
	if err != nil {
		return -1, err
	}
	return int(num), nil
}

func CheckMgmtCidrContainsIp(ip string, mgmtNic map[string]interface{}) bool {
	maskCidr, err := NetmaskToCIDR(mgmtNic["netmask"].(string))
	PanicOnError(err)
	_, mgmtNet, err := net.ParseCIDR(fmt.Sprintf("%s/%d", mgmtNic["ip"], maskCidr))
	PanicOnError(err)

	return mgmtNet.Contains(net.ParseIP(ip))
}

func GetPrivteInterface() []string {
	bash := Bash{
		Command: fmt.Sprintf("sudo ip link | grep -B 2 'category:Private' | grep '<BROADCAST,MULTICAST' | awk -F ':' '{print $2}'"),
	}
	ret, o, _, err := bash.RunWithReturn()
	if err != nil {
		return nil
	}
	if ret != 0 {
		return nil
	}

	lines := strings.Split(o, "\n")
	var nics []string
	for _, name := range lines {
		name = strings.Trim(name, " ")
		if name != "" {
			nics = append(nics, name)
		}
	}

	if len(nics) == 0 {
		return nil
	}

	return nics
}

func GetUpperIp(cidr net.IPNet) net.IP {
	ip := cidr.IP
	mask := cidr.Mask
	n := len(ip)
	if n != len(mask) {
		return nil
	}
	out := make(net.IP, n)
	for i := 0; i < n; i++ {
		out[i] = ip[i] | ^mask[i]
	}
	return out
}

/* this only for ipv4 */
func GetBroadcastIpFromNetwork(ip, netmask string) string {
	var brAddress []string
	ips := strings.Split(ip, ".")
	masks := strings.Split(netmask, ".")

	for i := 0; i < 4; i++ {
		ipByte, err := strconv.Atoi(ips[i])
		PanicOnError(err)
		maskByte, err := strconv.Atoi(masks[i])
		PanicOnError(err)
		ipByte = ipByte & maskByte
		maskByte = maskByte ^ 0xFF

		brAddress = append(brAddress, fmt.Sprintf("%d", (byte)(ipByte^maskByte)))
	}

	return strings.Join(brAddress, ".")
}

func GetNexthop(dst string) (string, error) {
	/* $ ip r get 10.86.4.0/23
	   10.86.4.0 via 192.168.100.1 dev eth1  src 192.168.100.129
	       cache
	   $ ip r get 192.168.250.0/24
	   broadcast 192.168.250.0 dev eth0  src 192.168.250.14
	       cache <local,brd>
	*/
	bash := Bash{
		Command: fmt.Sprintf("ip r get %s | grep via | awk '{print $3}'", dst),
	}
	ret, o, e, err := bash.RunWithReturn()
	if err != nil {
		return "", err
	}
	if ret != 0 {
		return "", fmt.Errorf("get nexthop for %s failed, ret = %d, error:%s", dst, ret, e)
	}

	return strings.TrimSpace(o), nil
}

func AddRoute(dst, nexthop string) error {
	bash := Bash{
		Command: fmt.Sprintf("sudo ip route add %s via %s", dst, nexthop),
	}
	if IsEuler2203() {
		bash = Bash{
			Command: fmt.Sprintf("sudo vtysh -c 'configure terminal' -c 'ip route %s %s'", dst, nexthop),
		}
	}
	ret, _, e, err := bash.RunWithReturn()
	if err != nil {
		if strings.Contains(e, "File exists") {
			log.Debugf("route is exists, skip err")
			return nil
		}
		return err
	}
	if ret != 0 {
		return fmt.Errorf("add route %s nexthop %s failed, ret = %d, error:%s", dst, nexthop, ret, e)
	}

	return nil
}

func FlushNicRoute(nic string) error {
	bash := Bash{
		Command: fmt.Sprintf("sudo ip route flush dev %s", nic),
	}
	ret, _, _, err := bash.RunWithReturn()
	if err != nil || ret != 0 {
		return nil
	}

	return err
}

func DelIp6DefaultRoute() error {
	bash := Bash{
		Command: fmt.Sprintf("ip -6 r | grep default | awk '{print $3}'"),
	}
	ret, oldGw6, _, err := bash.RunWithReturn()
	if err != nil || ret != 0 {
		return nil
	}

	bash = Bash{
		Command: fmt.Sprintf(fmt.Sprintf("sudo ip -6 route del default via %s", oldGw6)),
	}
	_, _, _, err = bash.RunWithReturn()

	return err
}

func AddIp6DefaultRoute(gw6, dev string) {
	/* default ip6 route
	   # ip -6 r | grep default
	   default via caca::1 dev eth1  metric 1024 */

	oldGw6 := ""
	bash := Bash{
		Command: fmt.Sprintf("ip -6 r | grep default | awk '{print $3}'"),
	}
	ret, o, _, err := bash.RunWithReturn()
	if err == nil && ret == 0 {
		oldGw6 = o
	}

	var cmds []string
	if oldGw6 != "" {
		cmds = append(cmds, fmt.Sprintf("sudo ip -6 route del default via %s", oldGw6))
	}
	cmds = append(cmds, fmt.Sprintf("sudo ip -6 route add default via %s dev %s", gw6, dev))
	bash = Bash{
		Command: strings.Join(cmds, ";"),
	}
	_, _, _, err = bash.RunWithReturn()
	PanicOnError(err)
}

func DelIp4DefaultRoute() error {
	bash := Bash{
		Command: fmt.Sprintf("ip -4 r | grep default | awk '{print $3}'"),
	}
	ret, oldGw4, _, err := bash.RunWithReturn()
	if err != nil || ret != 0 {
		return nil
	}

	bash = Bash{
		Command: fmt.Sprintf(fmt.Sprintf("sudo ip -4 route del default via %s", oldGw4)),
	}
	_, _, _, err = bash.RunWithReturn()

	return err
}

func AddIp4DefaultRoute(gw4, dev string) {
	oldGw4 := ""
	bash := Bash{
		Command: fmt.Sprintf("ip -4 r | grep default | awk '{print $3}'"),
	}
	ret, o, _, err := bash.RunWithReturn()
	if err == nil && ret == 0 {
		oldGw4 = o
	}

	var cmds []string
	if oldGw4 != "" {
		cmds = append(cmds, fmt.Sprintf("sudo ip -4 route del default via %s", oldGw4))
	}
	cmds = append(cmds, fmt.Sprintf("sudo ip -4 route add default via %s dev %s", gw4, dev))
	bash = Bash{
		Command: strings.Join(cmds, ";"),
	}
	_, _, _, err = bash.RunWithReturn()
	PanicOnError(err)
}

func IsIpv4Address(address string) bool {
	parsedIP := net.ParseIP(address)
	if parsedIP != nil && parsedIP.To4() != nil {
		return true
	}

	return false
}

func IsIpv6Address(address string) bool {
	parsedIP := net.ParseIP(address)
	return parsedIP != nil && parsedIP.To4() == nil
}

func FormatURLHost(host string) string {
	if IsIpv6Address(host) && !strings.HasPrefix(host, "[") {
		return fmt.Sprintf("[%s]", host)
	}
	return host
}

func routeCidr(ip string) string {
	if strings.Contains(ip, "/") {
		return ip
	}
	if IsIpv6Address(ip) {
		return ip + "/128"
	}
	return ip + "/32"
}

func ipRouteCommand(ip string) string {
	if IsIpv6Address(ip) {
		return "ip -6 route"
	}
	return "ip route"
}

func frrRouteCommand(ip string) string {
	if IsIpv6Address(ip) {
		return "ipv6 route"
	}
	return "ip route"
}

func IsMgtNic(name string) bool {
	return name == "eth0"
}

// CreateBondInterface creates a bond interface with the specified mode
// mode can be "xor" (balance-xor) or "ab" (active-backup)
func CreateBondInterface(bondName, mode string) error {
	var bondMode string
	switch mode {
	case "xor":
		bondMode = "balance-xor"
	case "ab":
		bondMode = "active-backup"
	default:
		return fmt.Errorf("unsupported bond mode: %s, only 'xor' and 'ab' are supported", mode)
	}

	// Create bond interface
	bash := Bash{
		Command: fmt.Sprintf("sudo ip link add %s type bond mode %s", bondName, bondMode),
	}
	ret, _, e, err := bash.RunWithReturn()
	if err != nil {
		return err
	}
	if ret != 0 {
		return fmt.Errorf("create bond interface %s failed: %s", bondName, e)
	}

	// Set xmit_hash_policy for balance-xor mode
	if mode == "xor" {
		bash = Bash{
			Command: fmt.Sprintf("sudo sh -c \"echo layer3+4 > /sys/class/net/%s/bonding/xmit_hash_policy\"", bondName),
		}
		ret, _, e, err = bash.RunWithReturn()
		if err != nil {
			return err
		}
		if ret != 0 {
			return fmt.Errorf("set xmit_hash_policy for bond %s failed: %s", bondName, e)
		}
	}

	// Set miimon
	bash = Bash{
		Command: fmt.Sprintf("sudo sh -c \"echo 100 > /sys/class/net/%s/bonding/miimon\"", bondName),
	}
	ret, _, e, err = bash.RunWithReturn()
	if err != nil {
		return err
	}
	if ret != 0 {
		return fmt.Errorf("set miimon for bond %s failed: %s", bondName, e)
	}

	log.Debugf("bond interface %s created with mode %s", bondName, bondMode)
	return nil
}

// AddSlaveToBond adds a slave interface to a bond
func AddSlaveToBond(slaveName, bondName string) error {
	// Set slave interface down
	bash := Bash{
		Command: fmt.Sprintf("sudo ip link set %s down", slaveName),
	}
	ret, _, e, err := bash.RunWithReturn()
	if err != nil {
		return err
	}
	if ret != 0 {
		return fmt.Errorf("set slave %s down failed: %s", slaveName, e)
	}

	// Add slave to bond
	bash = Bash{
		Command: fmt.Sprintf("sudo ip link set %s master %s", slaveName, bondName),
	}
	ret, _, e, err = bash.RunWithReturn()
	if err != nil {
		return err
	}
	if ret != 0 {
		return fmt.Errorf("add slave %s to bond %s failed: %s", slaveName, bondName, e)
	}

	log.Debugf("slave %s added to bond %s", slaveName, bondName)
	return nil
}

// ConfigureBondInterface configures IP address and brings up the bond interface
func ConfigureBondInterface(bondName, ip, netmask string) error {
	// Add IP address to bond
	cidr, err := NetmaskToCIDR(netmask)
	if err != nil {
		return err
	}
	ipString := fmt.Sprintf("%s/%d", ip, cidr)

	bash := Bash{
		Command: fmt.Sprintf("sudo ip addr add %s dev %s", ipString, bondName),
	}
	ret, _, e, err := bash.RunWithReturn()
	if err != nil {
		return err
	}
	if ret != 0 {
		return fmt.Errorf("add ip %s to bond %s failed: %s", ipString, bondName, e)
	}

	// Bring up bond interface
	bash = Bash{
		Command: fmt.Sprintf("sudo ip link set %s up", bondName),
	}
	ret, _, e, err = bash.RunWithReturn()
	if err != nil {
		return err
	}
	if ret != 0 {
		return fmt.Errorf("bring up bond %s failed: %s", bondName, e)
	}

	log.Debugf("bond %s configured with ip %s", bondName, ipString)
	return nil
}

// SetupBondWithSlaves creates a bond interface and adds slave interfaces to it
// This is the main function to setup a complete bond configuration
func SetupBondWithSlaves(bondName, mode string, slaves []string, ip, netmask string) error {
	// Create bond interface
	if err := CreateBondInterface(bondName, mode); err != nil {
		return fmt.Errorf("create bond interface failed: %v", err)
	}

	// Add slaves to bond
	for _, slave := range slaves {
		if err := AddSlaveToBond(slave, bondName); err != nil {
			return fmt.Errorf("add slave %s to bond failed: %v", slave, err)
		}
	}

	// Configure bond interface with IP
	if err := ConfigureBondInterface(bondName, ip, netmask); err != nil {
		return fmt.Errorf("configure bond interface failed: %v", err)
	}

	return nil
}

// GetBondMode reads the current bond mode from sysfs
// Returns the mode in short format: "xor" (balance-xor) or "ab" (active-backup)
func GetBondMode(bondName string) (string, error) {
	modePath := fmt.Sprintf("/sys/class/net/%s/bonding/mode", bondName)
	data, err := os.ReadFile(modePath)
	if err != nil {
		return "", fmt.Errorf("cannot read bond mode from %s: %v", modePath, err)
	}

	// The content format is like "balance-xor 2" or "active-backup 1"
	modeStr := strings.TrimSpace(string(data))
	parts := strings.Fields(modeStr)
	if len(parts) == 0 {
		return "", fmt.Errorf("invalid bond mode format: %s", modeStr)
	}

	// Convert from kernel format to short format
	kernelMode := parts[0]
	switch kernelMode {
	case "balance-xor":
		return "xor", nil
	case "active-backup":
		return "ab", nil
	default:
		return "", fmt.Errorf("unsupported bond mode: %s", kernelMode)
	}
}

// DeleteBondInterface removes a bond interface
// It will first remove all slave interfaces from the bond
func DeleteBondInterface(bondName string) error {
	// Get all slaves
	slavesPath := fmt.Sprintf("/sys/class/net/%s/bonding/slaves", bondName)
	data, err := os.ReadFile(slavesPath)
	if err != nil {
		log.Warnf("cannot read bond slaves from %s: %v", slavesPath, err)
	} else {
		// Remove all slaves
		slavesStr := strings.TrimSpace(string(data))
		if slavesStr != "" {
			slaves := strings.Fields(slavesStr)
			for _, slave := range slaves {
				bash := Bash{
					Command: fmt.Sprintf("sudo ip link set %s nomaster", slave),
				}
				ret, _, e, err := bash.RunWithReturn()
				if err != nil {
					log.Warnf("remove slave %s from bond %s failed: %v", slave, bondName, err)
				}
				if ret != 0 {
					log.Warnf("remove slave %s from bond %s failed: %s", slave, bondName, e)
				}
			}
		}
	}

	// Delete bond interface
	bash := Bash{
		Command: fmt.Sprintf("sudo ip link delete %s", bondName),
	}
	ret, _, e, err := bash.RunWithReturn()
	if err != nil {
		return fmt.Errorf("delete bond interface %s failed: %v", bondName, err)
	}
	if ret != 0 {
		return fmt.Errorf("delete bond interface %s failed: %s", bondName, e)
	}

	log.Debugf("bond interface %s deleted", bondName)
	return nil
}
