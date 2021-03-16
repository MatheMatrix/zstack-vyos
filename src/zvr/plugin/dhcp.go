package plugin

import (
	"bytes"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"html/template"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"zvr/server"
	"zvr/utils"
)

const (
	ADD_DHCP_PATH            = "/adddhcp"
	REFRESH_DHCP_SERVER_PATH = "/refreshDhcpServer"
	START_DHCP_SERVER_PATH   = "/startDhcpServer"
	STOP_DHCP_SERVER_PATH    = "/stopDhcpServer"
	REMOVE_DHCP_PATH         = "/removedhcp"

	DHCPD_BIN_PATH_VYOS_1_1_7      = "/usr/sbin/dhcpd3"
	DHCPD_BIN_PATH_VYOS_1_2		   = "/usr/sbin/dhcpd"
	DHCPD_PATH          = "/home/vyos/zvr/dhcp3"
	HOST_HOST_FILE_TEMP = "/tmp/.dhcphosts"
	HOST_HOST_FILE      = "/etc/hosts"

	OMAPI_PORT = 7911

	GROUP_FULL    = "full"
	GROUP_PARTIAL = "partial"

	MAX_LEASE_TIME = 31104000 /* 360 days */

	DHCP_DHCP_SCRIPT = "/home/vyos/zvr/keepalived/script/dhcpd.sh"
)

type dhcpInfo struct {
	Ip                 string   `json:"ip"`
	Mac                string   `json:"mac"`
	Netmask            string   `json:"netmask"`
	Gateway            string   `json:"gateway"`
	Dns                []string `json:"dns"`
	Hostname           string   `json:"hostname"`
	VrNicMac           string   `json:"vrNicMac"`
	DnsDomain          string   `json:"dnsDomain"`
	IsDefaultL3Network bool     `json:"isDefaultL3Network"`
	Mtu                int      `json:"mtu"`
}

type dhcpServer struct {
	NicMac    string     `json:"nicMac"`
	Subnet    string     `json:"subnet"`
	Netmask   string     `json:"netmask"`
	Gateway   string     `json:"gateway"`
	DnsServer string     `json:"dnsServer"`
	DnsDomain string     `json:"dnsDomain"`
	Mtu       int        `json:"mtu"`
	DhcpInfos []dhcpInfo `json:"dhcpInfos"`
}

type addDhcpCmd struct {
	DhcpEntries []dhcpInfo `json:"dhcpEntries"`
	Rebuild     bool       `json:"rebuild"`
}

type removeDhcpCmd struct {
	DhcpEntries []dhcpInfo `json:"dhcpEntries"`
}

type dhcpServerCmd struct {
	DhcpServers []dhcpServer `json:"dhcpServers"`
}

type DhcpServerStruct struct {
	NicMac    string
	Subnet    string
	Netmask   string
	Gateway   string
	DnsServer string
	DnsDomain string
	Mtu       int
	/* dhcp entry info, key is nic.mac */
	DhcpInfos map[string]dhcpInfo
}

/* all dhcp server, key is vrNicMac */
var DhcpServerEntries map[string]*DhcpServerStruct
var DEFAULT_HOSTS []string

func getDhcpServerPath(nicName string) (pid, conf, lease, tempConf string) {
	pid = fmt.Sprintf("%s/%s/%s.pid", DHCPD_PATH, nicName, nicName)
	conf = fmt.Sprintf("%s/%s/%s.conf", DHCPD_PATH, nicName, nicName)
	lease = fmt.Sprintf("%s/%s/%s.lease", DHCPD_PATH, nicName, nicName)
	tempConf = fmt.Sprintf("%s/%s/%s.tempConf", DHCPD_PATH, nicName, nicName)
	os.Mkdir(fmt.Sprintf("%s/%s", DHCPD_PATH, nicName), os.ModePerm)
	return pid, conf, lease, tempConf
}

func getNicIndex(nicName string) (int, error) {
	return strconv.Atoi(nicName[len(nicName)-1:])
}

func getNicOmApiPort(nicName string) int {
	idx, err := getNicIndex(nicName)
	utils.PanicOnError(err)
	return OMAPI_PORT + idx
}

func makeLanName(nicName string) string {
	return nicName + "-subnet"
}

const dhcpServerHaTemplate_VYOS_1_1_7 = `# generated by ZStack, don't modify it'
sudo pkill -9 dhcpd3
{{ range .DhcpServers }}
sudo touch {{.LeaseFile}}
sudo chmod 666 {{.LeaseFile}}
sudo truncate -s 0 {{.LeaseFile}}
sudo rm -f {{.PidFile}}
sudo cp {{.TempConf}} {{.ConfFile}}
sudo /usr/sbin/dhcpd3 -pf {{.PidFile}} -cf {{.ConfFile}} -lf {{.LeaseFile}}
{{ end }}
`
const dhcpServerHaTemplate_VYOS_1_2 = `# generated by ZStack, don't modify it'
sudo pkill -9 dhcpd
{{ range .DhcpServers }}
sudo touch {{.LeaseFile}}
sudo chmod 666 {{.LeaseFile}}
sudo truncate -s 0 {{.LeaseFile}}
sudo rm -f {{.PidFile}}
sudo cp {{.TempConf}} {{.ConfFile}}
sudo /usr/sbin/dhcpd -pf {{.PidFile}} -cf {{.ConfFile}} -lf {{.LeaseFile}}
{{ end }}
`

type dhcpServerFiles struct {
	ConfFile string
	PidFile string
	LeaseFile string
	TempConf  string
}

func getHostNameFromIp(ip string) string {
	return strings.Replace(ip, ".", "-", -1)
}

func getHostNameFromIpMac(ip, mac string) string {
	return fmt.Sprintf("%s-%s", strings.Replace(ip, ".", "-", -1), strings.Replace(mac, ":", "", -1))
}

func writeDhcpScriptFile() {
	var fileList []dhcpServerFiles
	var dhcpServerTemplate string
	if utils.IsHaEnabled() {
		/* generate a temp configure file for ha */
		for _, dhcp := range DhcpServerEntries {
			nicname, err := utils.GetNicNameByMac(dhcp.NicMac)
			utils.PanicOnError(err)
			pid, conf, lease, tempConf := getDhcpServerPath(nicname)
			getDhcpConfigFile(*dhcp, tempConf, nicname)
			fileList = append(fileList, dhcpServerFiles{conf, pid, lease, tempConf})
		}

		var buf bytes.Buffer
		m := map[string]interface{}{}
		m["DhcpServers"] = fileList

		if utils.Vyos_version == utils.VYOS_1_1_7 {
			dhcpServerTemplate = dhcpServerHaTemplate_VYOS_1_1_7
		} else  {
			dhcpServerTemplate = dhcpServerHaTemplate_VYOS_1_2
		}

		tmpl, err := template.New("haConf").Parse(dhcpServerTemplate)
		utils.PanicOnError(err)
		err = tmpl.Execute(&buf, m)
		utils.PanicOnError(err)
		err = ioutil.WriteFile(DHCP_DHCP_SCRIPT, buf.Bytes(), 0755)
		utils.PanicOnError(err)
	}
}

/* each interface will have a dhcp server */
func addDhcpHandler(ctx *server.CommandContext) interface{} {
	cmd := &addDhcpCmd{}
	ctx.GetCommand(cmd)

	for _, entry := range cmd.DhcpEntries {
		nicName, err := utils.GetNicNameByMac(entry.VrNicMac)
		utils.PanicOnError(err)
		omApiPort := getNicOmApiPort(nicName)
		group := GROUP_FULL
		if !entry.IsDefaultL3Network {
			group = GROUP_PARTIAL
		}

		/* add a entry by OMAPI */
		hostName := entry.Hostname
		if hostName == "" {
			hostName = strings.Replace(entry.Ip, ".", "-", -1)
			entry.Hostname = hostName
		}

		if _, ok := DhcpServerEntries[entry.VrNicMac]; ok {
			/* delete the entry which has same ip but different mac  */
			for _, e := range DhcpServerEntries[entry.VrNicMac].DhcpInfos {
				/* for some reason, MN node may send 2 entries with same ip but different macs
				so delete old entry if existed */
				if e.Ip == entry.Ip {
					log.Errorf("[vyos dhcp] found 2 entries with same ip, old: %+v, new: %+v", e, entry)
					b := &utils.Bash{
						Command: fmt.Sprintf(`omshell << EOF
server localhost
port %d
connect
new host
set hardware-address = %s
open
remove
EOF`, omApiPort, e.Mac),
						NoLog: true}
					if err = b.Run(); err != nil {
						log.Errorf("[vyos dhcp] delete old entry [mac: %s] failed, %s", e.Mac, err)
					}
					delete(DhcpServerEntries[entry.VrNicMac].DhcpInfos, e.Mac)
				}
				/* duplicated hostname */
				if e.Hostname == hostName {
					hostName = getHostNameFromIpMac(entry.Ip, entry.Mac)
					entry.Hostname = hostName
				}
			}
			DhcpServerEntries[entry.VrNicMac].DhcpInfos[entry.Mac] = entry
		} else {
			log.Errorf("[vyos dhcp] can not save dhcp entry[%+v] to buffer", entry)
			continue
		}

		/* add a entry by OMAPI */
		if entry.IsDefaultL3Network {
			b := &utils.Bash{
				Command: fmt.Sprintf(`omshell << EOF
server localhost
port %d
connect
new host
set name = "%s"
set hardware-address = %s
set hardware-type = 1
set ip-address = %s
set group = "%s"
create
EOF`, omApiPort, hostName, entry.Mac, entry.Ip, group),
			NoLog: true}
			if err = b.Run(); err != nil {
				log.Errorf("[vyos dhcp] add new entry [mac: %+v] failed, %s", entry, err)
			}
		} else {
			b := &utils.Bash{
				Command: fmt.Sprintf(`omshell << EOF
server localhost
port %d
connect
new host
set name = "%s"
set hardware-address = %s
set hardware-type = 1
set ip-address = %s
set group = "%s"
create
EOF`, omApiPort, hostName, entry.Mac, entry.Ip, group),
				NoLog: true}
			if err = b.Run(); err != nil {
				log.Errorf("[vyos dhcp] add new entry [mac: %+v] failed, %s", entry, err)
			}
		}
	}

	writeDhcpScriptFile()
	return nil
}

func stopAllDhcpServers() {
	var progname string

	if utils.Vyos_version == utils.VYOS_1_1_7 {
		progname = "dhcpd3"
	} else {
		progname = "dhcpd"
	}

	bash := &utils.Bash{
		Command: fmt.Sprintf("pkill -9 %s; rm -rf %s/*", progname, DHCPD_PATH),
		Sudo: true,
	}
	bash.Run()
}

func stopDhcpServer(pidFile, confFile, leaseFile  string) {
	b := &utils.Bash{
		Command: fmt.Sprintf("kill -9 $(cat %s); truncate -s 0 %s; truncate -s 0 %s", pidFile, confFile, leaseFile),
		Sudo: true,
	}
	b.Run()
}

/* each interface will have a dhcp server */
func refreshDhcpServer(ctx *server.CommandContext) interface{} {
	cmd := &dhcpServerCmd{}
	ctx.GetCommand(cmd)

	stopAllDhcpServers()
	/* no dhcp servers now */
	if len(cmd.DhcpServers) == 0 {
		return nil
	}

	/* empty the dhcp entries */
	DhcpServerEntries = make(map[string]*DhcpServerStruct)
	/* start dhcp servers */
	for _, server := range cmd.DhcpServers {
		startDhcpServer(server)
	}

	writeDhcpScriptFile()

	return nil
}

/* each interface will have a dhcp server */
func startDhcpServerCmd(ctx *server.CommandContext) interface{} {
	cmd := &dhcpServerCmd{}
	ctx.GetCommand(cmd)

	server := cmd.DhcpServers[0]
	nicname, err := utils.GetNicNameByMac(server.NicMac)
	utils.PanicOnError(err)
	pidFile, confFile, leaseFile, _ := getDhcpServerPath(nicname)
	stopDhcpServer(pidFile, confFile, leaseFile)
	startDhcpServer(server)

	writeDhcpScriptFile()
	return nil
}

/* each interface will have a dhcp server */
func stopDhcpServerCmd(ctx *server.CommandContext) interface{} {
	cmd := &dhcpServerCmd{}
	ctx.GetCommand(cmd)

	server := cmd.DhcpServers[0]
	nicname, err := utils.GetNicNameByMac(server.NicMac)
	utils.PanicOnError(err)
	pidFile, confFile, leaseFile, _ := getDhcpServerPath(nicname)
	stopDhcpServer(pidFile, confFile, leaseFile)

	delete(DhcpServerEntries, server.NicMac)

	writeDhcpScriptFile()
	return nil
}

func removeDhcpHandler(ctx *server.CommandContext) interface{} {
	cmd := &removeDhcpCmd{}
	ctx.GetCommand(cmd)

	for _, entry := range cmd.DhcpEntries {
		nicname, err := utils.GetNicNameByMac(entry.VrNicMac)
		utils.PanicOnError(err)
		omApiPort := getNicOmApiPort(nicname)

		/* add a entry by OMAPI */
		b := &utils.Bash{
			Command: fmt.Sprintf(`omshell << EOF
server localhost
port %d
connect
new host
set hardware-address = %s
open
remove
EOF`, omApiPort, entry.Mac),
			NoLog: true}
		err = b.Run()

		/* remove info from buffered dhcp server info */
		if _, ok := DhcpServerEntries[entry.VrNicMac]; ok {
			delete(DhcpServerEntries[entry.VrNicMac].DhcpInfos, entry.Mac)
		}
	}

	writeDhcpScriptFile()
	return nil
}

const dhcpServerTemplate = `# generated by ZStack, don't modify it'
ddns-update-style none;
omapi-port {{.OMAPIPort}};
log-facility local3;
shared-network {{.SubnetName}} {
    authoritative;
    subnet {{.Subnet}} netmask {{.NetMask}} {
        default-lease-time {{.MaxLeaseTime}};
        max-lease-time {{.MaxLeaseTime}};
        server-identifier {{.DnsServer}};
        option subnet-mask {{.NetMask}};
        option interface-mtu {{.Mtu}};
        option broadcast-address {{.BroadCastAddress}};
        use-host-decl-names on;

        group full {
            option domain-name-servers {{.DnsServer}};
            option routers {{.Gateway}};
            {{ if ne .DnsDomain "" }}option domain-name "{{.DnsDomain}}";{{ end }}

			{{ range .FullEntries }}
            host {{.HostName}} {
                option host-name "{{.HostName}}";
                fixed-address {{.Ip}};
                hardware ethernet {{.Mac}};
            }
			{{ end }}
        }  

        group partial {
            {{ range .PartEntries }}
            host {{.HostName}} {
                fixed-address {{.Ip}};
                hardware ethernet {{.Mac}};
            }
			{{ end }}
        }
    }
}
`

func setDhcpFirewallRules(nicName string) error {
	rule := utils.NewIptablesRule(utils.UDP, "", "", 0, 67, nil, utils.RETURN, utils.DnsRuleComment)
	utils.InsertFireWallRule(nicName, rule, utils.LOCAL)
	rule = utils.NewIptablesRule(utils.UDP, "", "", 0, 68, nil, utils.RETURN, utils.DnsRuleComment)
	utils.InsertFireWallRule(nicName, rule, utils.LOCAL)
	rule = utils.NewIptablesRule(utils.UDP, "", "", 0, 53, nil, utils.RETURN, utils.DnsRuleComment)
	utils.InsertFireWallRule(nicName, rule, utils.LOCAL)
	rule = utils.NewIptablesRule(utils.TCP, "", "", 0, 53, nil, utils.RETURN, utils.DnsRuleComment)
	utils.InsertFireWallRule(nicName, rule, utils.LOCAL)
	return nil
}

func makeDhcpFirewallRuleDescription(nicname string) string {
	return fmt.Sprintf("DHCP-for-%s", nicname)
}

func getDhcpConfigFile(dhcp DhcpServerStruct, confFile string, nicname string)  {
	subnet := strings.Split(dhcp.Subnet, "/")
	dhcpServer := map[string]interface{}{}
	dhcpServer["OMAPIPort"] = getNicOmApiPort(nicname)
	dhcpServer["SubnetName"] = makeLanName(nicname)
	dhcpServer["Subnet"] = subnet[0]
	dhcpServer["NetMask"] = dhcp.Netmask
	dhcpServer["BroadCastAddress"] = utils.GetBroadcastIpFromNetwork(dhcp.Gateway, dhcp.Netmask)
	dhcpServer["Mtu"] = dhcp.Mtu
	dhcpServer["Gateway"] = dhcp.Gateway
	dhcpServer["DnsServer"] = dhcp.DnsServer
	dhcpServer["MaxLeaseTime"] = MAX_LEASE_TIME
	dhcpServer["DnsDomain"] = dhcp.DnsDomain

	/* nics which are default nic of the vm, will get ip/gateway/dns domain */
	var fullEntries []map[string]interface{}
	/* nics which are not default nic of the vm, will get ip */
	var partEntries []map[string]interface{}

	for _, info := range dhcp.DhcpInfos {
		entry := map[string]interface{}{}
		entry["HostName"] = info.Hostname
		entry["Ip"] = info.Ip
		entry["Mac"] = info.Mac
		if info.IsDefaultL3Network {
			fullEntries = append(fullEntries, entry)
		} else {
			partEntries = append(partEntries, entry)
		}
	}
	dhcpServer["FullEntries"] = fullEntries
	dhcpServer["PartEntries"] = partEntries

	var buf bytes.Buffer
	tmpl, err := template.New("conf").Parse(dhcpServerTemplate)
	utils.PanicOnError(err)
	err = tmpl.Execute(&buf, dhcpServer)
	utils.PanicOnError(err)
	err = ioutil.WriteFile(confFile, buf.Bytes(), 0755)
	utils.PanicOnError(err)
}

func startDhcpServer(dhcp dhcpServer) {
	nicname, err := utils.GetNicNameByMac(dhcp.NicMac)
	utils.PanicOnError(err)
	pidFile, conFile, leaseFile, _ := getDhcpServerPath(nicname)
	/* lease file must be created first */
	utils.CreateFileIfNotExists(leaseFile, os.O_WRONLY|os.O_APPEND, 0666)
	os.Truncate(leaseFile, 0)
	os.Remove(pidFile)

	hostNameMap := make(map[string]string)

	dhcpStruct := DhcpServerStruct{dhcp.NicMac,dhcp.Subnet, dhcp.Netmask,  dhcp.Gateway,
		dhcp.DnsServer, dhcp.DnsDomain, dhcp.Mtu, map[string]dhcpInfo{}}
	for _, info := range dhcp.DhcpInfos {
		/* if there is duplicated hostname */
		hostName := info.Hostname
		if hostName == "" {
			hostName = getHostNameFromIp(info.Ip)
			info.Hostname = hostName
		}
		if _, ok := hostNameMap[hostName]; ok {
			info.Hostname = getHostNameFromIpMac(info.Ip, info.Mac)
			hostNameMap[info.Hostname] = info.Hostname
		} else {
			hostNameMap[hostName] = hostName
		}
		dhcpStruct.DhcpInfos[info.Mac] = info
	}
	getDhcpConfigFile(dhcpStruct, conFile, nicname)

	/* start dhcp server for nic */
	var dhcpdBinPath string;
	if utils.Vyos_version == utils.VYOS_1_1_7 {
		dhcpdBinPath = DHCPD_BIN_PATH_VYOS_1_1_7
	} else  {
		dhcpdBinPath = DHCPD_BIN_PATH_VYOS_1_2
	} 

	b := &utils.Bash{
		Command: fmt.Sprintf("sudo %s -pf %s -cf %s -lf %s", dhcpdBinPath, pidFile, conFile, leaseFile),
	}
	err = b.Run()

	tree := server.NewParserFromShowConfiguration().Tree

	if utils.IsSkipVyosIptables() {
		setDhcpFirewallRules(nicname)
	} else {
		des := makeDhcpFirewallRuleDescription(nicname)
		if r := tree.FindFirewallRuleByDescription(nicname, "local", des); r == nil {
			tree.SetFirewallOnInterface(nicname, "local",
				fmt.Sprintf("description %v", des),
				"destination port 67-68",
				"protocol udp",
				"action accept",
			)
		}
		des = makeDnsFirewallRuleDescription(nicname)
		if r := tree.FindFirewallRuleByDescription(nicname, "local", des); r == nil {
			/* dhcp will set vpc as dns forwarder */
			tree.SetFirewallOnInterface(nicname, "local",
				fmt.Sprintf("description %v", des),
				"destination port 53",
				"protocol tcp_udp",
				"action accept",
			)
		}

		tree.AttachFirewallToInterface(nicname, "local")
	}
	tree.Apply(false)

	delete(DhcpServerEntries, dhcp.NicMac)
	DhcpServerEntries[dhcp.NicMac] = &dhcpStruct

	addDnsNic(nicname)
}

func enableDhcpLog() {
	dhcp_log_file, err := ioutil.TempFile(DHCPD_PATH, "rsyslog")
	utils.PanicOnError(err)
	conf := `$ModLoad imudp
$UDPServerRun 514
local3.debug     /var/log/dhcp.log`
	_, err = dhcp_log_file.Write([]byte(conf))
	utils.PanicOnError(err)

	dhcp_log_rotatoe_file, err := ioutil.TempFile(DHCPD_PATH, "rotation")
	utils.PanicOnError(err)
	rotate_conf := `/var/log/dhcp.log {
size 10240k
rotate 20
compress
copytruncate
notifempty
missingok
}`
	_, err = dhcp_log_rotatoe_file.Write([]byte(rotate_conf))
	utils.PanicOnError(err)

	zvr_log_rotatoe_file, err := ioutil.TempFile(DHCPD_PATH, "zvrRotation")
	utils.PanicOnError(err)
	zvr_rotate_conf := `/home/vyos/zvr/zvr.log {
size 10240k
rotate 40
compress
copytruncate
notifempty
missingok
}`
	_, err = zvr_log_rotatoe_file.Write([]byte(zvr_rotate_conf))
	utils.PanicOnError(err)

	utils.SudoMoveFile(dhcp_log_file.Name(), "/etc/rsyslog.d/dhcp.conf")
	utils.SudoMoveFile(dhcp_log_rotatoe_file.Name(), "/etc/logrotate.d/dhcp")
	utils.SudoMoveFile(zvr_log_rotatoe_file.Name(), "/etc/logrotate.d/zvr")
}

func init() {
	os.Mkdir(DHCPD_PATH, os.ModePerm)
	DEFAULT_HOSTS = []string{
		"127.0.0.1 localhost",
		"::1     ip6-localhost ip6-loopback",
		"fe00::0 ip6-localnet",
		"ff00::0 ip6-mcastprefix",
		"ff02::1 ip6-allnodes",
		"ff02::2 ip6-allrouters",
		"ff02::3 ip6-allhosts",
		"127.0.1.1	  vyos	 #vyatta entry"}
	DhcpServerEntries = make(map[string]*DhcpServerStruct)
	enableDhcpLog()
}

func DhcpEntryPoint() {
	server.RegisterAsyncCommandHandler(ADD_DHCP_PATH, server.VyosLock(addDhcpHandler))
	server.RegisterAsyncCommandHandler(REMOVE_DHCP_PATH, server.VyosLock(removeDhcpHandler))
	server.RegisterAsyncCommandHandler(REFRESH_DHCP_SERVER_PATH, server.VyosLock(refreshDhcpServer))
	server.RegisterAsyncCommandHandler(START_DHCP_SERVER_PATH, server.VyosLock(startDhcpServerCmd))
	server.RegisterAsyncCommandHandler(STOP_DHCP_SERVER_PATH, server.VyosLock(stopDhcpServerCmd))
}
