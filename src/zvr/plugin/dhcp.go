package plugin

import (
	"bytes"
	"fmt"
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

	DHCPD_BIN_PATH      = "/usr/sbin/dhcpd3"
	DHCPD_PATH          = "/home/vyos/zvr/dhcp3"
	HOST_HOST_FILE_TEMP = "/tmp/.dhcphosts"
	HOST_HOST_FILE      = "/etc/hosts"

	OMAPI_PORT = 7911

	GROUP_FULL    = "full"
	GROUP_PARTIAL = "partial"

	MAX_LEASE_TIME = 31104000 /* 360 days */
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

/* all dhcp entries, key is hostName */
var dhcpdEntries map[string]dhcpInfo
var DEFAULT_HOSTS []string

func getDhcpServerPath(nicName string) (pid, conf, lease, log string) {
	pid = fmt.Sprintf("%s/%s/%s.pid", DHCPD_PATH, nicName, nicName)
	conf = fmt.Sprintf("%s/%s/%s.conf", DHCPD_PATH, nicName, nicName)
	lease = fmt.Sprintf("%s/%s/%s.lease", DHCPD_PATH, nicName, nicName)
	log = fmt.Sprintf("%s/%s/%s.log", DHCPD_PATH, nicName, nicName)
	os.Mkdir(fmt.Sprintf("%s/%s", DHCPD_PATH, nicName), os.ModePerm)
	return pid, conf, lease, log
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

func changeDhcpHosts() {
	hosts := DEFAULT_HOSTS
	for _, entry := range dhcpdEntries {
		hosts = append(hosts, fmt.Sprintf("%s %s", entry.Ip, entry.Hostname))
	}
	hostConents := strings.Join(hosts, "\n")
	err := ioutil.WriteFile(HOST_HOST_FILE_TEMP, []byte(hostConents), 0755)
	utils.PanicOnError(err)
	bash := utils.Bash{
		Command: fmt.Sprintf("sudo mv %s %s; service dnsmasq restart", HOST_HOST_FILE_TEMP, HOST_HOST_FILE),
	}
	_, _, _, err = bash.RunWithReturn()
	utils.PanicOnError(err)
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
		dhcpdEntries[entry.Mac] = entry

		/* add a entry by OMAPI */
		var b *utils.Bash
		if entry.IsDefaultL3Network {
			b = &utils.Bash{
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
			EOF`, omApiPort, entry.Hostname, entry.Mac, entry.Ip, group)}
		} else {
			b = &utils.Bash{
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
			EOF`, omApiPort, entry.Hostname, entry.Mac, entry.Ip, group)}
		}
		err = b.Run()
	}

	/* update /etc/hosts for dnsmasq */
	changeDhcpHosts()
	return nil
}

func stopAllDhcpServers() {
	b := &utils.Bash{
		Command: fmt.Sprintf("sudo pkill -9 dhcpd3"),
	}
	b.Run()
}

func stopDhcpServer(pidFile string) {
	b := &utils.Bash{
		Command: fmt.Sprintf("sudo kill -9 $(cat %s)", pidFile),
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
	dhcpdEntries = make(map[string]dhcpInfo)
	/* start dhcp servers */
	for _, server := range cmd.DhcpServers {
		startDhcpServer(server)
	}

	changeDhcpHosts()

	return nil
}

/* each interface will have a dhcp server */
func startDhcpServerCmd(ctx *server.CommandContext) interface{} {
	cmd := &dhcpServerCmd{}
	ctx.GetCommand(cmd)

	server := cmd.DhcpServers[0]
	nicname, err := utils.GetNicNameByMac(server.NicMac)
	utils.PanicOnError(err)
	pidFile, _, _, _ := getDhcpServerPath(nicname)
	stopDhcpServer(pidFile)
	startDhcpServer(server)

	changeDhcpHosts()
	return nil
}

/* each interface will have a dhcp server */
func stopDhcpServerCmd(ctx *server.CommandContext) interface{} {
	cmd := &dhcpServerCmd{}
	ctx.GetCommand(cmd)

	server := cmd.DhcpServers[0]
	nicname, err := utils.GetNicNameByMac(server.NicMac)
	utils.PanicOnError(err)
	pidFile, _, _, _ := getDhcpServerPath(nicname)
	stopDhcpServer(pidFile)

	for key, entry := range dhcpdEntries {
		if entry.VrNicMac == server.NicMac {
			delete(dhcpdEntries, key)
		}
	}

	changeDhcpHosts()
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
			EOF`, omApiPort, entry.Mac)}
		err = b.Run()

		delete(dhcpdEntries, entry.Mac)
	}

	changeDhcpHosts()
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
        option subnet-mask {{.NetMask}};
        option interface-mtu {{.Mtu}};
        use-host-decl-names on;

        group full {
            option domain-name-servers {{.Gateway}};
            option routers {{.Gateway}};
            {{ if ne .DnsDomain "" }}
            option domain-name {{.DnsDomain}};
            {{ end }}

			{{ range .FullEntries }}
            host {{.HostName}} {
                option host-name {{.HostName}};
                fixed-address {{.Ip}};
                hardware ethernet {{.Mac}};
            }
			{{ end }}
        }  

        group partial {
            {{ range .PartEntries }}
            host {{.HostName}} {
                option host-name {{.HostName}};
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
	return nil
}

func makeDhcpFirewallRuleDescription(nicname string) string {
	return fmt.Sprintf("DHCP-for-%s", nicname)
}

func startDhcpServer(dhcp dhcpServer) {
	nicname, err := utils.GetNicNameByMac(dhcp.NicMac)
	utils.PanicOnError(err)
	pidFile, conFile, leaseFile, logFile := getDhcpServerPath(nicname)
	/* lease file must be created first */
	utils.CreateFileIfNotExists(leaseFile, os.O_WRONLY|os.O_APPEND, 0666)
	os.Truncate(leaseFile, 0)
	os.Remove(pidFile)

	subnet := strings.Split(dhcp.Subnet, "/")
	dhcpServer := map[string]interface{}{}
	dhcpServer["OMAPIPort"] = getNicOmApiPort(nicname)
	dhcpServer["SubnetName"] = makeLanName(nicname)
	dhcpServer["Subnet"] = subnet[0]
	dhcpServer["NetMask"] = dhcp.Netmask
	dhcpServer["Mtu"] = dhcp.Mtu
	dhcpServer["Gateway"] = dhcp.Gateway
	dhcpServer["MaxLeaseTime"] = MAX_LEASE_TIME
	dhcpServer["DnsDomain"] = dhcp.DnsDomain
	dhcpServer["DnsServers"] = dhcp.Gateway

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
	dhcpServer["LogFile"] = logFile

	var buf bytes.Buffer
	tmpl, err := template.New("conf").Parse(dhcpServerTemplate)
	utils.PanicOnError(err)
	err = tmpl.Execute(&buf, dhcpServer)
	utils.PanicOnError(err)
	err = ioutil.WriteFile(conFile, buf.Bytes(), 0755)
	utils.PanicOnError(err)

	/* start dhcp server for nic */
	b := &utils.Bash{
		Command: fmt.Sprintf("sudo %s -pf %s -cf %s -lf %s", DHCPD_BIN_PATH, pidFile, conFile, leaseFile),
	}
	err = b.Run()

	if utils.IsSkipVyosIptables() {
		setDhcpFirewallRules(nicname)
	} else {
		tree := server.NewParserFromShowConfiguration().Tree
		des := makeDhcpFirewallRuleDescription(nicname)
		if r := tree.FindFirewallRuleByDescription(nicname, "local", des); r == nil {
			tree.SetFirewallOnInterface(nicname, "local",
				fmt.Sprintf("description %v", des),
				"destination port 67-68",
				"protocol udp",
				"action accept",
			)

			tree.AttachFirewallToInterface(nicname, "local")
		}
		tree.Apply(false)
	}

	for _, entry := range dhcp.DhcpInfos {
		dhcpdEntries[entry.Mac] = entry
	}
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

	bash := utils.Bash{
		Command: fmt.Sprintf("sudo mv %s /etc/rsyslog.d/dhcp.conf; sudo mv %s /etc/logrotate.d/dhcp; sudo /etc/init.d/rsyslog restart",
			dhcp_log_file.Name(), dhcp_log_rotatoe_file.Name()),
	}
	err = bash.Run()
	utils.PanicOnError(err)
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
	dhcpdEntries = make(map[string]dhcpInfo)
	enableDhcpLog()
}

func DhcpEntryPoint() {
	server.RegisterAsyncCommandHandler(ADD_DHCP_PATH, server.VyosLock(addDhcpHandler))
	server.RegisterAsyncCommandHandler(REMOVE_DHCP_PATH, server.VyosLock(removeDhcpHandler))
	server.RegisterAsyncCommandHandler(REFRESH_DHCP_SERVER_PATH, server.VyosLock(refreshDhcpServer))
	server.RegisterAsyncCommandHandler(START_DHCP_SERVER_PATH, server.VyosLock(startDhcpServerCmd))
	server.RegisterAsyncCommandHandler(STOP_DHCP_SERVER_PATH, server.VyosLock(stopDhcpServerCmd))
}
