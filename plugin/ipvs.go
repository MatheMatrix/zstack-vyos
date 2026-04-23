package plugin

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
	"zstack-vyos/server"
	"zstack-vyos/utils"

	prom "github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
)

type IpvsConnectionType int

const (
	IpvsConnectionTypeDR IpvsConnectionType = iota + 1
	IpvsConnectionTypeNAT
	IpvsConnectionTypeTUNNEL
)

// IpvsProtoTCP / IpvsProtoUDP are the canonical internal forms of
// IpvsFrontendService.ProtocolType / IpvsBackendServer.ProtocolType
// (F-016 normalization).  Code that shells out to ipvsadm should call
// IpvsadmProtoFlag to translate to the CLI flag form.
const (
	IpvsProtoTCP    = "tcp"
	IpvsProtoUDP    = "udp"
	IpvsProtoFwmark = "fwmark"
)

// IpvsadmProtoFlag returns the ipvsadm CLI flag ("-t" / "-u" / "-f")
// corresponding to a normalized internal protocol string.  Unknown protocols
// return "" so callers fail loudly instead of silently building wrong
// command lines.
func IpvsadmProtoFlag(proto string) string {
	switch strings.ToLower(proto) {
	case IpvsProtoTCP, "-t":
		return "-t"
	case IpvsProtoUDP, "-u":
		return "-u"
	case IpvsProtoFwmark, "-f":
		return "-f"
	}
	return ""
}

// NormalizeIpvsProto migrates legacy ipvsadm-flag form ("-t"/"-u") and
// uppercase form ("TCP"/"UDP") to the canonical lowercase internal form
// ("tcp"/"udp").  Used both at construction time and when loading persisted
// JSON written by older builds.
func NormalizeIpvsProto(proto string) string {
	switch strings.ToLower(proto) {
	case "-t", IpvsProtoTCP:
		return IpvsProtoTCP
	case "-u", IpvsProtoUDP:
		return IpvsProtoUDP
	case "-f", IpvsProtoFwmark:
		return IpvsProtoFwmark
	}
	return strings.ToLower(proto)
}

const (
	IPVS_LOG_CHAIN_NAME      = "ipvs-log"
	IPVS_FULL_NAT_CHAIN_NAME = "ipvs-full-nat"
	IPVS_LOG_IPSET_NAME      = "ipvs-set"
	IPVS_LOG_IPSET6_NAME     = "ipvs6-set"
	IPVS_LOG_PREFIX          = "ipvs-log"

	IPVS_HEALTH_CHECK_BIN_FILE      = "/usr/local/bin/ipvsHealthCheck"
	IPVS_HEALTH_CHECK_BIN_FILE_VYOS = "/opt/vyatta/sbin/ipvsHealthCheck"
	IPVS_HEALTH_CHECK_CONFIG_FILE   = "/etc/ipvs/healthcheck.conf"
	IPVS_HEALTH_CHECK_LOG_FILE      = "/var/log/ipvs_health_check.log"
	IPVS_HEALTH_CHECK_START_LOG     = "/var/log/ipvs_health_check_start.log"
	IPVS_HEALTH_CHECK_PID_FILE      = "/var/run/ipvs_health_check.pid"
)

func (cType IpvsConnectionType) String() string {
	switch cType {
	case IpvsConnectionTypeDR:
		return "-g"
	case IpvsConnectionTypeNAT:
		return "-m"
	case IpvsConnectionTypeTUNNEL:
		return "-i"
	default:
		return "Unknown"
	}
}

/*
	ZStack need 4 scheduling methods:

scheduling-method Algorithm for allocating TCP connections and UDP datagrams to real servers. Scheduling algorithms are implemented as kernel modules. Ten are shipped with the Linux Virtual Server:
rr - Robin Robin: distributes jobs equally amongst the available real servers.
wrr - Weighted Round Robin: assigns jobs to real servers proportionally to there real servers' weight. Servers with higher weights receive new jobs first and get more jobs than servers with lower weights. Servers with equal weights get an equal distribution of new jobs.
lc - Least-Connection: assigns more jobs to real servers with fewer active jobs.
wlc - Weighted Least-Connection: assigns more jobs to servers with fewer jobs and relative to the real servers' weight (Ci/Wi). This is the default.
lblc - Locality-Based Least-Connection: assigns jobs destined for the same IP address to the same server if the server is not overloaded and available; otherwise assign jobs to servers with fewer jobs, and keep it for future assignment.
lblcr - Locality-Based Least-Connection with Replication: assigns jobs destined for the same IP address to the least-connection node in the server set for the IP address. If all the node in the server set are over loaded, it picks up a node with fewer jobs in the cluster and adds it in the sever set for the target. If the server set has not been modified for the specified time, the most loaded node is removed from the server set, in order to avoid high degree of replication.
dh - Destination Hashing: assigns jobs to servers through looking up a statically assigned hash table by their destination IP addresses.
sh - Source Hashing: assigns jobs to servers through looking up a statically assigned hash table by their source IP addresses.
sed - Shortest Expected Delay: assigns an incoming job to the server with the shortest expected delay. The expected delay that the job will experience is (Ci + 1) / Ui if sent to the ith server, in which Ci is the number of jobs on the the ith server and Ui is the fixed service rate (weight) of the ith server.
nq - Never Queue: assigns an incoming job to an idle server if there is, instead of waiting for a fast one; if all the servers are busy, it adopts the Shortest Expected Delay policy to assign the job.
*/
type IpvsSchedulerType int

const (
	IpvsSchedulerRR IpvsSchedulerType = iota + 1
	IpvsSchedulerWRR
	IpvsSchedulerLC
	IpvsSchedulerSH
)

func (sch IpvsSchedulerType) String() string {
	switch sch {
	case IpvsSchedulerRR:
		return "rr"
	case IpvsSchedulerWRR:
		return "wrr"
	case IpvsSchedulerLC:
		return "lc"
	case IpvsSchedulerSH:
		return "sh"
	default:
		return "Unknown"
	}
}

func GetIpvsSchedulerTypeFromString(sch string) IpvsSchedulerType {
	switch strings.ToLower(sch) {
	case "roundrobin":
		return IpvsSchedulerRR
	case IpvsSchedulerRR.String():
		return IpvsSchedulerRR
	case "weightroundrobin":
		return IpvsSchedulerWRR
	case IpvsSchedulerWRR.String():
		return IpvsSchedulerWRR
	case "leastconn":
		return IpvsSchedulerLC
	case IpvsSchedulerLC.String():
		return IpvsSchedulerLC
	case "source":
		return IpvsSchedulerSH
	case IpvsSchedulerSH.String():
		return IpvsSchedulerSH
	default:
		return IpvsSchedulerRR
	}
}

func makeIpvsFirewallRuleDescription(lb LbInfo) string {
	return fmt.Sprintf("%s-%v-%v", utils.IpvsComment, lb.LbUuid, lb.ListenerUuid)
}

type IpvsBackendServer struct {
	/* for ipvsadm, ConnectionType is configure for each backend server */
	ConnectionType string // "dr", "tunnel", "nat"
	Weight         string // "default 1"
	BackendIp      string
	BackendPort    string
	Counter        LbCounter

	*IpvsFrontendService
}

type IpvsFrontendService struct {
	/* for keepalived, ConnectionType is configure for frontEndService */
	ConnectionType string // "dr", "tunnel", "nat"
	ProtocolType   string // "tcp", "udp", "fwmark"
	Scheduler      string // "rr|wrr|lc|wlc|lblc|lblcr|dh|sh|sed|nq"
	FrontIp        string
	FrontPort      string
	SessionNumber  uint64

	AclType  string   // "black" or "white"
	AclEntry []string // List of IP addresses or CIDR ranges

	BackendServers map[string]*IpvsBackendServer
	LbInfo
	LbParams
}

type IpvsConf struct {
	Services map[string]*IpvsFrontendService
}

var gIpvsConf *IpvsConf
var ipvsHealthCheckPidMon *utils.PidMon

/* first key: lbUuid, second key is listenerUuid */
var gIpvsLbInfoMap map[string]map[string]LbInfo
var gEnableLog = false

type IpvsHealthCheckBackendServer struct {
	LbUuid       string
	ListenerUuid string

	ConnectionType string // "dr", "tunnel", "nat"
	ProtocolType   string // "tcp", "udp", "fwmark"
	Scheduler      string // "rr|wrr|lc|wlc|lblc|lblcr|dh|sh|sed|nq"
	FrontIp        string
	FrontPort      string

	Weight      string // "default 1"
	BackendIp   string
	BackendPort string

	HealthCheckProtocol string
	HealthCheckPort     int
	HealthCheckInterval int
	HealthCheckTimeout  int
	HealthyThreshold    uint
	UnhealthyThreshold  uint

	MaxConnection int
	MinConnection int
}

func (bs *IpvsHealthCheckBackendServer) CopyParamsFrom(other *IpvsHealthCheckBackendServer) {
	bs.ConnectionType = other.ConnectionType
	bs.Scheduler = other.Scheduler
	bs.Weight = other.Weight
	bs.HealthCheckProtocol = other.HealthCheckProtocol
	bs.HealthCheckPort = other.HealthCheckPort
	bs.HealthCheckInterval = other.HealthCheckInterval
	bs.HealthCheckTimeout = other.HealthCheckTimeout
	bs.HealthyThreshold = other.HealthyThreshold
	bs.UnhealthyThreshold = other.UnhealthyThreshold
	bs.MaxConnection = other.MaxConnection
	bs.MinConnection = other.MinConnection
}

type IpvsHealthCheckFrontService struct {
	LbUuid       string
	ListenerUuid string

	ConnectionType string // "dr", "tunnel", "nat"
	ProtocolType   string // "tcp", "udp", "fwmark"
	Scheduler      string // "rr|wrr|lc|wlc|lblc|lblcr|dh|sh|sed|nq"
	FrontIp        string
	FrontPort      string

	BackendServers []*IpvsHealthCheckBackendServer
}

type IpvsHealthCheckConf struct {
	Services []*IpvsHealthCheckFrontService
}

func (hcConf *IpvsHealthCheckConf) FromIpvsConf(conf *IpvsConf) *IpvsHealthCheckConf {
	hcConf.Services = nil
	for _, fs := range conf.Services {
		hcFs := IpvsHealthCheckFrontService{
			LbUuid:       fs.LbInfo.LbUuid,
			ListenerUuid: fs.LbInfo.ListenerUuid,

			FrontIp:        fs.FrontIp,
			FrontPort:      fs.FrontPort,
			ProtocolType:   fs.ProtocolType,
			Scheduler:      fs.Scheduler,
			ConnectionType: fs.ConnectionType,

			BackendServers: []*IpvsHealthCheckBackendServer{},
		}

		for _, bs := range fs.BackendServers {
			hcBs := IpvsHealthCheckBackendServer{
				LbUuid:       bs.LbUuid,
				ListenerUuid: bs.ListenerUuid,

				ConnectionType: bs.ConnectionType,
				ProtocolType:   bs.ProtocolType,
				Scheduler:      bs.Scheduler,
				FrontIp:        bs.FrontIp,
				FrontPort:      bs.FrontPort,

				Weight:        bs.Weight,
				BackendIp:     bs.BackendIp,
				BackendPort:   bs.BackendPort,
				MaxConnection: bs.maxConnection,
				MinConnection: bs.minConnection,

				HealthCheckProtocol: bs.healthCheckProtocl,
				HealthCheckPort:     bs.healthCheckPort,
				HealthCheckInterval: bs.healthCheckInterval,
				HealthCheckTimeout:  bs.healthCheckTimeout,
				HealthyThreshold:    bs.healthyThreshold,
				UnhealthyThreshold:  bs.unhealthyThreshold,
			}

			hcFs.BackendServers = append(hcFs.BackendServers, &hcBs)
		}

		hcConf.Services = append(hcConf.Services, &hcFs)
	}

	return hcConf
}

func (ipvs *IpvsConf) ipvsadmSave() (*IpvsConf, error) {
	b := utils.Bash{
		Command: "ipvsadm-save -n",
		Sudo:    true,
	}

	ret, o, _, err := b.RunWithReturn()
	if ret != 0 || err != nil {
		return nil, fmt.Errorf("failed to execute ipvsadm-save, %v", err)
	}

	err = ipvs.ParseIpvs(o)
	return ipvs, err
}

func (ipvs *IpvsConf) ParseIpvs(content string) error {
	services := map[string]*IpvsFrontendService{}

	/* # ipvsadm-save -n
	-A -t 172.25.116.175:80 -s rr
	-a -t 172.25.116.175:80 -r 192.168.1.180:80 -m -w 1
	-a -t 172.25.116.175:80 -r 192.168.1.230:80 -m -w 1
	-A -u 172.25.116.175:8080 -s rr
	-a -u 172.25.116.175:8080 -r 192.168.1.180:80 -m -w 1
	-a -u 172.25.116.175:8080 -r 192.168.1.230:80 -m -w 1
	*/
	lines := strings.Split(content, "\n")
	var service *IpvsFrontendService
	for _, line := range lines {
		line := strings.TrimSpace(line)
		if line == "" {
			continue
		}

		items := strings.Fields(line)
		protocol := items[1]

		if items[0] == "-A" {
			ip := ""
			port := ""
			if strings.Contains(items[2], "]") {
				ipports := strings.Split(items[2], "]")
				ip = strings.Trim(ipports[0], "[")
				port = strings.Trim(ipports[1], ":")
			} else {
				ipports := strings.Split(items[2], ":")
				ip = ipports[0]
				port = ipports[1]
			}

			scheduler := items[4]
			info := LbInfo{}
			if strings.Contains(ip, ":") {
				info.Vip6 = ip
			} else {
				info.Vip = ip
			}
			info.LoadBalancerPort, _ = strconv.Atoi(port)
			if protocol == "-u" {
				info.Mode = "udp"
			}

			param := LbParams{}
			param.balancerAlgorithm = scheduler

			service = NewIpvsFrontService(info, param, ip, map[string]*IpvsBackendServer{})
			services[service.getFrontendServiceKey()] = service
		} else if items[0] == "-a" {
			backendIp := ""
			backendPort := ""
			if strings.Contains(items[4], "]") {
				ipports := strings.Split(items[4], "]")
				backendIp = strings.Trim(ipports[0], "[")
				backendPort = strings.Trim(ipports[1], ":")
			} else {
				ipports := strings.Split(items[4], ":")
				backendIp = ipports[0]
				backendPort = ipports[1]
			}

			service.ConnectionType = items[5]
			weight := items[7]
			backend := NewIpvsBackendServer(backendIp, backendPort, weight, service)
			service.BackendServers[backend.GetBackendKey()] = backend
		}
	}

	ipvs.Services = services
	return nil
}

func (conf *IpvsConf) ReloadIpvsHealthCheckConfig() {
	hcConf := IpvsHealthCheckConf{}
	hcConf.FromIpvsConf(conf)
	err := utils.JsonStoreConfig(IPVS_HEALTH_CHECK_CONFIG_FILE, hcConf)
	utils.PanicOnError(err)

	pid, err := utils.ReadPid(IPVS_HEALTH_CHECK_PID_FILE)
	utils.PanicOnError(err)

	b := utils.Bash{
		Command: fmt.Sprintf("kill -HUP %d", pid),
		Sudo:    true,
	}

	err = b.Run()
	utils.PanicOnError(err)
}

func NewIpvsBackendServer(serverIp, serverPort, weight string, frontService *IpvsFrontendService) *IpvsBackendServer {
	return &IpvsBackendServer{
		ConnectionType:      frontService.ConnectionType,
		Weight:              weight,
		BackendIp:           serverIp,
		BackendPort:         serverPort,
		Counter:             LbCounter{lbUuid: frontService.LbUuid, listenerUuid: frontService.ListenerUuid},
		IpvsFrontendService: frontService,
	}
}

func NewIpvsFrontService(info LbInfo, param LbParams, frontIp string, servers map[string]*IpvsBackendServer) *IpvsFrontendService {
	connectionType := IpvsConnectionTypeNAT.String()
	protocolType := IpvsProtoUDP
	if info.Mode == LB_MODE_HTTPS || info.Mode == LB_MODE_HTTP || info.Mode == LB_MODE_TCP {
		protocolType = IpvsProtoTCP
	}
	scheduler := GetIpvsSchedulerTypeFromString(param.balancerAlgorithm)
	return &IpvsFrontendService{
		ConnectionType: connectionType,
		ProtocolType:   protocolType,
		Scheduler:      scheduler.String(),
		FrontIp:        frontIp,
		FrontPort:      fmt.Sprintf("%d", info.LoadBalancerPort),
		SessionNumber:  0,
		BackendServers: servers,
		LbInfo:         info,
		LbParams:       param,
	}
}

func NewIpvsConfFromSave() (*IpvsConf, error) {
	conf := IpvsConf{
		Services: map[string]*IpvsFrontendService{},
	}
	_, err := conf.ipvsadmSave()
	return &conf, err
}

func (fs *IpvsFrontendService) getFrontendServiceKey() string {
	return fs.ProtocolType + "-" + fs.FrontIp + "-" + fs.FrontPort
}

func (fs *IpvsFrontendService) EnableIpvsLog() (err error) {

	ipset := utils.GetIpSet(IPVS_LOG_IPSET_NAME)
	ipset.Member = []string{}
	protol := IpvsProtoUDP
	if fs.ProtocolType == IpvsProtoTCP {
		protol = IpvsProtoTCP
	}

	frontIp := fs.FrontIp
	ip := net.ParseIP(frontIp)
	if ip != nil && ip.To4() == nil {
		frontIp = fmt.Sprintf("[%s]", frontIp)
		/* TODO: ip6tables is not added */
		return nil
	}

	err = ipset.AddMember([]string{frontIp + "," + protol + ":" + fs.FrontPort})
	utils.PanicOnError(err)

	return nil
}

func (fs *IpvsFrontendService) DisableIpvsLog() (err error) {
	ipset := utils.GetIpSet(IPVS_LOG_IPSET_NAME)
	ipset.Member = []string{}
	protol := IpvsProtoUDP
	if fs.ProtocolType == IpvsProtoTCP {
		protol = IpvsProtoTCP
	}

	frontIp := fs.FrontIp
	ip := net.ParseIP(frontIp)
	if ip != nil && ip.To4() == nil {
		frontIp = fmt.Sprintf("[%s]", frontIp)
	}

	ipset.DeleteMember([]string{frontIp + "," + protol + ":" + fs.FrontPort})

	return nil
}

func refreshIpvsFirewallRuleByVyos(services map[string]*IpvsFrontendService) error {
	tree := server.NewParserFromShowConfiguration().Tree

	//remove old rule, the reconfigure it
	nics, _ := utils.GetAllNics()
	for _, nic := range nics {
		for {
			if r := tree.FindFirewallRuleByDescriptionRegex(
				nic.Name, "in", utils.IpvsComment, utils.StringRegCompareFn); r != nil {
				r.Delete()
			} else {
				break
			}
		}
		for {
			if r := tree.FindFirewallRuleByDescriptionRegex(
				nic.Name, "local", utils.IpvsComment, utils.StringRegCompareFn); r != nil {
				r.Delete()
			} else {
				break
			}
		}
	}

	changed := false
	for _, fs := range services {
		changed = true
		des := makeIpvsFirewallRuleDescription(fs.LbInfo)
		nicname, err := utils.GetNicNameByMac(fs.PublicNic)
		utils.PanicOnError(err)
		proto := utils.IPTABLES_PROTO_UDP
		if fs.ProtocolType == IpvsProtoTCP {
			proto = utils.IPTABLES_PROTO_TCP
		}

		if r := tree.FindFirewallRuleByDescription(nicname, "local", des); r == nil {
			tree.SetFirewallOnInterface(nicname, "local",
				fmt.Sprintf("description %v", des),
				fmt.Sprintf("destination address %v", fs.Vip),
				fmt.Sprintf("destination port %v", fs.LoadBalancerPort),
				fmt.Sprintf("protocol %s", proto),
				"action accept",
			)

			configureInternalFirewallRule(tree, des,
				fmt.Sprintf("description %v", des),
				fmt.Sprintf("destination address %v", fs.Vip),
				fmt.Sprintf("destination port %v", fs.LoadBalancerPort),
				fmt.Sprintf("protocol %s", proto),
				"action accept",
			)
		}

		tree.AttachFirewallToInterface(nicname, "local")

		for _, bs := range fs.BackendServers {
			priNic := utils.GetNicForRoute(bs.BackendIp)
			priNic = strings.TrimSpace(priNic)
			if r := tree.FindFirewallRuleByDescription(priNic, "in", des); r == nil {
				tree.SetFirewallOnInterface(nicname, "in",
					fmt.Sprintf("description %v", des),
					fmt.Sprintf("source address %v", bs.BackendIp),
					fmt.Sprintf("source port %v", bs.BackendPort),
					fmt.Sprintf("protocol %s", proto),
					"action accept",
				)
			}
		}
		if fs.AclType != "" && len(fs.AclEntry) > 0 {
			err := fmt.Errorf("can not set UDP Load Balancer ACL on VyOS;please upgrade to ZStack Euler VRouter image")
			utils.PanicOnError(err)
		}
	}

	if changed {
		tree.Apply(false)
	}

	return nil
}

func refreshIpvsFullNatRules(services map[string]*IpvsFrontendService) {
	if !utils.IsSLB() {
		// only slb need full nat rule
		return
	}

	table := utils.NewIpTables(utils.NatTable)
	var rules []*utils.IpTableRule

	table.RemoveIpTableRuleByComments(utils.IpvsComment)

	for _, fs := range services {
		log.Debugf("refreshIpvsFullNatRules service %+v", fs)
		proto := utils.IPTABLES_PROTO_UDP
		if fs.ProtocolType == IpvsProtoTCP {
			proto = utils.IPTABLES_PROTO_TCP
		}

		for _, bs := range fs.BackendServers {
			if strings.Contains(bs.BackendIp, ":") {
				/* TODO: add ipv6 rules */
				continue
			}

			nicname := utils.GetNicForRoute(bs.BackendIp)
			nicname = strings.TrimSpace(nicname)
			nicIp, err := utils.GetIpByNicName(nicname)
			utils.PanicOnError(err)
			rule := utils.NewIpTableRule(IPVS_FULL_NAT_CHAIN_NAME)
			rule.SetDstIp(bs.BackendIp + "/32").SetDstPort(bs.BackendPort).SetProto(proto)
			rule.SetAction(utils.IPTABLES_ACTION_SNAT).SetSnatTargetIp(nicIp)
			rule.SetComment(utils.IpvsComment)
			rules = append(rules, rule)
		}
	}

	if gEnableLog {
		rule := utils.NewIpTableRule(IPVS_LOG_CHAIN_NAME)
		rule.SetActionLog(IPVS_LOG_PREFIX)
		rules = append(rules, rule)
	}

	if len(rules) != 0 {
		table.AddIpTableRules(rules)
	}

	err := table.Apply()
	utils.PanicOnError(err)
}

func refreshIpvsFirewallRuleByIptables(services map[string]*IpvsFrontendService) error {
	table := utils.NewIpTables(utils.FirewallTable)
	var rules []*utils.IpTableRule

	table.RemoveIpTableRuleByComments(utils.IpvsComment)

	for _, fs := range services {
		nicname, err := utils.GetNicNameByMac(fs.LbInfo.PublicNic)
		utils.PanicOnError(err)

		proto := utils.IPTABLES_PROTO_UDP
		if fs.ProtocolType == IpvsProtoTCP {
			proto = utils.IPTABLES_PROTO_TCP
		}

		if !strings.Contains(fs.FrontIp, ":") {
			rule := utils.NewIpTableRule(utils.GetRuleSetName(nicname, utils.RULESET_LOCAL))
			rule.SetAction(utils.IPTABLES_ACTION_ACCEPT).SetComment(utils.IpvsComment)
			rule.SetDstIp(fs.FrontIp).SetDstPort(fmt.Sprintf("%d", fs.LbInfo.LoadBalancerPort)).SetProto(proto)
			rules = append(rules, rule)

			priNics := utils.GetPrivteInterface()
			for _, priNic := range priNics {
				newRule := rule.Copy()
				newRule.SetChainName(utils.GetRuleSetName(priNic, utils.RULESET_LOCAL))
				rules = append(rules, newRule)
			}
		}

		for _, bs := range fs.BackendServers {
			if strings.Contains(bs.BackendIp, ":") {
				continue
			}

			nicname := utils.GetNicForRoute(bs.BackendIp)
			nicname = strings.TrimSpace(nicname)
			rule := utils.NewIpTableRule(utils.GetRuleSetName(nicname, utils.RULESET_IN))
			rule.SetAction(utils.IPTABLES_ACTION_ACCEPT).SetComment(utils.IpvsComment)
			rule.SetSrcIp(bs.BackendIp).SetSrcPort(bs.BackendPort).SetProto(proto)
			rules = append(rules, rule)
		}
		if fs.AclType != "" && len(fs.AclEntry) > 0 {
			rules = append(rules, addAclRules(table, fs, nicname, proto)...)
		}
	}
	if len(rules) != 0 {
		table.AddIpTableRules(rules)
	}
	log.Debugf("all rules list are %s", rules)
	return table.Apply()
}

func addAclRules(table *utils.IpTables, fs *IpvsFrontendService, nicname string, proto string) []*utils.IpTableRule {
	var rules []*utils.IpTableRule

	if fs.AclType == "" || len(fs.AclEntry) == 0 {
		return rules
	}

	// create new chain
	chainName := fmt.Sprintf("acl-rules@%s@%v", nicname, fs.FrontPort)
	table.AddChain(chainName)
	rule := utils.NewIpTableRule(utils.GetRuleSetName(nicname, utils.RULESET_LOCAL))
	// Make sure this firewall rule is positioned at the top
	rule.SetAction(chainName).SetInNic(nicname).SetProto(proto).SetComment(utils.IpvsComment).SetDstPort(fs.FrontPort).SetPriority(-1)
	rules = append(rules, rule)

	// Basic rules for blacklist and whitelist
	for _, entry := range fs.AclEntry {
		rule := utils.NewIpTableRule(chainName)
		rule.SetDstIp(fs.FrontIp).SetDstPort(fs.FrontPort).SetProto(proto).SetComment(utils.IpvsComment)
		if fs.AclType == "black" {
			rule.SetAction(utils.IPTABLES_ACTION_REJECT).SetRejectType(utils.REJECT_TYPE_ICMP_UNREACHABLE)
		} else {
			rule.SetAction(utils.IPTABLES_ACTION_ACCEPT)
		}
		if strings.Contains(entry, "-") {
			ipRange := strings.Split(entry, "-")
			if len(ipRange) == 2 {
				startIP := ipRange[0]
				endIP := ipRange[1]
				rule.SetSrcIpRange(fmt.Sprintf("%s-%s", startIP, endIP))
			}
		} else {
			rule.SetSrcIp(entry)
		}
		rules = append(rules, rule)
	}

	// For the whitelist, add the default rejection rule
	if fs.AclType == "white" {
		rule := utils.NewIpTableRule(chainName)
		rule.SetDstIp(fs.FrontIp).SetDstPort(fs.FrontPort).SetProto(proto).SetComment(utils.IpvsComment)
		rule.SetAction(utils.IPTABLES_ACTION_REJECT).SetRejectType(utils.REJECT_TYPE_ICMP_UNREACHABLE)
		rules = append(rules, rule)
	}

	rule = utils.NewIpTableRule(chainName)
	rule.SetAction(utils.IPTABLES_ACTION_RETURN).SetComment(utils.IpvsComment)
	rules = append(rules, rule)

	return rules
}

func RefreshIpvsBackend() error {
	// Capture the current conf so we can detect scheduler changes below.
	oldConf := gIpvsConf

	services := map[string]*IpvsFrontendService{}
	for _, lb := range gIpvsLbInfoMap {
		for _, listener := range lb {
			if strings.ToLower(listener.Mode) != "udp" {
				/* current only udp lb use ipvs */
				continue
			}

			lbParam := ParseLbParams(listener)

			// parse ACL config
			var aclType string
			var aclEntries []string
			enableAcl := false
			for _, param := range listener.Parameters {
				parts := strings.Split(param, "::")
				if len(parts) != 2 {
					continue
				}

				switch parts[0] {
				case "accessControlStatus":
					// Acl are processed only when accessControlStatus is enabled
					if parts[1] == "enable" {
						enableAcl = true
					}
				case "aclType":
					aclType = parts[1]
				case "aclEntry":
					// If multiple IP addresses are separated by commas (,), split them
					aclEntries = strings.Split(parts[1], ",")
				}
			}

			var fs4, fs6 *IpvsFrontendService
			if listener.Vip != "" {
				fs4 = NewIpvsFrontService(listener, lbParam, listener.Vip, map[string]*IpvsBackendServer{})
				services[fs4.getFrontendServiceKey()] = fs4
				if enableAcl {
					fs4.AclType = aclType
					fs4.AclEntry = aclEntries
				}
			}

			if listener.Vip6 != "" {
				fs6 = NewIpvsFrontService(listener, lbParam, listener.Vip6, map[string]*IpvsBackendServer{})
				services[fs6.getFrontendServiceKey()] = fs6
				if enableAcl {
					fs6.AclType = aclType
					fs6.AclEntry = aclEntries
				}
			}

			for _, sg := range listener.ServerGroups {
				for _, bs := range sg.BackendServers {
					if listener.Vip != "" {
						bs := NewIpvsBackendServer(bs.Ip, fmt.Sprintf("%d", listener.InstancePort), fmt.Sprintf("%d", bs.Weight), fs4)
						if lbParam.healthCheckPort == 0 {
							bs.healthCheckPort = listener.InstancePort
						}
						fs4.BackendServers[bs.GetBackendKey()] = bs
					}

					if listener.Vip6 != "" {
						bs := NewIpvsBackendServer(bs.Ip, fmt.Sprintf("%d", listener.InstancePort), fmt.Sprintf("%d", bs.Weight), fs6)
						if lbParam.healthCheckPort == 0 {
							bs.healthCheckPort = listener.InstancePort
						}
						fs6.BackendServers[bs.GetBackendKey()] = bs
					}
				}
			}
		}
	}

	// F-013: detect runtime scheduler changes and apply them to the kernel
	// immediately.  This is the correct path for "change listener scheduler"
	// operations; the daemon's EditFrontService is a no-op by design.
	if oldConf != nil && ipvsAdmin != nil {
		for key, newFs := range services {
			if oldFs, ok := oldConf.Services[key]; ok {
				if oldFs.Scheduler != newFs.Scheduler {
					if err := ipvsAdmin.EditService(*newFs); err != nil {
						log.Warnf("[ipvs] EditService scheduler %s→%s for %s: %v",
							oldFs.Scheduler, newFs.Scheduler, key, err)
					}
				}
			}
		}
	}

	gIpvsConf = &IpvsConf{Services: services}
	gIpvsConf.ReloadIpvsHealthCheckConfig()

	// F-013: notify connected daemons of the new authoritative state.
	// Snapshot is the source of truth; any rs_event in flight against
	// the prior seq is naturally superseded.
	PushIpvsSnapshot()

	if utils.IsSkipVyosIptables() {
		err := refreshIpvsFirewallRuleByIptables(services)
		utils.PanicOnError(err)
	} else {
		err := refreshIpvsFirewallRuleByVyos(services)
		utils.PanicOnError(err)
	}

	refreshIpvsFullNatRules(services)

	return nil
}

func RefreshIpvsService(lbs map[string]LbInfo, enableLog bool) error {
	tempLbMaps := map[string]map[string]LbInfo{}
	for _, info := range lbs {
		if _, ok := tempLbMaps[info.LbUuid]; !ok {
			tempLbMaps[info.LbUuid] = make(map[string]LbInfo)
			tempLbMaps[info.LbUuid][info.ListenerUuid] = info
		} else {
			tempLbMaps[info.LbUuid][info.ListenerUuid] = info
		}
	}

	for lbUuid, lb := range tempLbMaps {
		for listenerUuid, listener := range lb {
			/* if there is no backend, delete listener */
			if len(listener.NicIps) == 0 {
				log.Debugf("no nics: %s", listenerUuid)
				delete(lb, listenerUuid)
				continue
			}

			if len(listener.ServerGroups) == 0 {
				log.Debugf("no server group: %s", listenerUuid)
				delete(lb, listenerUuid)
				continue
			}

			var servers []string
			for _, serverGroup := range listener.ServerGroups {
				for _, bs := range serverGroup.BackendServers {
					servers = append(servers, bs.Ip)
				}
			}
			if len(servers) == 0 {
				log.Debugf("no server group backend: %s", listenerUuid)
				delete(lb, listenerUuid)
				continue
			}
		}

		if len(lb) == 0 {
			log.Debugf("delete lb: %s", lbUuid)
			delete(gIpvsLbInfoMap, lbUuid)
		} else {
			gIpvsLbInfoMap[lbUuid] = lb
		}
	}

	gEnableLog = enableLog
	err := RefreshIpvsBackend()
	utils.PanicOnError(err)

	return nil
}

func DelIpvsService(lbs map[string]LbInfo) {
	for _, info := range lbs {
		delete(gIpvsLbInfoMap, info.LbUuid)
	}

	err := RefreshIpvsBackend()
	utils.PanicOnError(err)
}

func (bs *IpvsBackendServer) GetBackendKey() string {
	proto := IpvsProtoUDP
	if NormalizeIpvsProto(bs.ProtocolType) == IpvsProtoTCP {
		proto = IpvsProtoTCP
	}

	return proto + "-" + bs.FrontIp + "-" + bs.FrontPort + "-" + bs.BackendIp + "-" + bs.BackendPort
}

func getIpvsBackend(proto, frontIp, frontPort, backendIp, backendPort string) *IpvsBackendServer {
	for _, fs := range gIpvsConf.Services {
		for _, bs := range fs.BackendServers {
			if bs.BackendIp == backendIp && bs.BackendPort == backendPort &&
				bs.FrontIp == frontIp && bs.FrontPort == frontPort &&
				bs.ProtocolType == proto {
				return bs
			}
		}
	}

	log.Debugf("backend not found for :%s-%s-%s-%s-%s", proto, frontIp, frontPort, backendIp, backendPort)
	return nil
}

func GetIpvsFrontService(listenerUuid string) *IpvsFrontendService {
	for _, fs := range gIpvsConf.Services {
		if fs.ListenerUuid == listenerUuid {
			return fs
		}
	}

	log.Debugf("frontend not found for listenerUuid :%s", listenerUuid)
	return nil
}

func UpdateIpvsMetrics(c *loadBalancerCollector, ch chan<- prom.Metric) (err error) {
	if gIpvsConf.Services == nil {
		return
	}

	UpdateIpvsCounters()

	/* update listener total session */
	for _, fs := range gIpvsConf.Services {
		fs.SessionNumber = 0
		for _, bs := range fs.BackendServers {
			if bs.Counter.Status != 0 {
				fs.SessionNumber += bs.Counter.sessionNumber
			}
		}
	}

	for _, fs := range gIpvsConf.Services {
		maxConnection := 0
		for _, bs := range fs.BackendServers {
			cnt := &bs.Counter
			maxConnection = bs.maxConnection
			cnt.serverGroupUuid = getServerGroupUuidByBackend(cnt.ip, fs.LbInfo)
			ch <- prom.MustNewConstMetric(c.statusEntry, prom.GaugeValue, float64(cnt.Status), cnt.listenerUuid, cnt.ip, cnt.lbUuid, cnt.serverGroupUuid)
			ch <- prom.MustNewConstMetric(c.inByteEntry, prom.GaugeValue, float64(cnt.bytesIn), cnt.listenerUuid, cnt.ip, cnt.lbUuid, cnt.serverGroupUuid)
			ch <- prom.MustNewConstMetric(c.outByteEntry, prom.GaugeValue, float64(cnt.bytesOut), cnt.listenerUuid, cnt.ip, cnt.lbUuid, cnt.serverGroupUuid)
			ch <- prom.MustNewConstMetric(c.curSessionNumEntry, prom.GaugeValue, float64(cnt.sessionNumber), cnt.listenerUuid, cnt.ip, cnt.lbUuid)
			ch <- prom.MustNewConstMetric(c.refusedSessionNumEntry, prom.GaugeValue, float64(cnt.refusedSessionNumber), cnt.listenerUuid, cnt.ip, cnt.lbUuid)
			ch <- prom.MustNewConstMetric(c.totalSessionNumEntry, prom.GaugeValue, float64(cnt.totalSessionNumber), cnt.listenerUuid, cnt.ip, cnt.lbUuid)
			ch <- prom.MustNewConstMetric(c.concurrentSessionUsageEntry, prom.GaugeValue, float64(cnt.concurrentSessionNumber), cnt.listenerUuid, cnt.ip, cnt.lbUuid)
		}
		if maxConnection > 0 {
			ch <- prom.MustNewConstMetric(c.curSessionUsageEntry, prom.GaugeValue, float64(fs.SessionNumber*100/(uint64)(maxConnection)), fs.ListenerUuid, fs.LbUuid)
		}
	}

	return nil
}

// IpvsTabularRecord is one parsed "->" backend row from an `ipvsadm` tabular
// listing.  Proto is normalized to "tcp"/"udp" (F-016) so that the resulting
// keys feed directly into getIpvsBackend without further translation.
// Items is the raw `strings.Fields` split of the original "->" line.
type IpvsTabularRecord struct {
	Proto       string
	FrontIp     string
	FrontPort   string
	BackendIp   string
	BackendPort string
	Items       []string
}

// parseIpvsTabular parses output of either `ipvsadm -L -n --stats` or
// `ipvsadm -Ln --thresholds`.  It tracks the current TCP/UDP front-service
// and emits one record per "->" backend row.  Header / empty / unknown lines
// reset the front-service context so a stray "->" row never false-matches
// against an earlier service.  Fixes F-014: previously proto was hard-coded
// to "-u", causing every TCP backend lookup to miss; loop also `break`ed on
// first miss, dropping all subsequent backends.
func parseIpvsTabular(output string) []IpvsTabularRecord {
	var records []IpvsTabularRecord
	var proto, frontIp, frontPort string

	lines := strings.Split(output, "\n")
	if len(lines) > 3 {
		lines = lines[3:] // ignore the first 3 header lines
	} else {
		lines = nil
	}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		items := strings.Fields(line)
		if items[0] == "TCP" || items[0] == "UDP" {
			if items[0] == "TCP" {
				proto = IpvsProtoTCP
			} else {
				proto = IpvsProtoUDP
			}
			ipports := strings.Split(items[1], ":")
			frontIp = strings.Join(ipports[0:len(ipports)-1], ":")
			frontIp = strings.Trim(frontIp, "[")
			frontIp = strings.Trim(frontIp, "]")
			frontPort = ipports[len(ipports)-1]
		} else if items[0] == "->" {
			if proto == "" {
				continue
			}
			ipports := strings.Split(items[1], ":")
			backendIp := strings.Join(ipports[0:len(ipports)-1], ":")
			backendIp = strings.Trim(backendIp, "[")
			backendIp = strings.Trim(backendIp, "]")
			backendPort := ipports[len(ipports)-1]
			records = append(records, IpvsTabularRecord{
				Proto:       proto,
				FrontIp:     frontIp,
				FrontPort:   frontPort,
				BackendIp:   backendIp,
				BackendPort: backendPort,
				Items:       items,
			})
		} else {
			frontIp, frontPort, proto = "", "", ""
		}
	}
	return records
}

func UpdateIpvsCounters() {
	for _, fs := range gIpvsConf.Services {
		for _, bs := range fs.BackendServers {
			/* if it can not be updated by ipvsadm -L -n --stats, it's down*/
			bs.Counter.ip = bs.BackendIp
			bs.Counter.Status = 0
		}
	}

	b := utils.Bash{
		/*
			# ipvsadm -L -n --stats
			IP Virtual Server version 1.2.1 (size=4096)
			Prot LocalAddress:Port               Conns   InPkts  OutPkts  InBytes OutBytes
			  -> RemoteAddress:Port
			TCP  172.25.116.175:80                   0        0        0        0        0
			  -> 192.168.1.180:80                    0        0        0        0        0
			  -> 192.168.1.230:80                    0        0        0        0        0
			UDP  172.25.116.175:8080                 0        0        0        0        0
			  -> 192.168.1.180:80                    0        0        0        0        0
			  -> 192.168.1.230:80                    0        0        0        0        0
		*/
		Command: "ipvsadm -L -n --stats",
		Sudo:    true,
		NoLog:   true,
	}

	ret, o, _, err := b.RunWithReturn()
	if ret != 0 || err != nil {
		return
	}

	for _, r := range parseIpvsTabular(o) {
		bs := getIpvsBackend(r.Proto, r.FrontIp, r.FrontPort, r.BackendIp, r.BackendPort)
		if bs == nil {
			log.Debugf("GetIpvsCounters backend server for key:%s:%s:%s:%s:%s not found",
				r.Proto, r.FrontIp, r.FrontPort, r.BackendIp, r.BackendPort)
			continue
		}
		bs.Counter.ip = r.BackendIp
		bs.Counter.Status = 1
		bs.Counter.bytesIn, _ = strconv.ParseUint(strings.Trim(r.Items[5], " "), 10, 64)
		bs.Counter.bytesOut, _ = strconv.ParseUint(strings.Trim(r.Items[6], " "), 10, 64)
	}

	b = utils.Bash{
		/* example
		# ipvsadm -Ln --thresholds
		IP Virtual Server version 1.2.1 (size=4096)
		Prot LocalAddress:Port            Uthreshold Lthreshold ActiveConn InActConn
		  -> RemoteAddress:Port
		TCP  172.25.116.175:80 rr
		  -> 192.168.1.180:80             0          0          0          0
		  -> 192.168.1.181:80             10000      0          0          0
		  -> 192.168.1.182:80             10000      100        0          0
		*/
		Command: "ipvsadm -Ln --thresholds",
		Sudo:    true,
		NoLog:   true,
	}

	ret, o, _, err = b.RunWithReturn()
	if ret != 0 || err != nil {
		return
	}
	for _, r := range parseIpvsTabular(o) {
		bs := getIpvsBackend(r.Proto, r.FrontIp, r.FrontPort, r.BackendIp, r.BackendPort)
		if bs == nil {
			log.Debugf("GetIpvsCounters backend server for key:%s:%s:%s:%s:%s not found",
				r.Proto, r.FrontIp, r.FrontPort, r.BackendIp, r.BackendPort)
			continue
		}
		bs.Counter.sessionNumber, _ = strconv.ParseUint(strings.Trim(r.Items[4], " "), 10, 64)
		bs.Counter.concurrentSessionNumber = bs.Counter.sessionNumber
		bs.Counter.refusedSessionNumber, _ = strconv.ParseUint(strings.Trim(r.Items[5], " "), 10, 64)
		bs.Counter.totalSessionNumber = bs.Counter.sessionNumber + bs.Counter.refusedSessionNumber
	}
}

func StopIpvsHealthCheck() {
	if !utils.IsEuler2203() {
		ipvsHealthCheckPidMon.Destroy()
	} else {
		utils.ServiceOperation("ipvsHealthCheck", "stop")
	}
}

func startIpvsHealthCheckPidMon() {
	/* start ipvsHealthCheck */
	binPath := IPVS_HEALTH_CHECK_BIN_FILE
	if utils.IsVYOS() {
		binPath = IPVS_HEALTH_CHECK_BIN_FILE_VYOS
	}
	pid, err := utils.FindFirstPIDByPSExtern(true, binPath)
	if err != nil {
		log.Debugf("start ipvs health check")
		b := utils.Bash{
			Command: fmt.Sprintf("nohup %s -f %s -log %s -p %s > %s 2>&1 &", binPath,
				IPVS_HEALTH_CHECK_CONFIG_FILE, IPVS_HEALTH_CHECK_LOG_FILE,
				IPVS_HEALTH_CHECK_PID_FILE, IPVS_HEALTH_CHECK_START_LOG),
			Sudo: true,
		}
		err := b.Run()
		utils.PanicOnError(err)
	}

	time.Sleep(1 * time.Second)

	pid, err = utils.FindFirstPIDByPSExtern(true, binPath)
	log.Debugf("ipvs health check pid %d", pid)

	ipvsHealthCheckPidMon = utils.NewPidMon(pid, func() int {
		log.Warnf("start ipvs health check in PidMon")
		b := utils.Bash{
			Command: fmt.Sprintf("nohup %s -f %s -log %s -p %s > %s 2>&1 &", binPath,
				IPVS_HEALTH_CHECK_CONFIG_FILE, IPVS_HEALTH_CHECK_LOG_FILE,
				IPVS_HEALTH_CHECK_PID_FILE, IPVS_HEALTH_CHECK_START_LOG),
			Sudo: true,
		}
		err := b.Run()
		if err != nil {
			log.Warnf("failed to start ipvs health check: %v", err)
			return -1
		}

		pid, err := utils.FindFirstPIDByPSExtern(true, binPath)
		if err != nil {
			log.Warnf("failed to read ipvs health check pid: %v", err)
			return -1
		}

		return pid
	})
	log.Debugf("created ipvs health check PidMon")
	err = ipvsHealthCheckPidMon.Start()
	//utils.PanicOnError(err)
	if err != nil {
		log.Warnf("failed to start ipvs health check PidMon: %v", err)
	}
}

func InitIpvs() {
	gIpvsConf = &IpvsConf{}
	gIpvsLbInfoMap = make(map[string]map[string]LbInfo)

	// F-013: start the UDS server before health-check daemon so the
	// daemon's hello succeeds on first attempt.
	StartIpvsUdsServer()

	// add ipvs-log, ipvs-full-nat to nat table postrouting chain,
	// ipvs log must be ahead of ipvs-full-nat
	table := utils.NewIpTables(utils.NatTable)
	table.AddChain(IPVS_LOG_CHAIN_NAME)
	table.AddChain(IPVS_FULL_NAT_CHAIN_NAME)

	rule := utils.NewIpTableRule(utils.RULESET_SNAT.String())
	rule.SetIpvs(true)
	rule.SetAction(IPVS_LOG_CHAIN_NAME).SetCompareTarget(true).SetComment(utils.SystemTopRule)
	table.AddIpTableRules([]*utils.IpTableRule{rule})

	rule = utils.NewIpTableRule(utils.RULESET_SNAT.String())
	rule.SetIpvs(true)
	rule.SetAction(IPVS_FULL_NAT_CHAIN_NAME).SetCompareTarget(true).SetComment(utils.SystemTopRule)
	table.AddIpTableRules([]*utils.IpTableRule{rule})

	err := table.Apply()
	utils.PanicOnError(err)

	if utils.IsEuler2203() {
		utils.ServiceOperation("ipvsHealthCheck", "restart")
	} else {
		startIpvsHealthCheckPidMon()
	}

	bash := utils.Bash{
		Command: fmt.Sprintf("sysctl -w net.ipv4.vs.conntrack=1"),
		Sudo:    true,
	}
	bash.Run()
	bash.PanicIfError()
}

// ----- F-012: Listener wrappers for IPVS dispatch ------------------------------
//
// IpvsModeDR / IpvsModeFullNat are the values transported in LbInfo.IpvsMode
// from the management server.  An empty IpvsMode means "use legacy default":
//   - protocol udp -> IpvsFullNatListener (gobetween retired by Story S-002)
//   - protocol tcp/http/https -> HaproxyListener
//
// IpvsDRListener and IpvsFullNatListener satisfy the Listener interface but
// most operations are no-ops because the actual ipvsadm/iptables work is
// driven by the batch RefreshIpvsBackend() invoked once per refresh wave by
// commitIpvsListeners().  This preserves the O(1) full-state-rebuild
// semantics of the existing data plane while routing dispatch through the
// uniform Listener entry point.
const (
IpvsModeDR      = "dr"
IpvsModeFullNat = "fullnat"
)

func isIpvsListenerType(l Listener) bool {
switch l.(type) {
case *IpvsDRListener, *IpvsFullNatListener:
return true
}
return false
}

// commitIpvsListeners rebuilds the global IPVS state from the supplied
// listeners.  It replaces the former direct call to RefreshIpvsService.
// Callers MUST pass the complete set of IPVS listeners present in the wave,
// or use removeIpvsListeners separately for ones being torn down.
func commitIpvsListeners(listeners []Listener, enableLog bool) {
if len(listeners) == 0 {
return
}
lbs := make(map[string]LbInfo, len(listeners))
for _, l := range listeners {
info := l.getLbInfo()
lbs[info.ListenerUuid] = info
}
if err := RefreshIpvsService(lbs, enableLog); err != nil {
utils.PanicOnError(err)
}
}

// removeIpvsListeners tears down the IPVS state for the supplied listeners.
func removeIpvsListeners(listeners []Listener) {
if len(listeners) == 0 {
return
}
lbs := make(map[string]LbInfo, len(listeners))
for _, l := range listeners {
info := l.getLbInfo()
lbs[info.ListenerUuid] = info
}
DelIpvsService(lbs)
}

// IpvsFullNatListener is the Listener wrapper for IPVS FullNAT mode.
type IpvsFullNatListener struct {
lb           LbInfo
lastCounters *CachedCounters
}

func (l *IpvsFullNatListener) createListenerServiceConfigure(lb LbInfo) (err error) {
return nil
}
func (l *IpvsFullNatListener) checkIfListenerServiceUpdate(orig, curr string) (bool, error) {
return true, nil
}
func (l *IpvsFullNatListener) startListenerService() (int, error) { return 0, nil }
func (l *IpvsFullNatListener) stopListenerService() error         { return nil }
func (l *IpvsFullNatListener) postActionListenerServiceStop() (int, error) {
return 0, nil
}
func (l *IpvsFullNatListener) getLbCounters(listenerUuid string, _ Listener) <-chan CounterChanData {
ch := make(chan CounterChanData, 1)
close(ch)
return ch
}
func (l *IpvsFullNatListener) getLastCounters() *CachedCounters { return l.lastCounters }
func (l *IpvsFullNatListener) getIptablesRule() ([]*utils.IpTableRule, string) {
return nil, ""
}
func (l *IpvsFullNatListener) getIcmpIptablesRule() ([]*utils.IpTableRule, string) {
return nil, ""
}
func (l *IpvsFullNatListener) getSynIptablesRule() (*utils.IpTableRule, string) {
return nil, ""
}
func (l *IpvsFullNatListener) getLbInfo() LbInfo { return l.lb }
func (l *IpvsFullNatListener) startPidMonitor()  {}
func (l *IpvsFullNatListener) stopPidMonitor()   {}
func (l *IpvsFullNatListener) getMaxSession() int { return 0 }

// IpvsDRListener is the Listener wrapper for IPVS Direct-Routing mode.
// It behaves identically to IpvsFullNatListener at this layer; the actual
// ipvsadm rule shape is selected inside RefreshIpvsBackend based on the
// listener's IpvsMode.
type IpvsDRListener struct {
lb           LbInfo
lastCounters *CachedCounters
}

func (l *IpvsDRListener) createListenerServiceConfigure(lb LbInfo) (err error) {
return nil
}
func (l *IpvsDRListener) checkIfListenerServiceUpdate(orig, curr string) (bool, error) {
return true, nil
}
func (l *IpvsDRListener) startListenerService() (int, error) { return 0, nil }
func (l *IpvsDRListener) stopListenerService() error         { return nil }
func (l *IpvsDRListener) postActionListenerServiceStop() (int, error) {
return 0, nil
}
func (l *IpvsDRListener) getLbCounters(listenerUuid string, _ Listener) <-chan CounterChanData {
ch := make(chan CounterChanData, 1)
close(ch)
return ch
}
func (l *IpvsDRListener) getLastCounters() *CachedCounters { return l.lastCounters }
func (l *IpvsDRListener) getIptablesRule() ([]*utils.IpTableRule, string) {
return nil, ""
}
func (l *IpvsDRListener) getIcmpIptablesRule() ([]*utils.IpTableRule, string) {
return nil, ""
}
func (l *IpvsDRListener) getSynIptablesRule() (*utils.IpTableRule, string) {
return nil, ""
}
func (l *IpvsDRListener) getLbInfo() LbInfo  { return l.lb }
func (l *IpvsDRListener) startPidMonitor()   {}
func (l *IpvsDRListener) stopPidMonitor()    {}
func (l *IpvsDRListener) getMaxSession() int { return 0 }
