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

const (
	IPVS_LOG_CHAIN_NAME      = "ipvs-log"
	IPVS_FULL_NAT_CHAIN_NAME = "ipvs-full-nat"
	IPVS_LOG_IPSET_NAME      = "ipvs-set"
	IPVS_LOG_IPSET6_NAME     = "ipvs6-set"
	IPVS_LOG_PREFIX          = "ipvs-log"
	IPVS_ACL_CHAIN_PREFIX    = "acl-rules@"

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

func getIpvsConnectionTypeFromForwardMode(forwardMode string) IpvsConnectionType {
	switch strings.ToLower(forwardMode) {
	case LB_FORWARD_MODE_FULL_NAT, LB_FORWARD_MODE_NAT:
		return IpvsConnectionTypeNAT
	case LB_FORWARD_MODE_DR:
		return IpvsConnectionTypeDR
	default:
		return IpvsConnectionTypeNAT
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

func parseIpvsAclConfig(params []string) (string, []string, bool) {
	var aclType string
	var aclEntries []string
	enableAcl := false
	for _, param := range params {
		parts := strings.SplitN(param, "::", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "accessControlStatus":
			enableAcl = value == "enable"
		case "aclType":
			aclType = value
		case "aclEntry":
			for _, entry := range strings.Split(value, ",") {
				entry = strings.TrimSpace(entry)
				if entry != "" {
					aclEntries = append(aclEntries, entry)
				}
			}
		}
	}

	if !enableAcl || aclType == "" || len(aclEntries) == 0 {
		return "", nil, false
	}

	return aclType, aclEntries, true
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
			} else if protocol == "-t" {
				info.Mode = "tcp"
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
			for i := 8; i+1 < len(items); i++ {
				switch items[i] {
				case "-x":
					value, err := strconv.Atoi(items[i+1])
					if err != nil {
						return fmt.Errorf("invalid ipvs max connection %q", items[i+1])
					}
					backend.maxConnection = value
				case "-y":
					value, err := strconv.Atoi(items[i+1])
					if err != nil {
						return fmt.Errorf("invalid ipvs min connection %q", items[i+1])
					}
					backend.minConnection = value
				}
			}
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
	connectionType := getIpvsConnectionTypeFromForwardMode(info.ForwardMode).String()
	protocolType := "-u"
	if info.Mode == LB_MODE_HTTPS || info.Mode == LB_MODE_HTTP || info.Mode == LB_MODE_TCP {
		protocolType = "-t"
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

func validateIpvsAddress(address string) error {
	ip := net.ParseIP(address)
	if ip == nil {
		return fmt.Errorf("invalid ipvs address %q", address)
	}

	return nil
}

func formatIpvsAddress(address string) string {
	ip := net.ParseIP(address)
	if ip.To4() == nil {
		return fmt.Sprintf("[%s]", address)
	}

	return address
}

func validateIpvsPort(port string) error {
	value, err := strconv.Atoi(port)
	if err != nil || value <= 0 || value > 65535 {
		return fmt.Errorf("invalid ipvs port %q", port)
	}

	return nil
}

func validateIpvsScheduler(scheduler string) error {
	switch scheduler {
	case IpvsSchedulerRR.String(), IpvsSchedulerWRR.String(), IpvsSchedulerLC.String(), IpvsSchedulerSH.String():
		return nil
	default:
		return fmt.Errorf("invalid ipvs scheduler %q", scheduler)
	}
}

func validateIpvsConnectionType(connectionType string) error {
	switch connectionType {
	case IpvsConnectionTypeDR.String(), IpvsConnectionTypeNAT.String(), IpvsConnectionTypeTUNNEL.String():
		return nil
	default:
		return fmt.Errorf("invalid ipvs connection type %q", connectionType)
	}
}

func validateIpvsWeight(weight string) error {
	value, err := strconv.Atoi(weight)
	if err != nil || value < 0 {
		return fmt.Errorf("invalid ipvs weight %q", weight)
	}

	return nil
}

func ipvsProtocolArg(protocol string) string {
	if strings.EqualFold(protocol, "tcp") || strings.EqualFold(protocol, "-t") {
		return "-t"
	}

	return "-u"
}

func validateIpvsFrontendService(fs *IpvsFrontendService) error {
	if err := validateIpvsAddress(fs.FrontIp); err != nil {
		return err
	}
	if err := validateIpvsPort(fs.FrontPort); err != nil {
		return err
	}
	if err := validateIpvsScheduler(fs.Scheduler); err != nil {
		return err
	}

	return nil
}

func validateIpvsBackendServer(bs *IpvsBackendServer) error {
	if err := validateIpvsFrontendService(bs.IpvsFrontendService); err != nil {
		return err
	}
	if err := validateIpvsAddress(bs.BackendIp); err != nil {
		return err
	}
	if err := validateIpvsPort(bs.BackendPort); err != nil {
		return err
	}
	if err := validateIpvsConnectionType(bs.ConnectionType); err != nil {
		return err
	}
	if err := validateIpvsWeight(bs.Weight); err != nil {
		return err
	}

	return nil
}

func (fs *IpvsFrontendService) frontServiceAddress() string {
	return fmt.Sprintf("%s:%s", formatIpvsAddress(fs.FrontIp), fs.FrontPort)
}

func (bs *IpvsBackendServer) backendAddress() string {
	return fmt.Sprintf("%s:%s", formatIpvsAddress(bs.BackendIp), bs.BackendPort)
}

func makeIpvsAddServiceCommand(fs *IpvsFrontendService) string {
	proto := ipvsProtocolArg(fs.ProtocolType)
	return fmt.Sprintf("ipvsadm -A %s %s -s %s", proto, fs.frontServiceAddress(), fs.Scheduler)
}

func makeIpvsEnsureServiceCommand(fs *IpvsFrontendService) string {
	return fmt.Sprintf("%s || %s", makeIpvsAddServiceCommand(fs), makeIpvsEditServiceCommand(fs))
}

func makeIpvsEditServiceCommand(fs *IpvsFrontendService) string {
	proto := ipvsProtocolArg(fs.ProtocolType)
	return fmt.Sprintf("ipvsadm -E %s %s -s %s", proto, fs.frontServiceAddress(), fs.Scheduler)
}

func makeIpvsDeleteServiceCommand(fs *IpvsFrontendService) string {
	proto := ipvsProtocolArg(fs.ProtocolType)
	return fmt.Sprintf("ipvsadm -D %s %s", proto, fs.frontServiceAddress())
}

func makeIpvsAddBackendCommand(bs *IpvsBackendServer) string {
	proto := ipvsProtocolArg(bs.ProtocolType)
	return fmt.Sprintf("ipvsadm -a %s %s -r %s %s -w %s -x %d -y %d",
		proto, bs.frontServiceAddress(), bs.backendAddress(), bs.ConnectionType, bs.Weight,
		bs.maxConnection, bs.minConnection)
}

func makeIpvsEnsureBackendCommand(bs *IpvsBackendServer) string {
	return fmt.Sprintf("%s || %s", makeIpvsAddBackendCommand(bs), makeIpvsEditBackendCommand(bs))
}

func makeIpvsEditBackendCommand(bs *IpvsBackendServer) string {
	proto := ipvsProtocolArg(bs.ProtocolType)
	return fmt.Sprintf("ipvsadm -e %s %s -r %s %s -w %s -x %d -y %d",
		proto, bs.frontServiceAddress(), bs.backendAddress(), bs.ConnectionType, bs.Weight,
		bs.maxConnection, bs.minConnection)
}

func makeIpvsDeleteBackendCommand(bs *IpvsBackendServer) string {
	proto := ipvsProtocolArg(bs.ProtocolType)
	return fmt.Sprintf("ipvsadm -d %s %s -r %s",
		proto, bs.frontServiceAddress(), bs.backendAddress())
}

func sameIpvsBackend(current, desired *IpvsBackendServer) bool {
	return current.ConnectionType == desired.ConnectionType &&
		current.Weight == desired.Weight &&
		current.maxConnection == desired.maxConnection &&
		current.minConnection == desired.minConnection
}

func appendIpvsCommand(commands *[]string, cmd string) {
	*commands = append(*commands, cmd)
}

func syncIpvsadm(oldConf, desiredConf *IpvsConf) error {
	if desiredConf == nil {
		desiredConf = &IpvsConf{Services: map[string]*IpvsFrontendService{}}
	}
	if oldConf == nil {
		oldConf = &IpvsConf{Services: map[string]*IpvsFrontendService{}}
	}

	currentConf, err := NewIpvsConfFromSave()
	if err != nil {
		return err
	}

	var commands []string
	for key, fs := range desiredConf.Services {
		if err := validateIpvsFrontendService(fs); err != nil {
			return err
		}
		current := currentConf.Services[key]
		if current == nil {
			appendIpvsCommand(&commands, makeIpvsEnsureServiceCommand(fs))
		} else if current.Scheduler != fs.Scheduler {
			appendIpvsCommand(&commands, makeIpvsEditServiceCommand(fs))
		}

		for backendKey, bs := range fs.BackendServers {
			if err := validateIpvsBackendServer(bs); err != nil {
				return err
			}
			currentBackend := (*IpvsBackendServer)(nil)
			if current != nil {
				currentBackend = current.BackendServers[backendKey]
			}

			if currentBackend == nil {
				appendIpvsCommand(&commands, makeIpvsEnsureBackendCommand(bs))
			} else if !sameIpvsBackend(currentBackend, bs) {
				appendIpvsCommand(&commands, makeIpvsEditBackendCommand(bs))
			}
		}

		if old := oldConf.Services[key]; old != nil && current != nil {
			for backendKey, oldBackend := range old.BackendServers {
				if _, ok := fs.BackendServers[backendKey]; !ok {
					if current.BackendServers[backendKey] != nil {
						if err := validateIpvsBackendServer(oldBackend); err != nil {
							return err
						}
						appendIpvsCommand(&commands, makeIpvsDeleteBackendCommand(oldBackend))
					}
				}
			}
		}
	}

	for key, current := range currentConf.Services {
		if _, ok := desiredConf.Services[key]; ok {
			continue
		}
		if err := validateIpvsFrontendService(current); err != nil {
			return err
		}
		appendIpvsCommand(&commands, makeIpvsDeleteServiceCommand(current))
	}

	if len(commands) == 0 {
		return nil
	}

	b := utils.Bash{
		Command: "set -e; " + strings.Join(commands, "; "),
		Sudo:    true,
	}
	ret, stdout, stderr, err := b.RunWithReturn()
	if ret != 0 || err != nil {
		return fmt.Errorf("failed to sync ipvsadm, ret: %d, stdout: %s, stderr: %s, error: %v",
			ret, stdout, stderr, err)
	}

	return nil
}

func (fs *IpvsFrontendService) EnableIpvsLog() (err error) {

	ipset := utils.GetIpSet(IPVS_LOG_IPSET_NAME)
	ipset.Member = []string{}
	protol := "udp"
	if fs.ProtocolType == "-t" {
		protol = "tcp"
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
	protol := "udp"
	if fs.ProtocolType == "-t" {
		protol = "tcp"
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
		if fs.ProtocolType == "-t" || fs.ProtocolType == "tcp" {
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
			err := fmt.Errorf("can not set IPVS Load Balancer ACL on VyOS; please upgrade to ZStack Euler VRouter image")
			utils.PanicOnError(err)
		}
	}

	if changed {
		tree.Apply(false)
	}

	return nil
}

func makeIpvsFullLogRules(services map[string]*IpvsFrontendService) []*utils.IpTableRule {
	var rules []*utils.IpTableRule

	if !gEnableLog {
		return rules
	}

	for _, fs := range services {
		if !fs.LbInfo.EnableFullLog {
			continue
		}

		if ip := net.ParseIP(fs.FrontIp); ip != nil && ip.To4() == nil {
			/* TODO: add ipv6 rules */
			continue
		}

		rule := utils.NewIpTableRule(IPVS_LOG_CHAIN_NAME)
		rule.SetIpvs(true).SetIpvsVaddr(fs.FrontIp).SetIpvsVport(fs.FrontPort)
		rule.SetActionLog(IPVS_LOG_PREFIX).SetComment(utils.IpvsComment)
		rules = append(rules, rule)
	}

	return rules
}

func shouldInstallIpvsFullNatSnat(fs *IpvsFrontendService) bool {
	return fs.LbInfo.Mode != LB_MODE_TCP || strings.EqualFold(fs.LbInfo.ForwardMode, LB_FORWARD_MODE_FULL_NAT)
}

func shouldBypassPrivateNicSnat(fs *IpvsFrontendService) bool {
	return fs.LbInfo.Mode == LB_MODE_TCP &&
		(strings.EqualFold(fs.LbInfo.ForwardMode, LB_FORWARD_MODE_NAT) ||
			strings.EqualFold(fs.LbInfo.ForwardMode, LB_FORWARD_MODE_DR))
}

func isIpv6Address(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() == nil
}

func makeIpvsFullNatSnatRule(fs *IpvsFrontendService, bs *IpvsBackendServer, proto, nicIp string) *utils.IpTableRule {
	rule := utils.NewIpTableRule(IPVS_FULL_NAT_CHAIN_NAME)
	rule.SetIpvs(true).SetIpvsVaddr(fs.FrontIp).SetIpvsVport(fs.FrontPort)
	rule.SetDstIp(bs.BackendIp + "/32").SetDstPort(bs.BackendPort).SetProto(proto)
	rule.SetAction(utils.IPTABLES_ACTION_SNAT).SetSnatTargetIp(nicIp)
	rule.SetComment(utils.IpvsComment).SetPriority(utils.IpvsSnatRulePriority)
	return rule
}

func getIpvsPrivateNicSnatBypassDstIp(fs *IpvsFrontendService, bs *IpvsBackendServer) string {
	if strings.EqualFold(fs.LbInfo.ForwardMode, LB_FORWARD_MODE_DR) {
		return fs.FrontIp
	}

	return bs.BackendIp
}

func getIpvsPrivateNicSnatBypassDstPort(fs *IpvsFrontendService, bs *IpvsBackendServer) string {
	if strings.EqualFold(fs.LbInfo.ForwardMode, LB_FORWARD_MODE_DR) {
		return fs.FrontPort
	}

	return bs.BackendPort
}

func makeIpvsPrivateNicSnatBypassRule(fs *IpvsFrontendService, bs *IpvsBackendServer, proto string) *utils.IpTableRule {
	dstIp := getIpvsPrivateNicSnatBypassDstIp(fs, bs)
	dstPort := getIpvsPrivateNicSnatBypassDstPort(fs, bs)
	rule := utils.NewIpTableRule(utils.RULESET_SNAT.String())
	rule.SetIpvs(true).SetIpvsVaddr(fs.FrontIp).SetIpvsVport(fs.FrontPort)
	rule.SetDstIp(dstIp + "/32").SetDstPort(dstPort).SetProto(proto)
	rule.SetAction(utils.IPTABLES_ACTION_ACCEPT)
	rule.SetComment(utils.IpvsComment)
	return rule
}

func makeIpvsFullNatSnatRules(services map[string]*IpvsFrontendService) []*utils.IpTableRule {
	var rules []*utils.IpTableRule

	for _, fs := range services {
		if !shouldInstallIpvsFullNatSnat(fs) {
			continue
		}
		if isIpv6Address(fs.FrontIp) {
			/* TODO: add ipv6 rules */
			continue
		}

		log.Debugf("refreshIpvsFullNatRules service %+v", fs)
		proto := utils.IPTABLES_PROTO_UDP
		if fs.ProtocolType == "-t" || fs.ProtocolType == "tcp" {
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
			rules = append(rules, makeIpvsFullNatSnatRule(fs, bs, proto, nicIp))
		}
	}

	return rules
}

func makeIpvsPrivateNicSnatBypassRules(services map[string]*IpvsFrontendService) []*utils.IpTableRule {
	var rules []*utils.IpTableRule

	for _, fs := range services {
		if !shouldBypassPrivateNicSnat(fs) {
			continue
		}
		if isIpv6Address(fs.FrontIp) {
			/* TODO: add ipv6 rules */
			continue
		}

		proto := utils.IPTABLES_PROTO_UDP
		if fs.ProtocolType == "-t" || fs.ProtocolType == "tcp" {
			proto = utils.IPTABLES_PROTO_TCP
		}

		for _, bs := range fs.BackendServers {
			dstIp := getIpvsPrivateNicSnatBypassDstIp(fs, bs)
			if strings.Contains(dstIp, ":") {
				/* TODO: add ipv6 rules */
				continue
			}

			rules = append(rules, makeIpvsPrivateNicSnatBypassRule(fs, bs, proto))
		}
	}

	return rules
}

func makeIpvsNatRulesForAppliance(services map[string]*IpvsFrontendService, isSLB bool) []*utils.IpTableRule {
	rules := makeIpvsFullLogRules(services)
	if !isSLB {
		return append(rules, makeIpvsPrivateNicSnatBypassRules(services)...)
	}

	return append(rules, makeIpvsFullNatSnatRules(services)...)
}

func refreshIpvsFullNatRules(services map[string]*IpvsFrontendService) {
	table := utils.NewIpTables(utils.NatTable)
	isSLB := utils.IsSLB()
	rules := makeIpvsNatRulesForAppliance(services, isSLB)

	table.RemoveIpTableRuleByComments(utils.IpvsComment)

	if !isSLB {
		// Shared VRouter must bypass private-nic SNAT for TCP NAT/DR IPVS
		// flows, but still skips SLB-only full_nat SNAT rules.
		if len(rules) != 0 {
			table.AddIpTableRules(rules)
		}

		err := table.Apply()
		utils.PanicOnError(err)
		return
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
	cleanupIpvsAclChains(table)

	for _, fs := range services {
		nicname, err := utils.GetNicNameByMac(fs.LbInfo.PublicNic)
		utils.PanicOnError(err)

		proto := utils.IPTABLES_PROTO_UDP
		if fs.ProtocolType == "-t" || fs.ProtocolType == "tcp" {
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
	chainName := fmt.Sprintf("%s%s@%v", IPVS_ACL_CHAIN_PREFIX, nicname, fs.FrontPort)
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

func cleanupIpvsAclChains(table *utils.IpTables) {
	table.DeleteChainByKey(IPVS_ACL_CHAIN_PREFIX)
}

func RefreshIpvsBackend() error {
	services := map[string]*IpvsFrontendService{}
	for _, lb := range gIpvsLbInfoMap {
		for _, listener := range lb {
			if !isIpvsDataPlane(listener) {
				continue
			}

			lbParam := ParseLbParams(listener)

			aclType, aclEntries, enableAcl := parseIpvsAclConfig(listener.Parameters)

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

	desiredConf := &IpvsConf{Services: services}
	err := syncIpvsadm(gIpvsConf, desiredConf)
	if err != nil {
		return err
	}

	gIpvsConf = desiredConf
	gIpvsConf.ReloadIpvsHealthCheckConfig()

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

func shouldDeleteIpvsListener(listener LbInfo) bool {
	if len(listener.NicIps) == 0 {
		log.Debugf("no nics: %s", listener.ListenerUuid)
		return true
	}

	if len(listener.ServerGroups) == 0 {
		log.Debugf("no server group: %s", listener.ListenerUuid)
		return true
	}

	var servers []string
	for _, serverGroup := range listener.ServerGroups {
		for _, bs := range serverGroup.BackendServers {
			servers = append(servers, bs.Ip)
		}
	}
	if len(servers) == 0 {
		log.Debugf("no server group backend: %s", listener.ListenerUuid)
		return true
	}

	return false
}

func mergeIpvsServiceUpdates(current map[string]map[string]LbInfo, lbs map[string]LbInfo) map[string]map[string]LbInfo {
	merged := map[string]map[string]LbInfo{}
	for lbUuid, listeners := range current {
		merged[lbUuid] = map[string]LbInfo{}
		for listenerUuid, listener := range listeners {
			merged[lbUuid][listenerUuid] = listener
		}
	}

	for _, listener := range lbs {
		lbUuid := listener.LbUuid
		listenerUuid := listener.ListenerUuid
		if _, ok := merged[lbUuid]; !ok {
			merged[lbUuid] = map[string]LbInfo{}
		}

		if shouldDeleteIpvsListener(listener) {
			delete(merged[lbUuid], listenerUuid)
		} else {
			merged[lbUuid][listenerUuid] = listener
		}

		if len(merged[lbUuid]) == 0 {
			log.Debugf("delete lb: %s", lbUuid)
			delete(merged, lbUuid)
		}
	}

	return merged
}

func RefreshIpvsService(lbs map[string]LbInfo, enableLog bool) error {
	gIpvsLbInfoMap = mergeIpvsServiceUpdates(gIpvsLbInfoMap, lbs)
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
	proto := "udp"
	if strings.ToLower(bs.ProtocolType) == "tcp" || strings.ToLower(bs.ProtocolType) == "-t" {
		proto = "tcp"
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
			ch <- prom.MustNewConstMetric(c.curSessionNumEntry, prom.GaugeValue, float64(cnt.sessionNumber), cnt.listenerUuid, cnt.ip, cnt.lbUuid, cnt.serverGroupUuid)
			ch <- prom.MustNewConstMetric(c.refusedSessionNumEntry, prom.GaugeValue, float64(cnt.refusedSessionNumber), cnt.listenerUuid, cnt.ip, cnt.lbUuid, cnt.serverGroupUuid)
			ch <- prom.MustNewConstMetric(c.totalSessionNumEntry, prom.GaugeValue, float64(cnt.totalSessionNumber), cnt.listenerUuid, cnt.ip, cnt.lbUuid, cnt.serverGroupUuid)
			ch <- prom.MustNewConstMetric(c.concurrentSessionUsageEntry, prom.GaugeValue, float64(cnt.concurrentSessionNumber), cnt.listenerUuid, cnt.ip, cnt.lbUuid, cnt.serverGroupUuid)
		}
		if maxConnection > 0 {
			ch <- prom.MustNewConstMetric(c.curSessionUsageEntry, prom.GaugeValue, float64(fs.SessionNumber*100/(uint64)(maxConnection)), fs.ListenerUuid, fs.LbUuid)
		}
	}

	return nil
}

func UpdateIpvsCounters() {
	resetIpvsCounters()

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
	if ret == 0 && err == nil {
		updateIpvsCountersFromStats(o)
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
	if ret == 0 && err == nil {
		updateIpvsCountersFromThresholds(o)
	}
}

func resetIpvsCounters() {
	for _, fs := range gIpvsConf.Services {
		for _, bs := range fs.BackendServers {
			/* if it can not be updated by ipvsadm -L -n --stats, it's down*/
			bs.Counter.ip = bs.BackendIp
			bs.Counter.Status = 0
			bs.Counter.bytesIn = 0
			bs.Counter.bytesOut = 0
			bs.Counter.sessionNumber = 0
			bs.Counter.refusedSessionNumber = 0
			bs.Counter.totalSessionNumber = 0
			bs.Counter.concurrentSessionNumber = 0
		}
	}

}

func updateIpvsCountersFromStats(output string) {
	frontIp := ""
	frontPort := ""
	proto := "-u"
	backendIp := ""
	backendPort := ""
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || len(line) == 0 {
			continue
		}
		items := strings.Fields(line)
		if items[0] == "TCP" || items[0] == "UDP" {
			if len(items) < 2 {
				continue
			}
			proto = "-u"
			if items[0] == "TCP" {
				proto = "-t"
			}
			ipports := strings.Split(items[1], ":")
			if len(ipports) < 2 {
				continue
			}
			frontIp = strings.Join(ipports[0:len(ipports)-1], ":")
			frontIp = strings.Trim(frontIp, "[")
			frontIp = strings.Trim(frontIp, "]")
			frontPort = ipports[len(ipports)-1]
		} else if items[0] == "->" {
			if len(items) < 7 {
				continue
			}
			ipports := strings.Split(items[1], ":")
			if len(ipports) < 2 {
				continue
			}
			backendIp = strings.Join(ipports[0:len(ipports)-1], ":")
			backendIp = strings.Trim(backendIp, "[")
			backendIp = strings.Trim(backendIp, "]")
			backendPort = ipports[len(ipports)-1]

			bs := getIpvsBackend(proto, frontIp, frontPort, backendIp, backendPort)
			if bs == nil {
				log.Debugf("GetIpvsCounters backend server for key:%s:%s:%s:%s:%s not found",
					proto, frontIp, frontPort, backendIp, backendPort)
				continue
			}

			bs.Counter.ip = backendIp
			bs.Counter.Status = 1
			bs.Counter.bytesIn, _ = strconv.ParseUint(strings.Trim(items[5], " "), 10, 64)
			bs.Counter.bytesOut, _ = strconv.ParseUint(strings.Trim(items[6], " "), 10, 64)
		} else {
			frontIp = ""
			frontPort = ""
		}
	}
}

func updateIpvsCountersFromThresholds(output string) {
	frontIp := ""
	frontPort := ""
	proto := "-u"
	backendIp := ""
	backendPort := ""
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || len(line) == 0 {
			continue
		}
		items := strings.Fields(line)
		if items[0] == "TCP" || items[0] == "UDP" {
			if len(items) < 2 {
				continue
			}
			proto = "-u"
			if items[0] == "TCP" {
				proto = "-t"
			}
			ipports := strings.Split(items[1], ":")
			if len(ipports) < 2 {
				continue
			}
			frontIp = strings.Join(ipports[0:len(ipports)-1], ":")
			frontIp = strings.Trim(frontIp, "[")
			frontIp = strings.Trim(frontIp, "]")
			frontPort = ipports[len(ipports)-1]
		} else if items[0] == "->" {
			if len(items) < 6 {
				continue
			}
			ipports := strings.Split(items[1], ":")
			if len(ipports) < 2 {
				continue
			}
			backendIp = strings.Join(ipports[0:len(ipports)-1], ":")
			backendIp = strings.Trim(backendIp, "[")
			backendIp = strings.Trim(backendIp, "]")
			backendPort = ipports[len(ipports)-1]

			bs := getIpvsBackend(proto, frontIp, frontPort, backendIp, backendPort)
			if bs == nil {
				log.Debugf("GetIpvsCounters backend server for key:%s:%s:%s:%s:%s not found",
					proto, frontIp, frontPort, backendIp, backendPort)
				continue
			}

			bs.Counter.ip = backendIp
			bs.Counter.Status = 1
			bs.Counter.sessionNumber, _ = strconv.ParseUint(strings.Trim(items[4], " "), 10, 64)
			bs.Counter.concurrentSessionNumber = bs.Counter.sessionNumber
			bs.Counter.refusedSessionNumber, _ = strconv.ParseUint(strings.Trim(items[5], " "), 10, 64)
			bs.Counter.totalSessionNumber = bs.Counter.sessionNumber + bs.Counter.refusedSessionNumber
		} else {
			frontIp = ""
			frontPort = ""
		}
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
