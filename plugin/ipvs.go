package plugin

import (
	"bytes"
	"fmt"
	"html/template"
	"os"
	"path/filepath"

	"strconv"
	"strings"

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

const(
	IPVS_LOG_CHAIN_NAME = "ipvs-log"
	IPVS_LOG_IPSET_NAME = "ipvs-set"
	IPVS_LOG_PREFIX = "ipvs-log"

	IPVS_HEALTH_CHECK_BIN_FILE = "/usr/local/bin/ipvsHealthCheck"
	IPVS_HEALTH_CHECK_BIN_FILE_VYOS = "/opt/vyatta/sbin/ipvsHealthCheck"
	IPVS_HEALTH_CHECK_CONFIG_FILE = "/etc/ipvs/healthcheck.conf"
	IPVS_HEALTH_CHECK_LOG_FILE = "/var/log/ipvs_health_check.log"
	IPVS_HEALTH_CHECK_PID_FILE = "/var/run/ipvs_health_check.pid"
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

/* ZStack need 4 scheduling methods: 
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

type IpvsBackendServer struct {
	/* for ipvsadm, ConnectionType is configure for each backend server */
	ConnectionType  string // "dr", "tunnel", "nat"
	Weight string // "default 1"
	BackendIp string
	BackendPort string
	Counter    LbCounter
	
	*IpvsFrontendService
}

type IpvsFrontendService struct {
	/* for keepalived, ConnectionType is configure for frontEndService */
	ConnectionType string // "dr", "tunnel", "nat"
	ProtocolType  string // "tcp", "udp", "fwmark"
	Scheduler string  // "rr|wrr|lc|wlc|lblc|lblcr|dh|sh|sed|nq"
	FrontIp string
	FrontPort string
	SessionNumber uint64
	
	BackendServers map[string]*IpvsBackendServer
	LbInfo
	LbParams
}

type IpvsConf struct{
	Services map[string]*IpvsFrontendService
}

var gIpvsConf *IpvsConf
var ipvsHealthCheckPidMon *utils.PidMon

func getIpvsConf() string {
	return filepath.Join(getLbConfDir(), "ipvs.conf")
}

func (ipvs *IpvsConf) ipvsadmSave() *IpvsConf {
	b := utils.Bash{
		Command: "ipvsadm-save -n",
		Sudo: true,
	}

	ret, o, _, err := b.RunWithReturn()
	if ret != 0 || err != nil {
		utils.PanicOnError(fmt.Errorf("failed to execute ipvsadm-save, %v", err))
		return nil
	}

	ipvs.ParseIpvs(o)
	for _, fs := range ipvs.Services {
		log.Debugf("IpvsConf: frontend: %+v", fs)
		for _, bs := range fs.BackendServers {
			log.Debugf("\t\tbackend: %+v", bs)
		}
	}
	return ipvs
}

const tIpvsConf = `# This file is auto-generated, edit with caution!
{{- range .Services }}
-A {{ .ProtocolType }} {{ .FrontIp }}:{{ .FrontPort }} -s {{ .Scheduler }}
{{- range .BackendServers }}
-a {{ .ProtocolType }} {{ .FrontIp }}:{{ .FrontPort }} -r {{ .BackendIp }}:{{ .BackendPort }} {{ .ConnectionType }} -w {{ .Weight }}
{{ end -}}
 {{ end -}}
`

func (fs *IpvsFrontendService) getFrontendServiceKey() string {
	return fs.ProtocolType + "-" + fs.FrontIp + "-" + fs.FrontPort
}

func (ipvs *IpvsConf) BuildConf() error {
	tmpl, err := template.New("ipvs.conf").Parse(tIpvsConf)
	utils.PanicOnError(err)

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, ipvs)
	utils.PanicOnError(err)

	err = os.WriteFile(getIpvsConf(), buf.Bytes(), 0644)
	utils.PanicOnError(err)
	
	return nil
}

func (ipvs *IpvsConf) Restore() error {
	checksum, err := getFileChecksum(getIpvsConf())
	utils.PanicOnError(err)
	log.Debugf("old ipvs conf checksum %v", checksum)
	
	err = ipvs.BuildConf()
	utils.PanicOnError(err)
	
	newCheckSum, err := getFileChecksum(getIpvsConf())
	utils.PanicOnError(err)
	log.Debugf("new ipvs conf checksum %v", newCheckSum)
	
	/* if keepalived is not started, RestartKeepalived will also start keepalived */
	if newCheckSum == checksum {
		log.Debugf("ipvs configure file unchanged")
		return nil
	}
	
	b := utils.Bash{
		Command: fmt.Sprintf("ipvsadm-restore < %s", getIpvsConf()),
		Sudo: true,
	}

	return b.Run()
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
			ipports := strings.Split(items[2], ":")
			ip := ipports[0]
			port := ipports[1]
			scheduler := items[4]
			info := LbInfo{}
			if strings.Contains(ip, ":") {
				info.Vip6 = ip
			} else {
				info.Vip = ip
			}
			info.LoadBalancerPort, _ = strconv.Atoi(port)
			if protocol  == "-u" {
				info.Mode = "udp"
			}
			
			param := LbParams{}
			param.balancerAlgorithm = scheduler
			
			service = NewIpvsFrontService(info, param, ip,  map[string]*IpvsBackendServer{})
			services[service.getFrontendServiceKey()] = service
		} else if items[0] == "-a" {
			backendIpPorts := strings.Split(items[4], ":")
			backendIp := backendIpPorts[0]
			backendPort := backendIpPorts[1]

			service.ConnectionType = items[5]
			weight := items[7]
			backend := NewIpvsBackendServer(backendIp,  backendPort, weight, service)
			service.BackendServers[backend.GetBackendKey()] = backend
		}
	}

	ipvs.Services = services
	return nil
}

func NewIpvsBackendServer(serverIp ,  serverPort, weight string, frontService *IpvsFrontendService) *IpvsBackendServer {
	return &IpvsBackendServer{
		ConnectionType: frontService.ConnectionType, 
		Weight: weight,
		BackendIp:serverIp,
		BackendPort: serverPort,
		Counter: LbCounter{lbUuid: frontService.LbUuid, listenerUuid: frontService.ListenerUuid},
		IpvsFrontendService: frontService,
	}
}

func NewIpvsFrontService(info LbInfo, param LbParams, frontIp string, servers map[string]*IpvsBackendServer) *IpvsFrontendService {
	connectionType := IpvsConnectionTypeNAT.String()
	protocolType := "-u"
	scheduler := GetIpvsSchedulerTypeFromString(param.balancerAlgorithm)
	return &IpvsFrontendService {
		ConnectionType: connectionType, 
		ProtocolType:  protocolType,
		Scheduler: scheduler.String(), 
		FrontIp: frontIp,
		FrontPort: fmt.Sprintf("%d", info.LoadBalancerPort),
		SessionNumber: 0,
		BackendServers: servers,
		LbInfo: info,
		LbParams: param,
	}
}

func NewIpvsConfFromSave() *IpvsConf {
	conf := IpvsConf{
		Services: map[string]*IpvsFrontendService{},
	}
	return conf.ipvsadmSave()
}

func (conf *IpvsConf) SaveIpvsHealthCheckFile() error {
	hcConf := IpvsHealthCheckConf{}
	hcConf.FromIpvsConf(conf)
	err := utils.JsonStoreConfig(IPVS_HEALTH_CHECK_CONFIG_FILE, hcConf)
	
	return err
}

type IpvsHealthCheckBackendServer struct {
	LbUuid string
	ListenerUuid string
	
	ConnectionType string // "dr", "tunnel", "nat"
	ProtocolType  string // "tcp", "udp", "fwmark"
	Scheduler string  // "rr|wrr|lc|wlc|lblc|lblcr|dh|sh|sed|nq"
	FrontIp string
	FrontPort string
	
	Weight string // "default 1"
	BackendIp string
	BackendPort string
	
	HealthCheckProtocl string
	HealthCheckPort int
	HealthCheckInterval int 
	HealthCheckTimeout int 
	HealthyThreshold int 
	UnhealthyThreshold int
	
	MaxConnection int
	MinConnection int
}

func (bs *IpvsHealthCheckBackendServer) CopyParamsFrom(other *IpvsHealthCheckBackendServer) {
	bs.ConnectionType = other.ConnectionType
	bs.Scheduler = other.Scheduler
	bs.Weight = other.Weight
	bs.HealthCheckProtocl = other.HealthCheckProtocl
	bs.HealthCheckPort = other.HealthCheckPort
	bs.HealthCheckInterval = other.HealthCheckInterval
	bs.HealthCheckTimeout = other.HealthCheckTimeout
	bs.HealthyThreshold = other.HealthyThreshold
	bs.UnhealthyThreshold = other.UnhealthyThreshold
	bs.MaxConnection = other.MaxConnection
	bs.MinConnection = other.MinConnection
}

type IpvsHealthCheckFrontService struct {
	LbUuid string
	ListenerUuid string
	
	ConnectionType string // "dr", "tunnel", "nat"
	ProtocolType  string // "tcp", "udp", "fwmark"
	Scheduler string  // "rr|wrr|lc|wlc|lblc|lblcr|dh|sh|sed|nq"
	FrontIp string
	FrontPort string
	
	BackendServers []*IpvsHealthCheckBackendServer
}

type IpvsHealthCheckConf struct{
	Services []*IpvsHealthCheckFrontService
}

func (hcConf *IpvsHealthCheckConf) FromIpvsConf(conf *IpvsConf) *IpvsHealthCheckConf {
	for _, fs := range conf.Services {
		hcFs := IpvsHealthCheckFrontService{
			LbUuid: fs.LbInfo.LbUuid,
			ListenerUuid: fs.LbInfo.ListenerUuid,
			
			FrontIp: fs.FrontIp,
			FrontPort: fs.FrontPort,
			ProtocolType: fs.ProtocolType,
			Scheduler: fs.Scheduler,
			ConnectionType: fs.ConnectionType,

			BackendServers: []*IpvsHealthCheckBackendServer{},
		}
		
		for _, bs := range fs.BackendServers {
			hcBs := IpvsHealthCheckBackendServer{
				LbUuid: bs.LbUuid,
				ListenerUuid: bs.ListenerUuid,
				
				ConnectionType: bs.ConnectionType,
				ProtocolType: bs.ProtocolType,
				Scheduler: bs.Scheduler,
				FrontIp: bs.FrontIp,
				FrontPort: bs.FrontPort,
				
				Weight: bs.Weight,
				BackendIp: bs.BackendIp,
				BackendPort: bs.BackendPort,
				MaxConnection: bs.maxConnection,
				MinConnection: bs.minConnection,
				
				HealthCheckProtocl: bs.healthCheckProtocl,
				HealthCheckPort: bs.healthCheckPort,
				HealthCheckInterval: bs.healthCheckInterval,
				HealthCheckTimeout: bs.healthCheckTimeout,
				HealthyThreshold: bs.healthyThreshold,
				UnhealthyThreshold: bs.unhealthyThreshold,
			}
			
			hcFs.BackendServers = append(hcFs.BackendServers, &hcBs)
		}

		hcConf.Services = append(hcConf.Services, &hcFs);
	}

	return hcConf
}

func (fs *IpvsFrontendService) EnableIpvsLog() (err error) {
	
	ipset := utils.GetIpSet(IPVS_LOG_IPSET_NAME)
	ipset.Member = []string{}
	protol := "udp"
	if fs.ProtocolType == "-t" {
		protol = "tcp"
	}
	
	ipset.AddMember([]string{fs.FrontIp + "," + protol + ":" + fs.FrontPort})

	return nil
}

func (fs *IpvsFrontendService) DisableIpvsLog() (err error) {
	ipset := utils.GetIpSet(IPVS_LOG_IPSET_NAME)
	ipset.Member = []string{}
	protol := "udp"
	if fs.ProtocolType == "-t" {
		protol = "tcp"
	}
	
	ipset.DeleteMember([]string{fs.FrontIp + "," + protol +":" + fs.FrontPort})

	return nil
}

func RefreshIpvsService(lbs map[string]LbInfo) error {
	services := map[string]*IpvsFrontendService{}
	for _, lb := range lbs {
		if strings.ToLower(lb.Mode) != "udp" {
			/* current only udp lb use ipvs */
			continue
		}

		lbParam := ParseLbParams(lb)
		
		var fs4, fs6 *IpvsFrontendService
		if lb.Vip != "" {
			fs4 = NewIpvsFrontService(lb, lbParam, lb.Vip, map[string]*IpvsBackendServer{})
			services[fs4.getFrontendServiceKey()] = fs4
		}
		if lb.Vip6 != "" {
			fs6 =  NewIpvsFrontService(lb, lbParam, lb.Vip6, map[string]*IpvsBackendServer{})
			services[fs6.getFrontendServiceKey()] = fs6
		}
		
		for _, sg := range lb.ServerGroups {
			for _, bs := range sg.BackendServers {
				if lb.Vip != "" {
					server := NewIpvsBackendServer(bs.Ip, fmt.Sprintf("%d", lb.InstancePort),  fmt.Sprintf("%d", bs.Weight),  fs4)
					if lbParam.healthCheckPort == 0 {
						server.healthCheckPort = lb.InstancePort
					}
					fs4.BackendServers[server.GetBackendKey()] = server
				}
				
				if lb.Vip6 != "" {
					server := NewIpvsBackendServer(bs.Ip, fmt.Sprintf("%d", lb.InstancePort),  fmt.Sprintf("%d", bs.Weight), fs6)
					if lbParam.healthCheckPort == 0 {
						server.healthCheckPort = lb.InstancePort
					}
					fs6.BackendServers[server.GetBackendKey()] = server
				}
			}
		}
	}

	gIpvsConf = &IpvsConf{Services: services}
	/* save health check config file */
	err := gIpvsConf.SaveIpvsHealthCheckFile()
	utils.PanicOnError(err)
	
	for _, fs := range gIpvsConf.Services {
		/* service maybe not existed, ignore the error */ 
		fs.EnableIpvsLog()
	}
	
	return nil
}

func DelIpvsService(lbs map[string]LbInfo) {
	services := []*IpvsFrontendService{}
	for _, lb := range lbs {
		if strings.ToLower(lb.Mode) != "udp" {
			/* current only udp lb use ipvs */
			continue
		}
		
		lbParam := ParseLbParams(lb)
		
		var fs4, fs6 *IpvsFrontendService
		if lb.Vip != "" {
			fs4 = NewIpvsFrontService(lb, lbParam, lb.Vip, map[string]*IpvsBackendServer{})
			services = append(services,fs4)
		}
		if lb.Vip6 != "" {
			fs6 =  NewIpvsFrontService(lb, lbParam, lb.Vip6, map[string]*IpvsBackendServer{})
			services = append(services,fs6)
		}
	}

	for _, fs := range services {
		/* stop ipvslog */
		fs.DisableIpvsLog()

		/* del data */
		delete(gIpvsConf.Services, fs.getFrontendServiceKey())
	}

	/* save health check config file */
	err := gIpvsConf.SaveIpvsHealthCheckFile()
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
	
	log.Debugf("backend not found for :%s-%s-%s-%s-%s-%s", proto, frontIp, frontPort, backendIp, backendPort)
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
			ch <- prom.MustNewConstMetric(c.statusEntry, prom.GaugeValue, float64(cnt.Status), cnt.listenerUuid, cnt.ip, cnt.lbUuid)
			ch <- prom.MustNewConstMetric(c.inByteEntry, prom.GaugeValue, float64(cnt.bytesIn), cnt.listenerUuid, cnt.ip, cnt.lbUuid)
			ch <- prom.MustNewConstMetric(c.outByteEntry, prom.GaugeValue, float64(cnt.bytesOut), cnt.listenerUuid, cnt.ip, cnt.lbUuid)
			ch <- prom.MustNewConstMetric(c.curSessionNumEntry, prom.GaugeValue, float64(cnt.sessionNumber), cnt.listenerUuid, cnt.ip, cnt.lbUuid)
			ch <- prom.MustNewConstMetric(c.refusedSessionNumEntry, prom.GaugeValue, float64(cnt.refusedSessionNumber), cnt.listenerUuid, cnt.ip, cnt.lbUuid)
			ch <- prom.MustNewConstMetric(c.totalSessionNumEntry, prom.GaugeValue, float64(cnt.totalSessionNumber), cnt.listenerUuid, cnt.ip, cnt.lbUuid)
			ch <- prom.MustNewConstMetric(c.concurrentSessionUsageEntry, prom.GaugeValue, float64(cnt.concurrentSessionNumber), cnt.listenerUuid, cnt.ip, cnt.lbUuid)
		}
		if (maxConnection > 0) {
			ch <- prom.MustNewConstMetric(c.curSessionUsageEntry, prom.GaugeValue, float64(fs.SessionNumber*100/(uint64)(maxConnection)), fs.ListenerUuid, fs.LbUuid)
		}
	}
	
	return nil
}

func UpdateIpvsCounters() {
	for _, fs := range gIpvsConf.Services {
		for _, bs := range fs.BackendServers {
			/* if it can not be updated by ipvsadm -L -n --stats, it's down*/
			bs.Counter.ip = bs.BackendIp
			bs.Counter.Status =0
		}
	}
	
	b := utils.Bash {
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
		Sudo: true,
	}
	
	ret, o, _, err := b.RunWithReturn()
	if ret != 0 || err != nil {
		return
	}

	frontIp := ""
	frontPort := ""
	proto := "-u"
	backendIp := ""
	backendPort := ""
	lines := strings.Split(o, "\n")
	lines = lines[3:]  //ignore the first 3 lines 
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || len(line) == 0 {
			continue
		}
		log.Debugf("line: %s", line)
		items := strings.Fields(line)
		if items[0] == "TCP" || items[0] == "UDP" {
			ipports := strings.Split(items[1], ":")
			frontIp = ipports[0]
			frontPort = ipports[1]
		} else if items[0] == "->" {
			ipports := strings.Split(items[1], ":")
			backendIp = ipports[0]
			backendPort = ipports[1]
			
			bs := getIpvsBackend(proto, frontIp, frontPort, backendIp, backendPort)
			if bs == nil {
				log.Debugf("GetIpvsCounters backend server for key:%s:%s:%s:%s:%s not found", 
					proto, frontIp, frontPort, backendIp, backendPort)
				break
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
		Sudo: true,
	}
	
	ret, o, _, err = b.RunWithReturn()
	if ret != 0 || err != nil {
		return
	}
	lines = strings.Split(o, "\n")
	lines = lines[3:]  //ignore the first 3 lines 
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || len(line) == 0 {
			continue
		}
		log.Debugf("line: %s", line)
		items := strings.Fields(line)
		if items[0] == "TCP" || items[0] == "UDP" {
			ipports := strings.Split(items[1], ":")
			frontIp = ipports[0]
			frontPort = ipports[1]
		} else if items[0] == "->" {
			ipports := strings.Split(items[1], ":")
			backendIp = ipports[0]
			backendPort = ipports[1]
			
			bs := getIpvsBackend(proto, frontIp, frontPort, backendIp, backendPort)
			if bs == nil {
				log.Debugf("GetIpvsCounters backend server for key:%s:%s:%s:%s:%s not found", 
					proto, frontIp, frontPort, backendIp, backendPort)
				break
			}

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
	ipvsHealthCheckPidMon.Destroy()
}

func InitIpvs() {
	/* add ipvs ipset */
	eipIpset = utils.NewIPSet(IPVS_LOG_IPSET_NAME, utils.IPSET_TYPE_HASH_IP_PORT)
	if err := eipIpset.Create(); err != nil {
		utils.PanicOnError(err)
	}
		
	/* add ipvs hook in prerouting table */
	table := utils.NewIpTables(utils.NatTable)
	rule := utils.NewIpTableRule(utils.RULESET_DNAT.String())
	rule.SetAction(IPVS_LOG_CHAIN_NAME)
	table.AddIpTableRules([]*utils.IpTableRule{rule})

	table.AddChain(IPVS_LOG_CHAIN_NAME)
	rule = utils.NewIpTableRule(IPVS_LOG_CHAIN_NAME)
	rule.SetDstIpset(IPVS_LOG_IPSET_NAME)
	rule.SetActionLog(IPVS_LOG_PREFIX)
	table.AddIpTableRules([]*utils.IpTableRule{rule})
	table.Apply()
	
	/* start ipvsHealthCheck */
	binPath := IPVS_HEALTH_CHECK_BIN_FILE
	if utils.IsVYOS() {
		binPath = IPVS_HEALTH_CHECK_BIN_FILE_VYOS
	}
	pid, _ := utils.FindFirstPIDByPSExtern(true, binPath)
	if pid < 0 {
		log.Debugf("start ipvs health check")
		b := utils.Bash{
			Command: fmt.Sprintf("nohup %s -f %s -log %s -p %s > /dev/null 2>&1 &", binPath, 
				IPVS_HEALTH_CHECK_CONFIG_FILE, IPVS_HEALTH_CHECK_LOG_FILE,
				IPVS_HEALTH_CHECK_PID_FILE),
			Sudo: true,
		}
		err := b.Run()
		utils.PanicOnError(err)
	}

	pid, _ = utils.FindFirstPIDByPSExtern(true, binPath)
	log.Debugf("ipvs health check pid %d", pid)
	
	ipvsHealthCheckPidMon = utils.NewPidMon(pid, func() int {
		log.Warnf("start ipvs health check in PidMon")
		b := utils.Bash {
			Command: fmt.Sprintf("nohup %s -f %s -log %s -p %s > /dev/null 2>&1 &", binPath, 
				IPVS_HEALTH_CHECK_CONFIG_FILE, IPVS_HEALTH_CHECK_LOG_FILE,
				IPVS_HEALTH_CHECK_PID_FILE),
			Sudo: true,
		}
		err := b.Run()
		if err != nil {
			log.Warnf("failed to start ipvs health check: %v", err)
			return -1
		}

		pid, err := utils.FindFirstPIDByPSExtern(true, IPVS_HEALTH_CHECK_BIN_FILE)
		if err != nil {
			log.Warnf("failed to read ipvs health check pid: %v", err)
			return -1
		}

		return pid
	})
	log.Debugf("created lvs health check PidMon")
	ipvsHealthCheckPidMon.Start()
}
