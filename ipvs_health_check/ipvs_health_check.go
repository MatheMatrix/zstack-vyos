package main

import (
	"context"
	"flag"
	"fmt"
	"math"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"zstack-vyos/plugin"
	"zstack-vyos/utils"

	log "github.com/sirupsen/logrus"
)

type IpvsHealthCheckBackendServer struct {
	status     bool
	successCnt uint
	failedCnt  uint
	cancel     context.CancelFunc
	cancelled  uint32
	result     chan bool
	plugin.IpvsHealthCheckBackendServer
}

var logFile string
var confFile string
var pidFile string

var gHealthCheckMap map[string]*IpvsHealthCheckBackendServer
var gDisabledHealthCheckMap map[string]*IpvsHealthCheckBackendServer
var gHealthCheckMapLock sync.Mutex
var ipvsadmLock sync.Mutex

const (
	healthCheckProtocolNone = "none"
	healthCheckProtocolTCP  = "tcp"
	healthCheckProtocolUDP  = "udp"

	defaultHealthCheckTimeoutSeconds = 2
)

func isHealthCheckDisabled(protocol string) bool {
	return strings.EqualFold(protocol, healthCheckProtocolNone)
}

func healthCheckTimeoutDuration(timeout int) time.Duration {
	if timeout <= 0 {
		return time.Duration(defaultHealthCheckTimeoutSeconds) * time.Second
	}

	return time.Duration(timeout) * time.Second
}

func shellQuoteArg(arg string) string {
	return "'" + strings.ReplaceAll(arg, "'", `'"'"'`) + "'"
}

func formatIpvsHealthCheckAddress(address string) (string, error) {
	ip := net.ParseIP(address)
	if ip == nil {
		return "", fmt.Errorf("invalid ipvs health check address %q", address)
	}
	if ip.To4() == nil {
		return fmt.Sprintf("[%s]", address), nil
	}

	return address, nil
}

func validateIpvsHealthCheckPort(port string) error {
	value, err := strconv.Atoi(port)
	if err != nil || value <= 0 || value > 65535 {
		return fmt.Errorf("invalid ipvs health check port %q", port)
	}

	return nil
}

func ipvsHealthCheckEndpoint(address, port string) (string, error) {
	formattedAddress, err := formatIpvsHealthCheckAddress(address)
	if err != nil {
		return "", err
	}
	if err := validateIpvsHealthCheckPort(port); err != nil {
		return "", err
	}

	return shellQuoteArg(fmt.Sprintf("%s:%s", formattedAddress, port)), nil
}

func ipvsHealthCheckWeight(weight string) (string, error) {
	value, err := strconv.Atoi(weight)
	if err != nil || value < 0 {
		return "", fmt.Errorf("invalid ipvs health check weight %q", weight)
	}

	return shellQuoteArg(weight), nil
}

func parseCommandOptions() {
	flag.StringVar(&logFile, "log", plugin.IPVS_HEALTH_CHECK_LOG_FILE, "ipvs health check The log file path")
	flag.StringVar(&confFile, "f", plugin.IPVS_HEALTH_CHECK_CONFIG_FILE, "ipvs health check config file path")
	flag.StringVar(&pidFile, "p", plugin.IPVS_HEALTH_CHECK_PID_FILE, "ipvs health check pid file path")

	flag.Parse()
}

func (bs *IpvsHealthCheckBackendServer) getBackendKey() string {
	proto := healthCheckProtocolUDP
	if strings.ToLower(bs.ProtocolType) == healthCheckProtocolTCP || strings.ToLower(bs.ProtocolType) == "-t" {
		proto = healthCheckProtocolTCP
	}

	return proto + "-" + bs.FrontIp + "-" + bs.FrontPort + "-" + bs.BackendIp + "-" + bs.BackendPort
}

func (bs *IpvsHealthCheckBackendServer) equal(other *IpvsHealthCheckBackendServer) bool {
	return bs.ConnectionType == other.ConnectionType &&
		bs.ProtocolType == other.ProtocolType &&
		bs.Scheduler == other.Scheduler &&
		bs.FrontIp == other.FrontIp &&
		bs.FrontPort == other.FrontPort &&
		bs.Weight == other.Weight &&
		bs.BackendIp == other.BackendIp &&
		bs.BackendPort == other.BackendPort &&
		bs.HealthCheckProtocol == other.HealthCheckProtocol &&
		bs.HealthCheckPort == other.HealthCheckPort &&
		bs.HealthCheckInterval == other.HealthCheckInterval &&
		bs.HealthCheckTimeout == other.HealthCheckTimeout &&
		bs.HealthyThreshold == other.HealthyThreshold &&
		bs.UnhealthyThreshold == other.UnhealthyThreshold &&
		bs.MaxConnection == other.MaxConnection &&
		bs.MinConnection == other.MinConnection
}

func (bs *IpvsHealthCheckBackendServer) doHealthCheck() {
	protocol := strings.TrimSpace(strings.ToLower(bs.HealthCheckProtocol))
	switch protocol {
	case healthCheckProtocolNone:
		bs.result <- true
	case healthCheckProtocolTCP:
		bs.doTcpCheck()
	case healthCheckProtocolUDP:
		bs.doUdpCheck()
	default:
		log.Debugf("unknown health check protocol %q", bs.HealthCheckProtocol)
		bs.result <- false
	}
}

func (bs *IpvsHealthCheckBackendServer) Install() {
	ipvsadmLock.Lock()
	defer ipvsadmLock.Unlock()
	bs.status = true

	proto := "-u"
	if strings.ToLower(bs.ProtocolType) == "tcp" || strings.ToLower(bs.ProtocolType) == "-t" {
		proto = "-t"
	}
	frontService, err := ipvsHealthCheckEndpoint(bs.FrontIp, bs.FrontPort)
	if err != nil {
		log.Errorf("skip installing invalid ipvs health check service: %v", err)
		return
	}
	backendService, err := ipvsHealthCheckEndpoint(bs.BackendIp, bs.BackendPort)
	if err != nil {
		log.Errorf("skip installing invalid ipvs health check backend: %v", err)
		return
	}
	scheduler := shellQuoteArg(bs.Scheduler)
	connectionType := shellQuoteArg(bs.ConnectionType)
	weight, err := ipvsHealthCheckWeight(bs.Weight)
	if err != nil {
		log.Errorf("skip installing invalid ipvs health check weight: %v", err)
		return
	}

	cmd := fmt.Sprintf("(ipvsadm -L %s %s || ipvsadm -A %s %s -s %s); "+
		"(ipvsadm -e %s %s -r %s %s -w %s -x %d -y %d || "+
		"ipvsadm -a %s %s -r %s %s -w %s -x %d -y %d)",
		proto, frontService,
		proto, frontService, scheduler,
		proto, frontService, backendService, connectionType, weight, bs.MaxConnection, bs.MinConnection,
		proto, frontService, backendService, connectionType, weight, bs.MaxConnection, bs.MinConnection)

	b := utils.Bash{
		Command: cmd,
		Sudo:    true,
	}

	b.Run()
}

func (bs *IpvsHealthCheckBackendServer) UnInstall() {
	ipvsadmLock.Lock()
	defer ipvsadmLock.Unlock()
	bs.status = false

	proto := "-u"
	if strings.ToLower(bs.ProtocolType) == "tcp" || strings.ToLower(bs.ProtocolType) == "-t" {
		proto = "-t"
	}
	frontService, err := ipvsHealthCheckEndpoint(bs.FrontIp, bs.FrontPort)
	if err != nil {
		log.Errorf("skip uninstalling invalid ipvs health check service: %v", err)
		return
	}
	formattedFrontIp, err := formatIpvsHealthCheckAddress(bs.FrontIp)
	if err != nil {
		log.Errorf("skip uninstalling invalid ipvs health check service: %v", err)
		return
	}
	frontServicePattern := shellQuoteArg(fmt.Sprintf("^-a[[:space:]]+%s[[:space:]]+%s:[[:space:]]*%s[[:space:]]",
		proto, regexp.QuoteMeta(formattedFrontIp), regexp.QuoteMeta(bs.FrontPort)))
	backendService, err := ipvsHealthCheckEndpoint(bs.BackendIp, bs.BackendPort)
	if err != nil {
		log.Errorf("skip uninstalling invalid ipvs health check backend: %v", err)
		return
	}

	cmd := fmt.Sprintf("ipvsadm -d %s %s -r %s", proto, frontService, backendService)
	b := utils.Bash{
		Command: cmd,
		Sudo:    true,
	}
	b.Run()

	cmd = fmt.Sprintf("ipvsadm-save -n | grep -Eq %s || ipvsadm -D %s %s",
		frontServicePattern, proto, frontService)
	b = utils.Bash{
		Command: cmd,
		Sudo:    true,
	}
	b.Run()
}

func (bs *IpvsHealthCheckBackendServer) EnsureUninstalledIfDown() {
	if bs.status || isHealthCheckDisabled(bs.HealthCheckProtocol) {
		return
	}

	log.Debugf("[ipvsHealthCheck task] ensure down backend %s is uninstalled", bs.getBackendKey())
	bs.UnInstall()
}

func (bs *IpvsHealthCheckBackendServer) EditBackendServer() {
	ipvsadmLock.Lock()
	defer ipvsadmLock.Unlock()

	proto := "-u"
	if strings.ToLower(bs.ProtocolType) == "tcp" || strings.ToLower(bs.ProtocolType) == "-t" {
		proto = "-t"
	}
	frontService, err := ipvsHealthCheckEndpoint(bs.FrontIp, bs.FrontPort)
	if err != nil {
		log.Errorf("skip editing invalid ipvs health check service: %v", err)
		return
	}
	backendService, err := ipvsHealthCheckEndpoint(bs.BackendIp, bs.BackendPort)
	if err != nil {
		log.Errorf("skip editing invalid ipvs health check backend: %v", err)
		return
	}
	connectionType := shellQuoteArg(bs.ConnectionType)
	weight, err := ipvsHealthCheckWeight(bs.Weight)
	if err != nil {
		log.Errorf("skip editing invalid ipvs health check weight: %v", err)
		return
	}

	cmd := fmt.Sprintf("ipvsadm -e %s %s -r  %s %s -w %s -x %d -y %d",
		proto, frontService, backendService, connectionType, weight, bs.MaxConnection, bs.MinConnection)

	b := utils.Bash{
		Command: cmd,
		Sudo:    true,
	}
	b.Run()
}

func (bs *IpvsHealthCheckBackendServer) EditFrontService() {
	ipvsadmLock.Lock()
	defer ipvsadmLock.Unlock()

	proto := "-u"
	if strings.ToLower(bs.ProtocolType) == "tcp" || strings.ToLower(bs.ProtocolType) == "-t" {
		proto = "-t"
	}
	frontService, err := ipvsHealthCheckEndpoint(bs.FrontIp, bs.FrontPort)
	if err != nil {
		log.Errorf("skip editing invalid ipvs health check service: %v", err)
		return
	}

	cmd := fmt.Sprintf("ipvsadm -E %s %s -s %s", proto, frontService, shellQuoteArg(bs.Scheduler))
	b := utils.Bash{
		Command: cmd,
		Sudo:    true,
	}
	b.Run()
}

func (bs *IpvsHealthCheckBackendServer) setStatus(status bool) {
	bs.status = status
	bs.failedCnt = 0
	bs.successCnt = 0
}

func (bs *IpvsHealthCheckBackendServer) isCancelled() bool {
	return atomic.LoadUint32(&bs.cancelled) != 0
}

func (bs *IpvsHealthCheckBackendServer) applyHealthCheckResult(result bool) bool {
	if bs.isCancelled() {
		log.Debugf("[ipvsHealthCheck task] ignore health check result after cancellation for %s", bs.getBackendKey())
		return false
	}

	if result {
		if bs.successCnt == math.MaxUint-1 {
			bs.successCnt = bs.HealthyThreshold
		} else {
			bs.successCnt++
		}

		bs.failedCnt = 0
	} else {
		if bs.failedCnt == math.MaxUint-1 {
			bs.failedCnt = bs.UnhealthyThreshold
		} else {
			bs.failedCnt++
		}
		bs.successCnt = 0
	}

	log.Debugf("[ipvsHealthCheck task] %s: healthcheck resut:%v, current status %v:  successCnt: %d,%d failedCnt: %d:%d",
		bs.getBackendKey(), result, bs.status,
		bs.successCnt, bs.HealthyThreshold,
		bs.failedCnt, bs.UnhealthyThreshold)
	if bs.failedCnt >= bs.UnhealthyThreshold && bs.status {
		bs.UnInstall()
	} else if bs.successCnt >= bs.HealthyThreshold && !bs.status {
		bs.Install()
	}

	return true
}

func (bs *IpvsHealthCheckBackendServer) Start() {
	defer func() {
		if err := recover(); err != nil {
			/* run failed, start again */
			log.Infof("[ipvsHealthCheck task] run failed %+v", err)
			go bs.Start()
		}
	}()

	/*
		health check task is loop task: wait for following events:
		1. timer to do health check in another go routine
		2. health check result  ---- wait resulrt from #1
		3. backend server removed -- stopped the health check task
	*/

	ctx, cancel := context.WithCancel(context.Background())
	bs.cancel = cancel
	if bs.isCancelled() {
		cancel()
		return
	}
	bs.result = make(chan bool, 1)
	bs.successCnt = 0
	bs.failedCnt = 0

	log.Debugf("[ipvsHealthCheck task] start health check task for %s", bs.getBackendKey())
	if isHealthCheckDisabled(bs.HealthCheckProtocol) {
		bs.Install()
		<-ctx.Done()
		log.Debugf("[ipvsHealthCheck task] stop disabled health check task for %s", bs.getBackendKey())
		return
	}

	taskTimer := time.NewTimer(time.Duration(bs.HealthCheckInterval) * time.Second)

	for {
		select {
		case result := <-bs.result:
			if !bs.applyHealthCheckResult(result) {
				taskTimer.Stop()
				return
			}
			taskTimer.Reset(time.Duration(bs.HealthCheckInterval) * time.Second)

		case <-ctx.Done():
			log.Debugf("[ipvsHealthCheck task] stop health check task for %s", bs.getBackendKey())
			taskTimer.Stop()
			return

		case <-taskTimer.C:
			// avoid to call DoHealthCheck while previous call is not finished
			log.Debugf("[ipvsHealthCheck task] timer expired for health check task %s", bs.getBackendKey())
			go bs.doHealthCheck()
		}
	}
}

func (bs *IpvsHealthCheckBackendServer) Stop() {
	log.Debugf("[ipvsHealthCheck task] stop health check task for %s", bs.getBackendKey())
	bs.Cancel()
	bs.UnInstall()
}

func (bs *IpvsHealthCheckBackendServer) Cancel() {
	atomic.StoreUint32(&bs.cancelled, 1)
	if bs.cancel != nil {
		bs.cancel()
	}
}

func reloadIpvsHealthCheckConfig() {
	defer func() {
		if err := recover(); err != nil {
			log.Infof("[ipvsHealthCheck reload] load config failed %+v", err)
		}
	}()

	var conf plugin.IpvsHealthCheckConf
	err := utils.JsonLoadConfig(confFile, &conf)
	if err != nil {
		log.Debugf("[ipvsHealthCheck reload] load config failed %v", err)
		return
	}

	log.Debugf("[ipvsHealthCheck reload] load config file success, %++v", conf)
	checkers := map[string]*IpvsHealthCheckBackendServer{}
	disabledBackends := map[string]*IpvsHealthCheckBackendServer{}
	if conf.Services != nil {
		for _, fs := range conf.Services {
			log.Debugf("[ipvsHealthCheck reload] new Services: %+v", fs)
			for _, bs := range fs.BackendServers {
				nc := IpvsHealthCheckBackendServer{
					/*  health check will not install ipvs service, untill  backend is up */
					status:                       false,
					IpvsHealthCheckBackendServer: *bs,
				}

				log.Debugf("[ipvsHealthCheck reload] new checker: %+v", nc)
				if isHealthCheckDisabled(nc.HealthCheckProtocol) {
					disabledBackends[nc.getBackendKey()] = &nc
					continue
				}
				checkers[nc.getBackendKey()] = &nc
			}
		}
	}

	var toDeleted []string
	var toStopped []*IpvsHealthCheckBackendServer
	var toCancelled []*IpvsHealthCheckBackendServer
	var toStarted []*IpvsHealthCheckBackendServer
	var toInstalled []*IpvsHealthCheckBackendServer
	var toEnsureDown []*IpvsHealthCheckBackendServer

	func() {
		gHealthCheckMapLock.Lock()
		defer gHealthCheckMapLock.Unlock()

		for _, old := range gHealthCheckMap {
			log.Debugf("[ipvsHealthCheck reload] old checker: %+v", old)
			check, found := checkers[old.getBackendKey()]
			if !found {
				log.Debugf("[ipvsHealthCheck reload] delete health check task for %s", old.getBackendKey())
				toDeleted = append(toDeleted, old.getBackendKey())
				if disabledBackends[old.getBackendKey()] != nil {
					toCancelled = append(toCancelled, old)
					continue
				}
				toStopped = append(toStopped, old)
			} else {
				/* 后端服务器的health check task 参数可能变化, 有两种处理方式:
				1. copy health check配置参数给old
				2. copy old health check的状态参数给new,
				此处采用#1 */
				log.Debugf("[ipvsHealthCheck reload] update health check task params %+v", check.IpvsHealthCheckBackendServer)
				if isHealthCheckDisabled(old.HealthCheckProtocol) != isHealthCheckDisabled(check.HealthCheckProtocol) {
					log.Debugf("[ipvsHealthCheck reload] restart health check task for %s because health check protocol changed from %s to %s",
						old.getBackendKey(), old.HealthCheckProtocol, check.HealthCheckProtocol)
					toDeleted = append(toDeleted, old.getBackendKey())
					continue
				}

				if !old.equal(check) {
					if old.Scheduler != check.Scheduler {
						old.CopyParamsFrom(&check.IpvsHealthCheckBackendServer)
						go old.EditFrontService()
					} else {
						old.CopyParamsFrom(&check.IpvsHealthCheckBackendServer)
						go old.EditBackendServer()
					}

					if isHealthCheckDisabled(old.HealthCheckProtocol) {
						go old.Install()
					}
				} else {
					log.Debugf("[ipvsHealthCheck reload] checker: %s not changed", old.getBackendKey())
				}

				if !old.status {
					toEnsureDown = append(toEnsureDown, old)
				}
			}
		}

		for _, key := range toDeleted {
			log.Debugf("[ipvsHealthCheck reload] delete health check task for %s", key)
			delete(gHealthCheckMap, key)
		}

		/* new backend health check */
		for _, check := range checkers {
			_, found := gHealthCheckMap[check.getBackendKey()]
			if !found {
				log.Debugf("[ipvsHealthCheck reload] add new health check task %+v", check.getBackendKey())
				if disabledBackend := gDisabledHealthCheckMap[check.getBackendKey()]; disabledBackend != nil && disabledBackend.status {
					check.setStatus(true)
				}
				gHealthCheckMap[check.getBackendKey()] = check
				toEnsureDown = append(toEnsureDown, check)
				toStarted = append(toStarted, check)
			}
		}

		gDisabledHealthCheckMap = disabledBackends
		for _, bs := range disabledBackends {
			toInstalled = append(toInstalled, bs)
		}
	}()

	for _, check := range toCancelled {
		check.Cancel()
	}

	for _, check := range toStopped {
		check.Stop()
	}

	for _, check := range toInstalled {
		check.Install()
	}

	for _, check := range toEnsureDown {
		check.EnsureUninstalledIfDown()
	}

	for _, check := range toStarted {
		go check.Start()
	}
}

func writePidToFile(pidFilePath string) error {
	pid := os.Getpid()
	pidStr := strconv.Itoa(pid)

	file, err := os.Create(pidFilePath)
	if err != nil {
		return fmt.Errorf("can not create pid file: %v", err)
	}
	defer file.Close()

	_, err = file.WriteString(pidStr + "\n")
	if err != nil {
		return fmt.Errorf("can not write pid file: %v", err)
	}

	return nil
}

func syncIpvsadmWithHealthCheck() {
	defer func() {
		if err := recover(); err != nil {
			log.Infof("[ipvsHealthCheck sync] sync ipvsadm failed %+v", err)
		}
	}()

	conf, err := plugin.NewIpvsConfFromSave()
	if err != nil {
		log.Debugf("[ipvsHealthCheck sync] ipvsadm-save to config failed %+v", err)
	}

	var toInstalled []*IpvsHealthCheckBackendServer
	var toEnsureDown []*IpvsHealthCheckBackendServer

	func() {
		gHealthCheckMapLock.Lock()
		defer gHealthCheckMapLock.Unlock()

		tempBsMap := map[string]*IpvsHealthCheckBackendServer{}
		for _, fs := range conf.Services {
			log.Debugf("[ipvsHealthCheck sync] ipvsadm-save front end service %+v", fs)
			for _, bs := range fs.BackendServers {
				log.Debugf("[ipvsHealthCheck sync] 	ipvsadm-save backend end server %+v", bs)

				temp := IpvsHealthCheckBackendServer{}
				temp.ProtocolType = "udp"
				if strings.ToLower(fs.ProtocolType) == "tcp" || strings.ToLower(fs.ProtocolType) == "-t" {
					temp.ProtocolType = "tcp"
				}
				temp.FrontIp = fs.FrontIp
				temp.FrontPort = fs.FrontPort
				temp.BackendIp = bs.BackendIp
				temp.BackendPort = bs.BackendPort

				tempBsMap[temp.getBackendKey()] = &temp

				if gHealthCheckMap[temp.getBackendKey()] == nil && gDisabledHealthCheckMap[temp.getBackendKey()] == nil {
					log.Debugf("[ipvsHealthCheck sync] delete backend server %+v", temp.getBackendKey())
					go temp.UnInstall()
				} else if gHealthCheckMap[temp.getBackendKey()] != nil && !gHealthCheckMap[temp.getBackendKey()].status {
					log.Debugf("[ipvsHealthCheck sync] ensure down backend server %+v is uninstalled", temp.getBackendKey())
					toEnsureDown = append(toEnsureDown, gHealthCheckMap[temp.getBackendKey()])
				}
			}
		}

		for _, gbs := range gHealthCheckMap {
			if tempBsMap[gbs.getBackendKey()] == nil {
				log.Debugf("[ipvsHealthCheck sync] change backend server %+v status down", gbs.getBackendKey())
				gbs.setStatus(false)
			}
		}

		for _, gbs := range gDisabledHealthCheckMap {
			if tempBsMap[gbs.getBackendKey()] == nil {
				log.Debugf("[ipvsHealthCheck sync] reinstall disabled health check backend server %+v", gbs.getBackendKey())
				toInstalled = append(toInstalled, gbs)
			}
		}
	}()

	for _, gbs := range toInstalled {
		gbs.Install()
	}

	for _, gbs := range toEnsureDown {
		gbs.EnsureUninstalledIfDown()
	}
}

// when vpcha master/backup failover, we need to make
func fastUpBackendServers() {
	gHealthCheckMapLock.Lock()
	defer gHealthCheckMapLock.Unlock()

	for _, gbs := range gHealthCheckMap {
		if isHealthCheckDisabled(gbs.HealthCheckProtocol) {
			go gbs.Install()
			continue
		}

		// set false, when health check finished, it will install backend server
		gbs.setStatus(false)
		go gbs.doHealthCheck()
	}

	for _, gbs := range gDisabledHealthCheckMap {
		go gbs.Install()
	}
}

func main() {
	parseCommandOptions()
	utils.InitLog(logFile, utils.IsRuingUT())
	utils.InitVyosVersion()

	pid, _ := utils.ReadPid(pidFile)
	if pid != 0 {
		if utils.ProcessExists(pid) == nil {
			log.Debugf("[ipvsHealthCheck] already running, pid %d", pid)
			return
		}
	}
	err := writePidToFile(pidFile)
	if err != nil {
		log.Debugf("[ipvsHealthCheck] write pid[%d] to file failed, err %v", pid, err)
	}

	gHealthCheckMap = map[string]*IpvsHealthCheckBackendServer{}
	gDisabledHealthCheckMap = map[string]*IpvsHealthCheckBackendServer{}

	interruptChan := make(chan os.Signal, 1)
	signal.Notify(interruptChan, syscall.SIGHUP, syscall.SIGUSR1)

	syncTimer := time.NewTimer(time.Duration(300) * time.Second)

	/* push a signal when start process */
	interruptChan <- syscall.SIGHUP

	/* main thead loop handles 2 events:
	1. realod config
	2. sync ipvs-admin timer
	*/
	for {
		select {
		case sig := <-interruptChan:
			if sig == syscall.SIGHUP {
				reloadIpvsHealthCheckConfig()
			} else if sig == syscall.SIGUSR1 {
				fastUpBackendServers()
			} else {
				log.Debugf("[ipvsHealthCheck] unknow sig %+v", sig)
			}

		case <-syncTimer.C:
			/* sync ipvsadm-save */
			syncIpvsadmWithHealthCheck()

		}
	}
}

/* func for UT */
func stopIpvsConfig() {
	pid, err := utils.ReadPid(plugin.IPVS_HEALTH_CHECK_PID_FILE)
	utils.PanicOnError(err)
	/* reload config */
	b := utils.Bash{
		Command: fmt.Sprintf("kill -9 %d", pid),
		Sudo:    true,
	}
	err = b.Run()
	utils.PanicOnError(err)
}
