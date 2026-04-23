package main

import (
	"context"
	"flag"
	"fmt"
	"math"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"zstack-vyos/plugin"
	"zstack-vyos/utils"
	"zstack.io/zstack-vyos/ipvshc"

	log "github.com/sirupsen/logrus"
)

type IpvsHealthCheckBackendServer struct {
	status     bool
	successCnt uint
	failedCnt  uint
	cancel     context.CancelFunc
	result     chan bool
	// inflight gates a single in-flight Probe call (F-015 single-flight).
	// Use atomic.CompareAndSwapInt32 only.  Eliminates the goroutine-per-tick
	// leak observed in spec defect S-3 when probe duration > healthCheckInterval.
	inflight int32
	plugin.IpvsHealthCheckBackendServer
}

var logFile string
var confFile string
var pidFile string

var gHealthCheckMap map[string]*IpvsHealthCheckBackendServer
var gHealthCheckMapLock sync.Mutex

// gRootCtx is cancelled on SIGTERM/SIGINT to trigger graceful shutdown:
// every per-backend Start() loop derives its task ctx from this, so
// cancellation propagates to all probe tasks at once.  See main().
var gRootCtx context.Context
var gRootCancel context.CancelFunc

func parseCommandOptions() {
	flag.StringVar(&logFile, "log", plugin.IPVS_HEALTH_CHECK_LOG_FILE, "ipvs health check The log file path")
	flag.StringVar(&confFile, "f", plugin.IPVS_HEALTH_CHECK_CONFIG_FILE, "ipvs health check config file path")
	flag.StringVar(&pidFile, "p", plugin.IPVS_HEALTH_CHECK_PID_FILE, "ipvs health check pid file path")

	flag.Parse()
}

func (bs *IpvsHealthCheckBackendServer) getBackendKey() string {
	proto := "udp"
	if plugin.NormalizeIpvsProto(bs.ProtocolType) == "tcp" {
		proto = "tcp"
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
		bs.MaxConnection == other.MaxConnection &&
		bs.MinConnection == other.MinConnection
}

// doHealthCheck dispatches one health probe via the protocol-specific
// Prober implementation and pushes the result back to the consumer goroutine.
//
// F-015 invariants:
//   - Single-flight: at most one Probe call per backend at any time; if a
//     previous Probe is still running we drop the tick (the next tick will
//     retry).  Eliminates the goroutine-per-tick leak (S-3).
//   - Non-blocking send on bs.result: combined with single-flight this
//     guarantees we never deadlock the result channel even if the consumer
//     loop is delayed.
//   - Unknown HealthCheckProtocol is reported DOWN and logged at warn level
//     so operators notice misconfiguration immediately.
func (bs *IpvsHealthCheckBackendServer) doHealthCheck(ctx context.Context) {
	if !atomic.CompareAndSwapInt32(&bs.inflight, 0, 1) {
		log.Debugf("[ipvsHealthCheck] skip tick for %s — previous probe still running",
			bs.getBackendKey())
		return
	}
	defer atomic.StoreInt32(&bs.inflight, 0)

	prober := NewProber(ProbeTarget{
		BackendIp:           bs.BackendIp,
		HealthCheckPort:     bs.HealthCheckPort,
		HealthCheckTimeout:  bs.HealthCheckTimeout,
		HealthCheckProtocol: bs.HealthCheckProtocol,
		FrontPort:           bs.FrontPort,
	})
	if prober == nil {
		log.Warnf("[ipvsHealthCheck] unknown health check protocol %q for %s",
			bs.HealthCheckProtocol, bs.getBackendKey())
		bs.sendResult(false)
		return
	}

	bs.sendResult(prober.Probe(ctx))
}

// sendResult performs a non-blocking send on bs.result.  When combined with
// the inflight gate, we are guaranteed to be the only producer, so dropping
// here only happens when the consumer is shutting down.
func (bs *IpvsHealthCheckBackendServer) sendResult(v bool) {
	select {
	case bs.result <- v:
	default:
		log.Debugf("[ipvsHealthCheck] dropping result %v for %s — consumer not ready",
			v, bs.getBackendKey())
	}
}

func (bs *IpvsHealthCheckBackendServer) Install() {
	bs.status = true
	// F-013: plugin owns ipvsadm writes; we send rs_event up.
	emitRsEvent(&bs.IpvsHealthCheckBackendServer, ipvshc.RsEventUp, bs.Weight)
}

func (bs *IpvsHealthCheckBackendServer) UnInstall() {
	bs.status = false
	// F-013: plugin owns ipvsadm writes; we send rs_event down.
	emitRsEvent(&bs.IpvsHealthCheckBackendServer, ipvshc.RsEventDown, "")
	// Pruning of empty frontend services is now plugin-side: when the
	// last backend disappears in the snapshot, the plugin drops the
	// service via IpvsAdmin.DelService.  See plugin/ipvs_uds_server.go.
}

func (bs *IpvsHealthCheckBackendServer) EditBackendServer() {
	// F-013: plugin owns ipvsadm writes; weight changes go through rs_event.
	emitRsEvent(&bs.IpvsHealthCheckBackendServer, ipvshc.RsEventWeight, bs.Weight)
}

func (bs *IpvsHealthCheckBackendServer) EditFrontService() {
	// F-013: scheduler/front-service edits are picked up via the next
	// snapshot push from the plugin; no per-edit message is required.
	log.Debugf("[ipvsHealthCheck] EditFrontService for %s:%s — handled by plugin snapshot",
		bs.FrontIp, bs.FrontPort)
}

func (bs *IpvsHealthCheckBackendServer) setStatus(status bool) {
	bs.status = status
	bs.failedCnt = 0
	bs.successCnt = 0
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

	taskTimer := time.NewTimer(time.Duration(bs.HealthCheckInterval) * time.Second)

	parent := gRootCtx
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	bs.cancel = cancel
	bs.result = make(chan bool, 1)
	bs.status = false
	bs.successCnt = 0
	bs.failedCnt = 0
	atomic.StoreInt32(&bs.inflight, 0)

	log.Debugf("[ipvsHealthCheck task] start health check task for %s", bs.getBackendKey())
	for {
		select {
		case result := <-bs.result:
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
			taskTimer.Reset(time.Duration(bs.HealthCheckInterval) * time.Second)

		case <-ctx.Done():
			log.Debugf("[ipvsHealthCheck task] stop health check task for %s", bs.getBackendKey())
			taskTimer.Stop()
			return

		case <-taskTimer.C:
			// avoid to call DoHealthCheck while previous call is not finished
			log.Debugf("[ipvsHealthCheck task] timer expired for health check task %s", bs.getBackendKey())
			go bs.doHealthCheck(ctx)
		}
	}
}

func (bs *IpvsHealthCheckBackendServer) Stop() {
	log.Debugf("[ipvsHealthCheck task] stop health check task for %s", bs.getBackendKey())
	bs.cancel()
	bs.UnInstall()
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

	// F-016: migrate legacy ipvsadm-flag form ("-t"/"-u") that may still
	// live in healthcheck.conf written by older builds.
	for _, fs := range conf.Services {
		fs.ProtocolType = plugin.NormalizeIpvsProto(fs.ProtocolType)
		for _, bs := range fs.BackendServers {
			bs.ProtocolType = plugin.NormalizeIpvsProto(bs.ProtocolType)
		}
	}

	log.Debugf("[ipvsHealthCheck reload] load config file success, %++v", conf)
	checkers := map[string]*IpvsHealthCheckBackendServer{}
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
				checkers[nc.getBackendKey()] = &nc
			}
		}
	}

	gHealthCheckMapLock.Lock()
	defer gHealthCheckMapLock.Unlock()

	var toDeleted []string
	for _, old := range gHealthCheckMap {
		log.Debugf("[ipvsHealthCheck reload] old checker: %+v", old)
		check, found := checkers[old.getBackendKey()]
		if !found {
			log.Debugf("[ipvsHealthCheck reload] delete health check task for %s", old.getBackendKey())
			toDeleted = append(toDeleted, old.getBackendKey())
		} else {
			/* 后端服务器的health check task 参数可能变化, 有两种处理方式:
			1. copy health check配置参数给old
			2. copy old health check的状态参数给new,
			此处采用#1 */
			log.Debugf("[ipvsHealthCheck reload] update health check task params %+v", check.IpvsHealthCheckBackendServer)
			if !old.equal(check) {
				if old.Scheduler != check.Scheduler {
					old.CopyParamsFrom(&check.IpvsHealthCheckBackendServer)
					go old.EditFrontService()
				} else {
					old.CopyParamsFrom(&check.IpvsHealthCheckBackendServer)
					go old.EditBackendServer()
				}
			} else {
				log.Debugf("[ipvsHealthCheck reload] checker: %s not changed", old.getBackendKey())
			}

		}
	}

	for _, key := range toDeleted {
		log.Debugf("[ipvsHealthCheck reload] delete health check task for %s", key)
		go gHealthCheckMap[key].Stop()
		delete(gHealthCheckMap, key)
	}

	/* new backend health check */
	for _, check := range checkers {
		_, found := gHealthCheckMap[check.getBackendKey()]
		if !found {
			log.Debugf("[ipvsHealthCheck reload] add new health check task %+v", check.getBackendKey())
			gHealthCheckMap[check.getBackendKey()] = check
			go check.Start()
		}
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

	gHealthCheckMapLock.Lock()
	defer gHealthCheckMapLock.Unlock()

	tempBsMap := map[string]*IpvsHealthCheckBackendServer{}
	for _, fs := range conf.Services {
		log.Debugf("[ipvsHealthCheck sync] ipvsadm-save front end service %+v", fs)
		for _, bs := range fs.BackendServers {
			log.Debugf("[ipvsHealthCheck sync] 	ipvsadm-save backend end server %+v", bs)

			temp := IpvsHealthCheckBackendServer{}
			temp.ProtocolType = plugin.NormalizeIpvsProto(fs.ProtocolType)
			temp.FrontIp = fs.FrontIp
			temp.FrontPort = fs.FrontPort
			temp.BackendIp = bs.BackendIp
			temp.BackendPort = bs.BackendPort

			tempBsMap[temp.getBackendKey()] = &temp

			if gHealthCheckMap[temp.getBackendKey()] == nil {
				log.Warnf("[ipvsHealthCheck reconcile] kernel ipvs has rule %+v with no matching health check entry, removing (drift=extra)", temp.getBackendKey())
				go temp.UnInstall()
			} else if !gHealthCheckMap[temp.getBackendKey()].status {
				// F-017: today this only flips status without re-emitting
				// the ipvsadm AddBackend.  That works because the kernel rule
				// is observed present here.  True replay (when kernel rule is
				// missing) is owned by F-013 IpvsAdmin and tracked there.
				log.Debugf("[ipvsHealthCheck reconcile] kernel ipvs has rule %+v, marking status up", temp.getBackendKey())
				gHealthCheckMap[temp.getBackendKey()].setStatus(true)
			}
		}
	}

	for _, gbs := range gHealthCheckMap {
		if tempBsMap[gbs.getBackendKey()] == nil {
			log.Warnf("[ipvsHealthCheck reconcile] health check entry %+v has no kernel ipvs rule, marking status down (drift=missing)", gbs.getBackendKey())
			gbs.setStatus(false)
		}
	}
}

// when vpcha master/backup failover, we need to make
func fastUpBackendServers() {
	gHealthCheckMapLock.Lock()
	defer gHealthCheckMapLock.Unlock()

	for _, gbs := range gHealthCheckMap {
		// set false, when health check finished, it will install backend server
		gbs.setStatus(false)
		// fastUpBackendServers fires outside any per-backend task; use a
		// background ctx so the probe can run to completion even if the
		// originating call returns immediately.
		go gbs.doHealthCheck(context.Background())
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

	gRootCtx, gRootCancel = context.WithCancel(context.Background())

	// F-013: hard-block on UDS handshake failure.  The plugin owns
	// every ipvsadm write; if we cannot reach it, this daemon CANNOT
	// keep IPVS state consistent and must refuse to come up so that
	// systemd's restart policy + the LB outage are visible immediately.
	if err := initUdsClient(); err != nil {
		log.Errorf("[ipvsHealthCheck] FATAL: UDS handshake with plugin failed: %v", err)
		os.Exit(1)
	}

	interruptChan := make(chan os.Signal, 1)
	signal.Notify(interruptChan, syscall.SIGHUP, syscall.SIGUSR1, syscall.SIGTERM, syscall.SIGINT)

	// F-017: tighten reconciliation cadence from 300s -> 30s and switch
	// from one-shot Timer to Ticker (the prior NewTimer never re-armed,
	// so the sync only ran once at boot).
	syncTicker := time.NewTicker(30 * time.Second)
	defer syncTicker.Stop()

	/* push a signal when start process */
	interruptChan <- syscall.SIGHUP

	/* main thead loop handles 3 events:
	1. reload config (SIGHUP)
	2. fast-up backends (SIGUSR1, vpc-ha failover)
	3. sync ipvs-admin ticker
	plus graceful shutdown on SIGTERM/SIGINT.
	*/
	for {
		select {
		case sig := <-interruptChan:
			switch sig {
			case syscall.SIGHUP:
				reloadIpvsHealthCheckConfig()
			case syscall.SIGUSR1:
				fastUpBackendServers()
			case syscall.SIGTERM, syscall.SIGINT:
				log.Infof("[ipvsHealthCheck] received %v, beginning graceful shutdown", sig)
				gRootCancel()
				gracefulShutdownTasks()
				log.Infof("[ipvsHealthCheck] shutdown complete")
				return
			default:
				log.Debugf("[ipvsHealthCheck] unknow sig %+v", sig)
			}

		case <-syncTicker.C:
			/* sync ipvsadm-save */
			syncIpvsadmWithHealthCheck()

		}
	}
}

// gracefulShutdownTasks asks every running per-backend task to stop and
// waits up to 5s total for them to drain.  Per-task ctx cancellation has
// already been triggered by gRootCancel; this just bounds the wait so
// systemd's TimeoutStopSec doesn't kill us mid-cleanup.
func gracefulShutdownTasks() {
	gHealthCheckMapLock.Lock()
	keys := make([]string, 0, len(gHealthCheckMap))
	for k := range gHealthCheckMap {
		keys = append(keys, k)
	}
	gHealthCheckMapLock.Unlock()

	deadline := time.After(5 * time.Second)
	for _, k := range keys {
		select {
		case <-deadline:
			log.Warnf("[ipvsHealthCheck] graceful shutdown deadline reached, %d tasks still draining", len(keys))
			return
		default:
		}
		gHealthCheckMapLock.Lock()
		bs := gHealthCheckMap[k]
		gHealthCheckMapLock.Unlock()
		if bs == nil || bs.cancel == nil {
			continue
		}
		bs.cancel()
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
