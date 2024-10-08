package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"zstack-vyos/plugin"
	"zstack-vyos/utils"

	"github.com/fsnotify/fsnotify"
	log "github.com/sirupsen/logrus"
)

type IpvsHealthCheckBackendServer struct {
	status bool
	cancel context.CancelFunc
	result chan bool
	plugin.IpvsHealthCheckBackendServer
}

var logFile string
var confFile string
var pidFile string

var gHealthCheckMap map[string]*IpvsHealthCheckBackendServer
var healthCheckLock sync.Mutex

func parseCommandOptions() {
	flag.StringVar(&logFile, "log", plugin.IPVS_HEALTH_CHECK_LOG_FILE, "ipvs health check The log file path")
	flag.StringVar(&confFile, "f", plugin.IPVS_HEALTH_CHECK_CONFIG_FILE, "ipvs health check config file path")
	flag.StringVar(&pidFile, "p", plugin.IPVS_HEALTH_CHECK_PID_FILE, "ipvs health check pid file path")

	flag.Parse()
}

func (bs *IpvsHealthCheckBackendServer) getBackendKey() string {
	proto := "udp"
	if strings.ToLower(bs.ProtocolType) == "tcp" || strings.ToLower(bs.ProtocolType) == "-t" {
		proto = "tcp"
	}
	
	return proto + "-" + bs.FrontIp + "-" + bs.FrontPort + "-" + bs.BackendIp + "-" + bs.BackendPort
}

func (bs *IpvsHealthCheckBackendServer) doHealthCheck() {
	if bs.HealthCheckProtocl == "udp" {
		bs.doUdpCheck()
	} else {
		log.Debugf("unknow health check protocol %s", bs.HealthCheckProtocl)
		bs.result <- false
	}
}

func (bs *IpvsHealthCheckBackendServer) Install()  {
	log.Debugf("enable backend server %s:%s for front service %s:%s", bs.BackendIp, bs.BackendPort, bs.FrontIp, bs.FrontPort)
	
	healthCheckLock.Lock()
	defer healthCheckLock.Unlock()
	num :=0
	for _, gbs := range gHealthCheckMap {
		if bs.FrontIp != gbs.FrontIp || bs.FrontPort != gbs.FrontPort || bs.ProtocolType != gbs.ProtocolType {
			continue
		}
		
		if gbs.status {
			num++
		}
	}
	bs.status = true
	
	proto := "-u"
	if strings.ToLower(bs.ProtocolType) == "tcp" || strings.ToLower(bs.ProtocolType) == "-t" {
		proto = "-t"
	}
	frontIp := bs.FrontIp
	ip := net.ParseIP(frontIp)
	if ip != nil && ip.To4() == nil{
		frontIp = fmt.Sprintf("[%s]", frontIp)
	}
	backedIp := bs.BackendIp
	ip = net.ParseIP(backedIp)
	if ip != nil && ip.To4() == nil{
		backedIp = fmt.Sprintf("[%s]", backedIp)
	}

	cmds := []string{}
	if (num == 0) {
		/* first active backend is up, add the service */
		cmds = append(cmds, fmt.Sprintf("ipvsadm -A %s %s:%s -s %s", proto, frontIp, bs.FrontPort, bs.Scheduler))
	}
	cmds = append(cmds, fmt.Sprintf("ipvsadm -a %s %s:%s -r  %s:%s %s -w %s -x %d -y %d",
		proto, frontIp, bs.FrontPort, backedIp, bs.BackendPort, bs.ConnectionType, bs.Weight, 
		bs.MaxConnection, bs.MinConnection))
		
	b := utils.Bash{
		Command: strings.Join(cmds, ";"),
		Sudo: true,
	}
	
	b.Run()
}

func (bs *IpvsHealthCheckBackendServer) UnInstall()  {
	log.Debugf("disable backend server %s:%s for front service %s:%s", bs.BackendIp, bs.BackendPort, bs.FrontIp, bs.FrontPort)
	
	healthCheckLock.Lock()
	defer healthCheckLock.Unlock()
	num := 0
	for _, gbs := range gHealthCheckMap {
		if bs.FrontIp != gbs.FrontIp || bs.FrontPort != gbs.FrontPort || bs.ProtocolType != gbs.ProtocolType {
			continue
		}
		
		if gbs.status {
			num++
		}
	}
	bs.status = false
	
	proto := "-u"
	if strings.ToLower(bs.ProtocolType) == "tcp" || strings.ToLower(bs.ProtocolType) == "-t" {
		proto = "-t"
	}
	frontIp := bs.FrontIp
	ip := net.ParseIP(frontIp)
	if ip != nil && ip.To4() == nil{
		frontIp = fmt.Sprintf("[%s]", frontIp)
	}
	backedIp := bs.BackendIp
	ip = net.ParseIP(backedIp)
	if ip != nil && ip.To4() == nil{
		backedIp = fmt.Sprintf("[%s]", backedIp)
	}
	cmd := fmt.Sprintf("ipvsadm -d %s %s:%s -r %s:%s", proto, frontIp, bs.FrontPort, backedIp, bs.BackendPort)
	if (num <= 1) {
		/* last active backend is down, delete the service */
		cmd = fmt.Sprintf("ipvsadm -D %s %s:%s", proto, frontIp, bs.FrontPort)
	}
		
	b := utils.Bash{
		Command: cmd,
		Sudo: true,
	}
	
	b.Run()
} 

func (bs *IpvsHealthCheckBackendServer) Start() {
	/*
	health check task is loop task: wait for following events:
	1. timer to do health check in another go routine
	2. health check result  ---- wait resulrt from #1
	3. backend server removed -- stopped the health check task 
	*/
	
	taskTimer := time.NewTicker(time.Duration(bs.HealthCheckInterval) * time.Second)
	
	ctx, cancel := context.WithCancel(context.Background())
	bs.cancel = cancel
	bs.result = make(chan bool, 1)
	bs.status = false
	successCnt := 0
	failedCnt := 0

	log.Debugf("health check task started for %s", bs.getBackendKey())
	for {
		select {
		case result := <- bs.result:
			if result {
				successCnt++
				failedCnt = 0
			} else {
				failedCnt++
				successCnt = 0
			}
			
			log.Debugf("%s: healthcheck resut:%v, current status %v:  successCnt: %d,%d failedCnt: %d:%d", 
			    bs.getBackendKey(), result, bs.status,
				successCnt, bs.HealthyThreshold,
				failedCnt,  bs.UnhealthyThreshold)
			if failedCnt >= bs.UnhealthyThreshold && bs.status {
				bs.UnInstall()
			} else if (successCnt >= bs.HealthyThreshold && !bs.status) {
				bs.Install()
			}
			taskTimer.Reset(time.Duration(bs.HealthCheckInterval) * time.Second)
			
		case <- ctx.Done():
			log.Debugf("health check task for %s stopped", bs.getBackendKey())
			taskTimer.Stop()
			return
		
		case <- taskTimer.C:
			// avoid to call DoHealthCheck while previous call is not finished 
			log.Debugf("health check task timer for %s", bs.getBackendKey())
			taskTimer.Stop()
			go bs.doHealthCheck()
		}
	}
}

func (bs *IpvsHealthCheckBackendServer) Stop() {
	log.Debugf("health check task stopped for %s", bs.getBackendKey())
	bs.cancel()
	bs.UnInstall()
}

func handleEvents(events <-chan fsnotify.Event, errors <-chan error) {
	log.Debugf("handleEvents task")
	for {
		select {
			case event, ok := <-events:
				if !ok {
					log.Debugf("file event not ok")
					return
				}
				log.Debugf("file watch event %v", event)
				loadAndStartHealthChecker()
				
			case err, ok := <-errors:
				if !ok {
					return
				}
				log.Debugf("file watch error %v", err)
		}
	}
}

func loadAndStartHealthChecker() {
	var conf plugin.IpvsHealthCheckConf
	err := utils.JsonLoadConfig(confFile, &conf)
	if err != nil {
		log.Debugf("load ipvs health check config failed %v", err)
		return
	}
	
	log.Debugf("conf file %++v", conf)
	checkers := map[string]*IpvsHealthCheckBackendServer{}
	if conf.Services != nil {
		for _, fs := range conf.Services {
			for _, bs := range fs.BackendServers {
				checker := IpvsHealthCheckBackendServer{
					/*  health check will not install ipvs service, untill  backend is up */
					status: false,
					IpvsHealthCheckBackendServer: *bs,
				}
				
				log.Debugf("new checker %+v", checker)
				checkers[checker.getBackendKey()] = &checker
			}
		}
	}

	healthCheckLock.Lock()
	defer healthCheckLock.Unlock()
	
	toDeleted := []string{}
	for _, old := range gHealthCheckMap {
		log.Debugf("old health check task %s", old.getBackendKey())
		check, found:= checkers[old.getBackendKey()]
		if !found {
			log.Debugf("delete health check task for %s", old.getBackendKey())
			toDeleted = append(toDeleted, old.getBackendKey())
		} else {
			/* 后端服务器的health check task 参数可能变化, 有两种处理方式:
			1. copy health check配置参数给old
			2. copy old health check的状态参数给new, 
			此处采用#1 */
			log.Debugf("health check task params %+v", check.IpvsHealthCheckBackendServer)
			old.CopyParamsFrom(&check.IpvsHealthCheckBackendServer)
		}
	}

	log.Debugf("toDeleted: %+v",  toDeleted)
	for _, key := range toDeleted {
		go gHealthCheckMap[key].Stop()
		delete(gHealthCheckMap, key)
		log.Debugf("gHealthCheckMap: %d",  len(gHealthCheckMap))
	}
	
	/* new backend health check */
	for _, check := range checkers {
		_, found:= gHealthCheckMap[check.getBackendKey()]
		if !found {
			log.Debugf("new  health check task %+v", check.getBackendKey())
			gHealthCheckMap[check.getBackendKey()] = check
			go check.Start()
		}
	}
}


func setHealthCheckMapForUT(newMap map[string]*IpvsHealthCheckBackendServer) {
	gHealthCheckMap = newMap
}

func getHealthCheckMapForUT() map[string]*IpvsHealthCheckBackendServer {
	return gHealthCheckMap
}

func setConfFileForUT(path string) {
	confFile = path
}

func writePidToFile(pidFilePath string) error {
	pid := os.Getpid()
	pidStr := strconv.Itoa(pid)
	
	file, err := os.Create(pidFilePath)
	if err != nil {
		return fmt.Errorf("can not create pid file: %v", err)
	}
	defer file.Close()
	
	_, err = file.WriteString(pidStr+"\n")
	if err != nil {
		return fmt.Errorf("can not write pid file: %v", err)
	}
	
	return nil
}
	
func main() {
	parseCommandOptions()
	utils.InitLog(logFile, utils.IsRuingUT())
	
	if pid, _ := utils.ReadPid(pidFile); pid != 0 {
		if utils.ProcessExists(pid) == nil {
			log.Debugf("ipvs health check already running, pid %d", pid)
			return 
		}
	}
	writePidToFile(pidFile)
	
	interruptChan := make(chan os.Signal, 1)
	signal.Notify(interruptChan, syscall.SIGUSR1, syscall.SIGUSR2)
	
	go func() {
		for sig := range interruptChan {
			switch sig {
				case syscall.SIGUSR1:
				case syscall.SIGUSR2:
			}
		}
	}()
	
	gHealthCheckMap = map[string]*IpvsHealthCheckBackendServer{}
	watcher, err := fsnotify.NewWatcher()
	utils.PanicOnError(err)
	defer watcher.Close()
	
	loadAndStartHealthChecker()
	
	watcher.Add(confFile)
	go handleEvents(watcher.Events, watcher.Errors)

	// 主线程不能退出
	select{}
	log.Debugf("ipvs healcheck exit")
}
