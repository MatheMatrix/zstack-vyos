package plugin

import (
	"bytes"
	"os"
	"zvr/server"
	"zvr/utils"
	log "github.com/Sirupsen/logrus"
	"fmt"
	"io/ioutil"
)

const (
	INIT_PATH = "/init"
	PING_PATH = "/ping"
	ECHO_PATH = "/echo"
	CONFIGURE_NTP_PATH = "/configurentp"
	/* please follow following rule to change the version:
	  http://confluence.zstack.io/pages/viewpage.action?pageId=34014178 */
	VERSION_FILE_PATH = "/home/vyos/zvr/version"
	NETWORK_HEALTH_STATUS_PATH = "/home/vyos/zvr/.duplicate"
	NTP_CONF_DIR = "/home/vyos/zvr/ntp/conf/"
)

var (
	VERSION = ""
)

type InitConfig struct {
	RestartDnsmasqAfterNumberOfSIGUSER1 int `json:"restartDnsmasqAfterNumberOfSIGUSER1"`
	Uuid string `json:"uuid"`
	MgtCidr string `json:"mgtCidr"`
	LogLevel string `json:"logLevel"`
	TimeServers []string `json:"timeServers"`
}

type pingRsp struct {
	Uuid string `json:"uuid"`
	Version string `json:"version"`
	HaStatus string `json:"haStatus"`
	Healthy bool `json:"healthy"`
	HealthDetail string `json:"healthDetail"`
}

type configureNtpCmd struct {
	TimeServers []string `json:"timeServers"`
}

var (
	initConfig = &InitConfig{}
)
type networkHealthCheck struct {}
type fsHealthCheck struct {}

func (check *networkHealthCheck)healthCheck() (status HealthStatus) {
	status = HealthStatus{Healthy:true, HealthDetail:""}
	if e, _ := utils.PathExists(NETWORK_HEALTH_STATUS_PATH); e {
		f, _ := ioutil.ReadFile(NETWORK_HEALTH_STATUS_PATH)
		status.Healthy = false
                status.HealthDetail = string(f)
	}

	return status
}

func (check *fsHealthCheck)healthCheck() (status HealthStatus) {
	bash := utils.Bash{
		Command: "sudo mount|grep -w ro | grep -v loop0 | grep -v tmpfs",
	}
	status = HealthStatus{Healthy:true, HealthDetail:""}
	if ret, output, _, err := bash.RunWithReturn(); err == nil && ret == 0 {
		status.Healthy = false
		status.HealthDetail = fmt.Sprintf("RO file system: %s", output)
	}
	return status
}

func configureNtp(timeServers []string){
	if timeServers == nil || len(timeServers) == 0{
		return
	}
	var conf bytes.Buffer
	conf.WriteString( `# /etc/ntp.conf, configuration for ntpd; see ntp.conf(5) for help
# This configuration file is automatically generated by the Vyatta
# configuration subsystem.  Please do not manually edit it.
#
# The first section of this file consists of static parameters
# that can not be changed via the Vyatta configuration subsystem.
#
driftfile /var/lib/ntp/ntp.drift
# By default, exchange time with everybody, but don't allow configuration.
restrict -4 default kod notrap nomodify nopeer noquery
restrict -6 default kod notrap nomodify nopeer noquery
# Local users may interrogate the ntp server more closely.

restrict 127.0.0.1
restrict ::1

# Listen local ports only
interface ignore wildcard
interface listen 127.0.0.1
interface listen ::1

#
# The remainder of this file is for parameters that are set up via
# the Vyatta configuration subsystem.
#

`)

	for _,chronyServer := range timeServers {
		conf.WriteString("server " + chronyServer + "\n")
	}


	ntp_conf_file, err := ioutil.TempFile(NTP_CONF_DIR, "ntpConfig"); utils.PanicOnError(err)
	_, err = ntp_conf_file.Write(conf.Bytes()); utils.PanicOnError(err)

	bash := utils.Bash{
		Command: fmt.Sprintf("sudo mv %s /etc/ntp.conf; sudo /etc/init.d/ntp restart",
			ntp_conf_file.Name()),
	}
	err = bash.Run();utils.PanicOnError(err)
}
func initHandler(ctx *server.CommandContext) interface{} {
	ctx.GetCommand(initConfig)
	addRouteIfCallbackIpChanged()
	if initConfig.MgtCidr != "" {
		mgmtNic:= utils.GetMgmtInfoFromBootInfo()
		nexthop, _ := utils.GetNexthop(initConfig.MgtCidr)
		if nexthop != "" && nexthop != mgmtNic["gateway"].(string) {
			utils.AddRoute(initConfig.MgtCidr, mgmtNic["gateway"].(string))
		}
	}

	tree := server.NewParserFromShowConfiguration().Tree
	if tree.Get("system task-scheduler task ssh") == nil {
		tree.Set("system task-scheduler task ssh interval 1")
		tree.Set(fmt.Sprintf("system task-scheduler task ssh executable path '%s'", utils.Cronjob_file_ssh))
	}

	if tree.Get("system task-scheduler task zsn") == nil {
		tree.Set("system task-scheduler task zsn interval 1")
		tree.Set(fmt.Sprintf("system task-scheduler task zsn executable path '%s'", utils.Cronjob_file_zsn))
	}
	tree.Apply(false)

	doRefreshLogLevel(initConfig.LogLevel)
	configureNtp(initConfig.TimeServers)
	return nil
}

func pingHandler(ctx *server.CommandContext) interface{} {

	addRouteIfCallbackIpChanged()
	var haStatus string
	if !utils.IsHaEnabled() {
		haStatus = utils.NOHA
	} else if IsMaster() {
		haStatus = utils.HAMASTER
	} else {
		haStatus = utils.HABACKUP
	}
	return pingRsp{Uuid: initConfig.Uuid, Version: string(VERSION), HaStatus: haStatus,
		Healthy:healthStatus.Healthy, HealthDetail:healthStatus.HealthDetail }
}

func echoHandler(ctx *server.CommandContext) interface{} {
	return nil
}

func configureNtpHandle(ctx *server.CommandContext) interface{}{
	cmd := &configureNtpCmd{}
	ctx.GetCommand(cmd)

	configureNtp(cmd.TimeServers)
	return nil
}
func MiscEntryPoint() {
	server.RegisterAsyncCommandHandler(INIT_PATH, initHandler)
	server.RegisterAsyncCommandHandler(PING_PATH, pingHandler)
	server.RegisterSyncCommandHandler(ECHO_PATH, echoHandler)
	server.RegisterAsyncCommandHandler(CONFIGURE_NTP_PATH, configureNtpHandle)
}

func GetInitConfig() *InitConfig {
	return initConfig
}

func addRouteIfCallbackIpChanged() {
	if server.CURRENT_CALLBACK_IP != server.CALLBACK_IP {
		if server.CURRENT_CALLBACK_IP == "" {
			log.Debug(fmt.Sprintf("agent first start, add static route to callback ip host"))
		} else {
			log.Debug(fmt.Sprintf("detect call back ip host changed, add static route"))
		}
		// NOTE(WeiW): Since our mgmt nic is always eth0
		if server.CURRENT_CALLBACK_IP != "" {
			err := utils.RemoveZStackRoute(server.CURRENT_CALLBACK_IP);
			utils.PanicOnError(err)
		}

		mgmtNic := utils.GetMgmtInfoFromBootInfo()
		if (mgmtNic == nil || utils.CheckMgmtCidrContainsIp(server.CALLBACK_IP, mgmtNic) == false) {
			err := utils.SetZStackRoute(server.CALLBACK_IP, "eth0", mgmtNic["gateway"].(string)); utils.PanicOnError(err)
		} else if mgmtNic == nil {
			log.Debugf("can not get mgmt nic info, skip to configure route")
		} else if utils.GetNicForRoute(server.CALLBACK_IP) != "eth0" {
			err := utils.SetZStackRoute(server.CALLBACK_IP, "eth0", ""); utils.PanicOnError(err)
		} else {
			log.Debugf("the cidr of vr mgmt contains callback ip, skip to configure route")
		}
		server.CURRENT_CALLBACK_IP = server.CALLBACK_IP
	}
}

func init ()  {
	os.MkdirAll(NTP_CONF_DIR, os.ModePerm)
	ver, err := ioutil.ReadFile(VERSION_FILE_PATH)
	if err == nil {
		VERSION = string(ver)
	}
	RegisterHealthCheckCallback(&fsHealthCheck{})
	RegisterHealthCheckCallback(&networkHealthCheck{})
}
