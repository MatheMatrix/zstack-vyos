package plugin

import (
	"fmt"
	"strings"

	"zstack-vyos/server"
	"zstack-vyos/utils"
)

const (
	CONFIG_SNAT_LOG_PATH = "/snat/log/config"

	snatLogCollectorServiceName = "snatLogCollector"
	snatLogRsyslogConfPath      = "/etc/rsyslog.d/snat.conf"
	snatLogRuntimeEnvPath       = "/etc/zstack/snat-log.env"
	snatLogLocalFilePath        = "/var/log/snat_conntrack.log"
	snatLogRsyslogPort          = "15514"
)

type ConfigSnatLogCmd struct {
	Enable            bool    `json:"enable"`
	ManagementNodeIp  *string `json:"managementNodeIp"`
	ManagementNodeVip *string `json:"managementNodeVip"`
}

type ConfigSnatLogRsp struct {
	ServiceStatus string `json:"serviceStatus"`
}

type snatLogRuntimeConfig struct {
	VpcUUID      string
	VpcDefaultIP string
	MnVip        string
	MnIP         string
	MnPeerIP     string
	MgmtIP       string
}

func getBootstrapStringValue(key string) string {
	v, ok := utils.BootstrapInfo[key]
	if !ok {
		return ""
	}

	s, ok := v.(string)
	if !ok {
		return ""
	}

	return strings.TrimSpace(s)
}

func getOptionalCommandStringValue(v *string) string {
	if v == nil {
		return ""
	}

	return strings.TrimSpace(*v)
}

func applySnatLogMnOverrides(conf snatLogRuntimeConfig, cmd *ConfigSnatLogCmd) snatLogRuntimeConfig {
	if cmd == nil {
		return conf
	}

	// When management node addresses are provided by MN, treat them as the
	// source of truth for this refresh, including clearing a stale VIP.
	if cmd.ManagementNodeIp == nil && cmd.ManagementNodeVip == nil {
		return conf
	}

	if cmd.ManagementNodeIp != nil {
		conf.MnIP = getOptionalCommandStringValue(cmd.ManagementNodeIp)
		conf.MnVip = ""
	}
	if cmd.ManagementNodeVip != nil {
		conf.MnVip = getOptionalCommandStringValue(cmd.ManagementNodeVip)
	}

	return conf
}

func getSnatLogTargetMnIp(conf snatLogRuntimeConfig) string {
	if conf.MnVip != "" {
		return conf.MnVip
	}

	if conf.MnIP != "" {
		return conf.MnIP
	}

	if conf.MnPeerIP != "" {
		return conf.MnPeerIP
	}

	return ""
}

func getSnatLogRuntimeConfig() snatLogRuntimeConfig {
	conf := snatLogRuntimeConfig{}
	conf.VpcUUID = utils.GetVirtualRouterUuid()
	conf.VpcDefaultIP = getVpcDefaultPublicIp()
	conf.MnVip = getBootstrapStringValue("managementNodeVip")
	conf.MnIP = getBootstrapStringValue("managementNodeIp")
	conf.MnPeerIP = getBootstrapStringValue("managementPeerNodeIp")

	if mgmtNic, ok := utils.BootstrapInfo["managementNic"].(map[string]interface{}); ok {
		conf.MgmtIP = utils.GetManagementNicAddress(mgmtNic)
	}

	return conf
}

func getDefaultPublicIpFromNic(nic map[string]interface{}) (string, bool) {
	if nic == nil {
		return "", false
	}

	ip, _ := nic["ip"].(string)
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return "", false
	}

	category, _ := nic["category"].(string)
	if !strings.EqualFold(strings.TrimSpace(category), utils.NIC_TYPE_PUBLIC) {
		return "", false
	}

	isDefault, _ := nic["isDefaultRoute"].(bool)
	return ip, isDefault
}

func getVpcDefaultPublicIp() string {
	if mgmtNic, ok := utils.BootstrapInfo["managementNic"].(map[string]interface{}); ok {
		if ip, isDefault := getDefaultPublicIpFromNic(mgmtNic); isDefault {
			return ip
		}
	}

	if otherNics, ok := utils.BootstrapInfo["additionalNics"].([]interface{}); ok {
		for _, item := range otherNics {
			onic, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			if ip, isDefault := getDefaultPublicIpFromNic(onic); isDefault {
				return ip
			}
		}
	}

	if otherNics, ok := utils.BootstrapInfo["additionalNics"].([]interface{}); ok {
		for _, item := range otherNics {
			onic, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			if ip, _ := getDefaultPublicIpFromNic(onic); ip != "" {
				return ip
			}
		}
	}

	if mgmtNic, ok := utils.BootstrapInfo["managementNic"].(map[string]interface{}); ok {
		if ip, _ := getDefaultPublicIpFromNic(mgmtNic); ip != "" {
			return ip
		}
	}

	return ""
}

func buildSnatLogRuntimeEnv(conf snatLogRuntimeConfig) string {
	return fmt.Sprintf("VPC_UUID=%s\nVPC_DEFAULT_IP=%s\nMN_VIP=%s\nMN_IP=%s\nMN_PEER_IP=%s\nMGMT_IP=%s\n",
		conf.VpcUUID, conf.VpcDefaultIP, conf.MnVip, conf.MnIP, conf.MnPeerIP, conf.MgmtIP)
}

func configureSnatLogRuntimeEnv(conf snatLogRuntimeConfig) error {
	if strings.TrimSpace(conf.VpcUUID) == "" {
		return fmt.Errorf("vpc uuid is empty")
	}

	mkdir := utils.Bash{
		Command: "mkdir -p /etc/zstack",
		Sudo:    true,
	}
	if err := mkdir.Run(); err != nil {
		return err
	}

	if err := utils.WriteFile(snatLogRuntimeEnvPath, buildSnatLogRuntimeEnv(conf)); err != nil {
		return err
	}

	chmod := utils.Bash{
		Command: fmt.Sprintf("chmod 0644 %s && chown root:root %s", snatLogRuntimeEnvPath, snatLogRuntimeEnvPath),
		Sudo:    true,
	}

	return chmod.Run()
}

func buildSnatRsyslogConf(targetIp string) string {
	return fmt.Sprintf(`module(load="imfile")

input(type="imfile"
      File="%s"
      Tag="snat.raw"
      Severity="info"
      Facility="local4"
      PersistStateInterval="100"
      reopenOnTruncate="on")

if ($syslogtag contains "snat.raw") then {
    action(type="omfwd"
           target="%s"
           port="%s"
           protocol="tcp"
           template="RSYSLOG_SyslogProtocol23Format"
           action.resumeRetryCount="-1"
           queue.type="LinkedList"
           queue.filename="snat_forward"
           queue.maxdiskspace="256m"
           queue.saveonshutdown="on")
    stop
}
`, snatLogLocalFilePath, targetIp, snatLogRsyslogPort)
}

func configureSnatRsyslog(enable bool, targetIp string) error {
	if enable {
		if strings.TrimSpace(targetIp) == "" {
			return fmt.Errorf("management node ip is empty")
		}

		if err := utils.WriteFile(snatLogRsyslogConfPath, buildSnatRsyslogConf(targetIp)); err != nil {
			return err
		}

		chmod := utils.Bash{
			Command: fmt.Sprintf("chmod 0644 %s && chown root:root %s", snatLogRsyslogConfPath, snatLogRsyslogConfPath),
			Sudo:    true,
		}
		if err := chmod.Run(); err != nil {
			return err
		}
	} else {
		remove := utils.Bash{
			Command: fmt.Sprintf("rm -f %s", snatLogRsyslogConfPath),
			Sudo:    true,
		}
		if err := remove.Run(); err != nil {
			return err
		}
	}

	return utils.ServiceOperation("rsyslog", "restart")
}

func removeSnatLogRuntimeEnv() error {
	remove := utils.Bash{
		Command: fmt.Sprintf("rm -f %s", snatLogRuntimeEnvPath),
		Sudo:    true,
	}
	return remove.Run()
}

func disableSnatLog() error {
	errs := make([]string, 0, 3)

	if err := configureSnatCollector(false); err != nil {
		errs = append(errs, err.Error())
	}
	if err := configureSnatRsyslog(false, ""); err != nil {
		errs = append(errs, err.Error())
	}
	if err := removeSnatLogRuntimeEnv(); err != nil {
		errs = append(errs, err.Error())
	}

	if len(errs) != 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

func enableSnatLog(cmd *ConfigSnatLogCmd) (err error) {
	runtimeConf := applySnatLogMnOverrides(getSnatLogRuntimeConfig(), cmd)
	if err = configureSnatLogRuntimeEnv(runtimeConf); err != nil {
		return err
	}

	rollback := true
	defer func() {
		if !rollback || err == nil {
			return
		}

		if rollbackErr := disableSnatLog(); rollbackErr != nil {
			err = fmt.Errorf("%v; rollback failed: %v", err, rollbackErr)
		}
	}()

	mnIp := getSnatLogTargetMnIp(runtimeConf)
	if err = configureSnatRsyslog(true, mnIp); err != nil {
		return err
	}

	if err = configureSnatCollector(true); err != nil {
		return err
	}

	rollback = false
	return nil
}

func configureSnatCollector(enable bool) error {
	if enable {
		start := utils.Bash{
			Command: fmt.Sprintf("systemctl daemon-reload && systemctl enable %s && (systemctl is-active --quiet %s && systemctl restart %s || systemctl start %s)",
				snatLogCollectorServiceName,
				snatLogCollectorServiceName,
				snatLogCollectorServiceName,
				snatLogCollectorServiceName,
			),
			Sudo: true,
		}
		return start.Run()
	}

	stop := utils.Bash{
		Command: fmt.Sprintf("systemctl disable --now %s", snatLogCollectorServiceName),
		Sudo:    true,
	}
	retCode, _, stderr, err := stop.RunWithReturn()
	if err != nil {
		return err
	}
	if retCode != 0 {
		errMsg := strings.ToLower(stderr)
		if strings.Contains(errMsg, "not found") || strings.Contains(errMsg, "not loaded") {
			return nil
		}
		return fmt.Errorf("failed to disable %s: %s", snatLogCollectorServiceName, stderr)
	}
	return nil
}

func configSnatLogHandler(ctx *server.CommandContext) interface{} {
	cmd := &ConfigSnatLogCmd{}
	ctx.GetCommand(cmd)

	if !utils.IsEuler2203() || utils.IsSLB() {
		return ConfigSnatLogRsp{ServiceStatus: "disable"}
	}

	if cmd.Enable {
		err := enableSnatLog(cmd)
		utils.PanicOnError(err)

		return ConfigSnatLogRsp{ServiceStatus: "enable"}
	}

	err := disableSnatLog()
	utils.PanicOnError(err)

	return ConfigSnatLogRsp{ServiceStatus: "disable"}
}

func SnatLogEntryPoint() {
	server.RegisterAsyncCommandHandler(CONFIG_SNAT_LOG_PATH, server.VyosLock(configSnatLogHandler))
}
