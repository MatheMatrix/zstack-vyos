package plugin

import (
	"bytes"
	"fmt"
	"github.com/zstackio/zstack-vyos/utils"
	"html/template"
	"io/ioutil"
)

const (
	DNSMASQ_BIN_PATH       = "/usr/sbin/dnsmasq -x /var/run/dnsmasq.pid -u dnsmasq -7 /etc/dnsmasq.d"
	DNSMASQ_CONF_PATH      = "/etc/dnsmasq.conf"
	DNSMASQ_CONF_PATH_TEMP = "/home/vyos/zvr/dnsmasq.conf"
)

const dnsmasqTemplate = `#
# autogenerated by ZStack, DO NOT MODIFY IT
#
log-facility=/var/log/dnsmasq.log
no-poll
edns-packet-max=4096
cache-size=150
{{ range $index, $name := .NicNames }}
interface={{$name}}
{{ end }}
{{ range $index, $ip := .DnsServers }}
server={{$ip}}
{{ end }}
resolv-file=/etc/dnsmasq.conf
`

type DnsmasqConf struct {
	NicNames   []string
	DnsServers []string
}

func NewDnsmasq(nics, servers map[string]string) *DnsmasqConf {
	var nicNames, ips []string
	for nic, _ := range nics {
		nicNames = append(nicNames, nic)
	}
	for ip, _ := range servers {
		ips = append(ips, ip)
	}

	return &DnsmasqConf{NicNames: nicNames, DnsServers: ips}
}

func (d *DnsmasqConf) RestartDnsmasq() error {
	if len(d.DnsServers) == 0 || len(d.NicNames) == 0 {
		bash := utils.Bash{
			Command: fmt.Sprintf("sudo pkill -9 dnsmasq"),
		}
		bash.Run()
		return nil
	}

	tmpl, err := template.New("dnsmasq.conf").Parse(dnsmasqTemplate)
	utils.PanicOnError(err)

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, d)
	utils.PanicOnError(err)

	err = ioutil.WriteFile(DNSMASQ_CONF_PATH_TEMP, buf.Bytes(), 0755)
	utils.PanicOnError(err)
	bash := utils.Bash{
		Command: fmt.Sprintf("sudo mv %s %s",
			DNSMASQ_CONF_PATH_TEMP, DNSMASQ_CONF_PATH),
	}
	err = bash.Run()
	utils.PanicOnError(err)

	err = utils.Retry(func () error {
		bash = utils.Bash {
			Command: fmt.Sprintf("sudo pkill -9 dnsmasq; sudo %s", DNSMASQ_BIN_PATH),
		}
		return bash.Run()
	}, 5, 1)

	utils.PanicOnError(err)

	return nil
}
