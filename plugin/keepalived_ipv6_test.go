package plugin

import (
	"bytes"
	"html/template"
	"strings"
	"testing"
)

func TestNewKeepalivedConfRejectsEmptyHaVips(t *testing.T) {
	_, err := NewKeepalivedConf("eth0", "", "fd00:5:5:28::a2", "", "fd00:5:5:28::a2", nil, 5, nil)
	if err == nil {
		t.Fatalf("expected empty HA VIPs to be rejected")
	}
}

func TestNewKeepalivedConfBuildsIpv6OnlyConfig(t *testing.T) {
	conf, err := NewKeepalivedConf(
		"eth0",
		"",
		"fd00:5:5:28::a2",
		"",
		"fd00:5:5:28::a3",
		[]string{"2001:4860:4860::8888"},
		5,
		[]nicVipPair{{NicName: "eth1", Vip6: "1000:2000:3000:4000::11:e619", Prefix: 64}},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conf.VipV4 != nil {
		t.Fatalf("expected no IPv4 VIP, got %v", conf.VipV4.VipAddress())
	}
	if conf.VipV6 == nil || conf.VipV6.VipAddress() != "1000:2000:3000:4000::11:e619" {
		t.Fatalf("unexpected IPv6 VIP: %#v", conf.VipV6)
	}
	if len(conf.MonitorConfigs) != 1 {
		t.Fatalf("expected one monitor config, got %d", len(conf.MonitorConfigs))
	}
	if conf.MonitorConfigs[0].ScriptName != "monitor_2001_4860_4860_8888" {
		t.Fatalf("unexpected monitor script name: %s", conf.MonitorConfigs[0].ScriptName)
	}
	if conf.MonitorConfigs[0].ScriptFile != "check_monitor_2001_4860_4860_8888.sh" {
		t.Fatalf("unexpected monitor script file: %s", conf.MonitorConfigs[0].ScriptFile)
	}

	tmpl, err := template.New("keepalived.conf").Parse(tKeepalivedConf)
	if err != nil {
		t.Fatalf("failed to parse keepalived template: %v", err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, conf); err != nil {
		t.Fatalf("failed to render keepalived template: %v", err)
	}
	rendered := buf.String()
	for _, expected := range []string{
		"unicast_src_ip fd00:5:5:28::a2",
		"fd00:5:5:28::a3",
		"monitor_2001_4860_4860_8888",
		"check_monitor_2001_4860_4860_8888.sh",
	} {
		if !strings.Contains(rendered, expected) {
			t.Fatalf("rendered keepalived config does not contain %q:\n%s", expected, rendered)
		}
	}
	if strings.Contains(rendered, "monitor_2001:4860") {
		t.Fatalf("rendered keepalived config contains an unsanitized IPv6 monitor name:\n%s", rendered)
	}
}

func TestNewKeepalivedConfKeepsIpv4MonitorNamesCompatible(t *testing.T) {
	conf, err := NewKeepalivedConf(
		"eth0",
		"192.168.1.10",
		"",
		"192.168.1.11",
		"",
		[]string{"8.8.8.8"},
		5,
		[]nicVipPair{{NicName: "eth1", Vip: "192.168.100.10", Prefix: 24}},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(conf.MonitorConfigs) != 1 {
		t.Fatalf("expected one monitor config, got %d", len(conf.MonitorConfigs))
	}
	if conf.MonitorConfigs[0].ScriptName != "monitor_8.8.8.8" {
		t.Fatalf("unexpected monitor script name: %s", conf.MonitorConfigs[0].ScriptName)
	}
	if conf.MonitorConfigs[0].ScriptFile != "check_monitor_8.8.8.8.sh" {
		t.Fatalf("unexpected monitor script file: %s", conf.MonitorConfigs[0].ScriptFile)
	}

	tmpl, err := template.New("keepalived.conf").Parse(tKeepalivedConf)
	if err != nil {
		t.Fatalf("failed to parse keepalived template: %v", err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, conf); err != nil {
		t.Fatalf("failed to render keepalived template: %v", err)
	}
	rendered := buf.String()
	for _, expected := range []string{
		"vrrp_script monitor_8.8.8.8",
		"check_monitor_8.8.8.8.sh",
		"                monitor_8.8.8.8",
		"nopreempt\n\n\tunicast_src_ip 192.168.1.10\n\tunicast_peer {\n\t\t192.168.1.11\n\t}\n\n\ttrack_script",
	} {
		if !strings.Contains(rendered, expected) {
			t.Fatalf("rendered keepalived config does not contain %q:\n%s", expected, rendered)
		}
	}
	if strings.Contains(rendered, "monitor_8_8_8_8") {
		t.Fatalf("rendered keepalived config changed IPv4 monitor name:\n%s", rendered)
	}

	tmpl, err = template.New("keepalived-slb.conf").Parse(tKeepalivedSlbConf)
	if err != nil {
		t.Fatalf("failed to parse slb keepalived template: %v", err)
	}
	buf.Reset()
	if err := tmpl.Execute(&buf, conf); err != nil {
		t.Fatalf("failed to render slb keepalived template: %v", err)
	}
	rendered = buf.String()
	if !strings.Contains(rendered, "nopreempt\n\n\tunicast_src_ip 192.168.1.10\n\tunicast_peer {\n\t\t192.168.1.11\n\t}\n\n\ttrack_script") {
		t.Fatalf("rendered slb keepalived config changed IPv4 unicast spacing:\n%s", rendered)
	}
}
