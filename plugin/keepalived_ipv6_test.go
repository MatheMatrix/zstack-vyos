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
		"virtual_ipaddress",
		"1000:2000:3000:4000::11:e619/64 dev eth1 no_track",
	} {
		if !strings.Contains(rendered, expected) {
			t.Fatalf("rendered keepalived config does not contain %q:\n%s", expected, rendered)
		}
	}
	if strings.Contains(rendered, "monitor_2001:4860") {
		t.Fatalf("rendered keepalived config contains an unsanitized IPv6 monitor name:\n%s", rendered)
	}
}

func TestZSTAC86958UsesIpv6HeartbeatForIpv4Vip(t *testing.T) {
	conf, err := NewKeepalivedConf(
		"eth0",
		"",
		"fd66:6:6:6:ac18:f151:0:142",
		"",
		"fd66:6:6:6:ac18:f151:0:1b8",
		[]string{"192.168.0.1"},
		5,
		[]nicVipPair{{NicName: "eth1", Vip: "172.24.13.9", Prefix: 16}},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	conf.IsEuler2203 = true

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
		"unicast_src_ip fd66:6:6:6:ac18:f151:0:142",
		"fd66:6:6:6:ac18:f151:0:1b8",
		"no_virtual_ipaddress",
	} {
		if !strings.Contains(rendered, expected) {
			t.Fatalf("rendered keepalived config does not contain %q:\n%s", expected, rendered)
		}
	}
}

func TestNewKeepalivedConfRejectsIncompleteHeartbeatPairs(t *testing.T) {
	_, err := NewKeepalivedConf(
		"eth0",
		"192.168.1.10",
		"",
		"",
		"fd66:6:6:6:ac18:f151:0:1b8",
		nil,
		5,
		[]nicVipPair{{NicName: "eth1", Vip: "172.24.13.9", Prefix: 16}},
	)
	if err == nil {
		t.Fatalf("expected incomplete heartbeat pairs to be rejected")
	}
}

func TestNewKeepalivedConfFallsBackToValidIpv6HeartbeatPair(t *testing.T) {
	conf, err := NewKeepalivedConf(
		"eth0",
		"192.168.1.10",
		"fd66:6:6:6:ac18:f151:0:142",
		"",
		"fd66:6:6:6:ac18:f151:0:1b8",
		nil,
		5,
		[]nicVipPair{{NicName: "eth1", Vip: "172.24.13.9", Prefix: 16}},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conf.UnicastSrcIp != "fd66:6:6:6:ac18:f151:0:142" ||
		conf.UnicastPeerIp != "fd66:6:6:6:ac18:f151:0:1b8" {
		t.Fatalf("unexpected unicast heartbeat pair: %s, %s", conf.UnicastSrcIp, conf.UnicastPeerIp)
	}
}

func TestSlbIpv6UsesVipFamilyHeartbeat(t *testing.T) {
	conf, err := NewKeepalivedConf(
		"eth0",
		"192.168.1.10",
		"fd66:6:6:6:ac18:f151:0:142",
		"192.168.1.11",
		"fd66:6:6:6:ac18:f151:0:1b8",
		nil,
		5,
		[]nicVipPair{{NicName: "eth1", Vip6: "fd00:10::100", Prefix: 64}},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tmpl, err := template.New("keepalived.conf").Parse(tKeepalivedSlbConf)
	if err != nil {
		t.Fatalf("failed to parse keepalived template: %v", err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, conf); err != nil {
		t.Fatalf("failed to render keepalived template: %v", err)
	}

	rendered := buf.String()
	for _, expected := range []string{
		"unicast_src_ip fd66:6:6:6:ac18:f151:0:142",
		"fd66:6:6:6:ac18:f151:0:1b8",
		"virtual_ipaddress",
		"fd00:10::100/64",
	} {
		if !strings.Contains(rendered, expected) {
			t.Fatalf("rendered SLB config does not contain %q:\n%s", expected, rendered)
		}
	}
	if strings.Contains(rendered, "unicast_src_ip 192.168.1.10") {
		t.Fatalf("rendered IPv6 SLB config selected the IPv4 heartbeat:\n%s", rendered)
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
	conf.IsEuler2203 = true
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
	if strings.Contains(rendered, "no_virtual_ipaddress") {
		t.Fatalf("rendered IPv4 keepalived config changed no-VIP behavior:\n%s", rendered)
	}
	if strings.Contains(rendered, "virtual_ipaddress {") {
		t.Fatalf("rendered IPv4 keepalived config lets keepalived manage HA VIPs:\n%s", rendered)
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

func TestKeepalivedConfDeclaresIpv6VipWithoutTrackingVipNic(t *testing.T) {
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

	tmpl, err := template.New("keepalived.conf").Parse(tKeepalivedConf)
	if err != nil {
		t.Fatalf("failed to parse keepalived template: %v", err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, conf); err != nil {
		t.Fatalf("failed to render keepalived template: %v", err)
	}
	rendered := buf.String()
	if !strings.Contains(rendered, "virtual_ipaddress") {
		t.Fatalf("rendered keepalived config does not declare an IPv6 VIP:\n%s", rendered)
	}
	if !strings.Contains(rendered, "1000:2000:3000:4000::11:e619/64 dev eth1 no_track") {
		t.Fatalf("rendered keepalived config does not avoid tracking the VIP nic:\n%s", rendered)
	}
}
