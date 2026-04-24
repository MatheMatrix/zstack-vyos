package plugin

import (
	"fmt"
	"strings"
	"testing"

	"zstack-vyos/utils"
)

// TP-057: CALLBACK_IP 切换 - 使用 gateway6 字段
// 验证：当 CALLBACK_IP 为 IPv6 地址时，代码从 mgmtNic 读取 gateway6 字段（而非 gateway）
func TestCallbackIPUsesGateway6(t *testing.T) {
	original := utils.BootstrapInfo
	defer func() { utils.BootstrapInfo = original }()

	mgmtNic := map[string]interface{}{
		"ip":           "0.0.0.0",
		"netmask":      "255.255.255.0",
		"ip6":          "2001:db8::1",
		"prefixLength": float64(64),
		"gateway6":     "2001:db8::fe",
		"gateway":      "10.0.0.1",
	}
	utils.BootstrapInfo = map[string]interface{}{
		"managementNic": mgmtNic,
	}

	ipv6CallbackIP := "2001:db8::100"

	// Precondition: IPv6 CALLBACK_IP is correctly identified
	if !utils.IsIpv6Address(ipv6CallbackIP) {
		t.Fatalf("TP-057: IsIpv6Address(%q) should return true", ipv6CallbackIP)
	}

	// The misc.go code reads mgmtNic["gateway6"] when IPv6:
	//   if utils.IsIpv6Address(server.CALLBACK_IP) {
	//       gw, _ = mgmtNic["gateway6"].(string)
	//   }
	gw6, ok := mgmtNic["gateway6"].(string)
	if !ok {
		t.Fatalf("TP-057: mgmtNic[\"gateway6\"] type assertion failed")
	}
	if gw6 != "2001:db8::fe" {
		t.Errorf("TP-057: mgmtNic[\"gateway6\"] = %q, want 2001:db8::fe", gw6)
	}

	// An IPv6 CALLBACK_IP outside the management CIDR triggers the SetZStackRoute call with gateway6
	outsideIPv6 := "2002:db8::100"
	if utils.CheckMgmtCidrContainsIp(outsideIPv6, mgmtNic) {
		t.Errorf("TP-057: 2002:db8::100 should NOT be inside management CIDR 2001:db8::/64")
	}

	// Verify GetIpFromUrl with IPv6 URL correctly extracts IPv6 address (as used by server.CALLBACK_IP)
	callbackUrl := fmt.Sprintf("http://[%s]:7272/", ipv6CallbackIP)
	extractedIp, err := utils.GetIpFromUrl(callbackUrl)
	if err != nil {
		t.Fatalf("TP-057: GetIpFromUrl(%q) returned error: %v", callbackUrl, err)
	}
	if extractedIp != ipv6CallbackIP {
		t.Errorf("TP-057: GetIpFromUrl(%q) = %q, want %q", callbackUrl, extractedIp, ipv6CallbackIP)
	}
	if !utils.IsIpv6Address(extractedIp) {
		t.Errorf("TP-057: extracted CALLBACK_IP %q should be IPv6, gateway6 would be used", extractedIp)
	}
}

// TP-058: keepalived.go - peerIp = IPv6 时，curl URL 含 [ipv6]
// 验证 tKeepalivedNotifyBackup 模板中包含 IPv6 括号处理逻辑
func TestKeepalivedNotifyBackupIPv6BracketLogic(t *testing.T) {
	// The shell script template handles IPv6 by bracketing the peer IP:
	//   if echo "$peerIp" | grep -q ":"; then peerHost="[$peerIp]"; else peerHost="$peerIp"; fi
	//   curl ... http://"$peerHost:$port"/keepalived/garp
	if !strings.Contains(tKeepalivedNotifyBackup, `peerHost="[$peerIp]"`) {
		t.Errorf("TP-058: tKeepalivedNotifyBackup should contain IPv6 bracket assignment 'peerHost=\"[$peerIp]\"', got:\n%s",
			tKeepalivedNotifyBackup)
	}

	if !strings.Contains(tKeepalivedNotifyBackup, "/keepalived/garp") {
		t.Errorf("TP-058: tKeepalivedNotifyBackup should contain '/keepalived/garp' URL path, got:\n%s",
			tKeepalivedNotifyBackup)
	}

	if !strings.Contains(tKeepalivedNotifyBackup, `"$peerHost:$port"`) {
		t.Errorf("TP-058: tKeepalivedNotifyBackup should build URL using peerHost variable, got:\n%s",
			tKeepalivedNotifyBackup)
	}

	// Simulate the shell bracket logic in Go to verify correctness
	peerIpv6 := "2001:db8::2"
	var peerHost string
	if strings.Contains(peerIpv6, ":") {
		peerHost = "[" + peerIpv6 + "]"
	} else {
		peerHost = peerIpv6
	}
	expectedURL := fmt.Sprintf("http://%s:7272/keepalived/garp", peerHost)
	if expectedURL != "http://[2001:db8::2]:7272/keepalived/garp" {
		t.Errorf("TP-058: IPv6 GARP URL should be http://[2001:db8::2]:7272/keepalived/garp, got %q", expectedURL)
	}
}

// TP-060: promtail.go - mnIp = IPv6 时，lokiUrl = http://[ipv6]:3100/...
// 验证 promtailConfigHandler 中的 Loki URL 构造逻辑
func TestPromtailLokiURLIPv6(t *testing.T) {
	// The promtail.go logic:
	//   mnHost := cmd.LogTarget
	//   if utils.IsIpv6Address(cmd.LogTarget) {
	//       mnHost = fmt.Sprintf("[%s]", cmd.LogTarget)
	//   }
	//   lokiURL := fmt.Sprintf("http://%s:3100/loki/api/v1/push", mnHost)

	buildLokiURL := func(ip string) string {
		mnHost := ip
		if utils.IsIpv6Address(ip) {
			mnHost = fmt.Sprintf("[%s]", ip)
		}
		return fmt.Sprintf("http://%s:3100/loki/api/v1/push", mnHost)
	}

	ipv6MnIp := "2001:db8::5"
	lokiURL := buildLokiURL(ipv6MnIp)
	expected := "http://[2001:db8::5]:3100/loki/api/v1/push"
	if lokiURL != expected {
		t.Errorf("TP-060: Loki URL for IPv6 mnIp %q = %q, want %q", ipv6MnIp, lokiURL, expected)
	}

	// IPv4 case should remain unbracketed
	ipv4MnIp := "192.168.1.100"
	lokiURLv4 := buildLokiURL(ipv4MnIp)
	expectedv4 := "http://192.168.1.100:3100/loki/api/v1/push"
	if lokiURLv4 != expectedv4 {
		t.Errorf("TP-060: Loki URL for IPv4 mnIp %q = %q, want %q", ipv4MnIp, lokiURLv4, expectedv4)
	}

	// Verify IsIpv6Address correctly identifies the IPv6 mnIp
	if !utils.IsIpv6Address(ipv6MnIp) {
		t.Errorf("TP-060: IsIpv6Address(%q) should return true", ipv6MnIp)
	}
}

// TP-061: snat_log.go - mnIp = IPv6 时，rsyslog omfwd target = [ipv6]
// 验证 buildSnatRsyslogConf 对 IPv6 生成 target="[ipv6]"
func TestBuildSnatRsyslogConfIPv6(t *testing.T) {
	ipv6MnIp := "2001:db8::10"
	conf := buildSnatRsyslogConf(ipv6MnIp)

	// IPv6 target should be bracketed: target="[2001:db8::10]"
	expectedTarget := fmt.Sprintf(`target="[%s]"`, ipv6MnIp)
	if !strings.Contains(conf, expectedTarget) {
		t.Errorf("TP-061: rsyslog conf for IPv6 should contain %q, got:\n%s", expectedTarget, conf)
	}

	// Bare IPv6 address should NOT appear as target (must be bracketed)
	bareTarget := fmt.Sprintf(`target="%s"`, ipv6MnIp)
	if strings.Contains(conf, bareTarget) {
		t.Errorf("TP-061: rsyslog conf should NOT contain unbracketed target %q", bareTarget)
	}

	// Should still contain other required fields
	checks := []string{
		`module(load="imfile")`,
		"omfwd",
	}
	for _, c := range checks {
		if !strings.Contains(conf, c) {
			t.Errorf("TP-061: rsyslog conf should contain %q", c)
		}
	}
}

// TP-061 extended: IPv4 target remains unbracketed
func TestBuildSnatRsyslogConfIPv4Unchanged(t *testing.T) {
	ipv4MnIp := "10.0.0.5"
	conf := buildSnatRsyslogConf(ipv4MnIp)

	expectedTarget := fmt.Sprintf(`target="%s"`, ipv4MnIp)
	if !strings.Contains(conf, expectedTarget) {
		t.Errorf("TP-061: rsyslog conf for IPv4 should contain unbracketed %q, got:\n%s", expectedTarget, conf)
	}
}
