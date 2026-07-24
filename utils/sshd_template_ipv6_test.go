package utils

import (
	"bytes"
	"strings"
	"testing"
	"text/template"
)

var sshdTemplateCases = map[string]string{
	"default": sshdTemplate,
	"euler":   sshdTemplateEuler,
	"arm":     sshdTemplateArm,
}

func renderSshdTemplate(t *testing.T, text, listenAddress, listenAddress6 string) string {
	t.Helper()

	data := struct {
		Port                   int
		ListenAddress          string
		ListenAddress6         string
		PasswordAuthentication string
	}{
		Port:                   222,
		ListenAddress:          listenAddress,
		ListenAddress6:         listenAddress6,
		PasswordAuthentication: "no",
	}

	tmpl, err := template.New("sshd").Parse(text)
	if err != nil {
		t.Fatalf("parse sshd template: %v", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		t.Fatalf("render sshd template: %v", err)
	}
	return buf.String()
}

func assertNoWildcardListenAddress(t *testing.T, rendered string) {
	t.Helper()

	if strings.Contains(rendered, "ListenAddress 0.0.0.0") {
		t.Fatalf("ssh template should not contain IPv4 wildcard listen address, got %s", rendered)
	}
	if strings.Contains(rendered, "ListenAddress ::") {
		t.Fatalf("ssh template should not contain IPv6 wildcard listen address, got %s", rendered)
	}
	if strings.Contains(rendered, "ListenAddress [::]") {
		t.Fatalf("ssh template should not contain bracketed IPv6 wildcard listen address, got %s", rendered)
	}
	if strings.Contains(rendered, "\nPort 222\n") {
		t.Fatalf("ssh template should specify the port on each listen address, got %s", rendered)
	}
}

func TestSshdTemplatesRenderIpv4ListenAddressOnly(t *testing.T) {
	for name, text := range sshdTemplateCases {
		rendered := renderSshdTemplate(t, text, "192.168.1.10", "")
		if !strings.Contains(rendered, "ListenAddress 192.168.1.10:222") {
			t.Fatalf("expect %s template to contain IPv4 listen address, got %s", name, rendered)
		}
		if strings.Contains(rendered, "2001:db8::10") {
			t.Fatalf("expect %s template to skip IPv6 listen address, got %s", name, rendered)
		}
		assertNoWildcardListenAddress(t, rendered)
	}
}

func TestSshdTemplatesRenderIpv6ListenAddressOnly(t *testing.T) {
	for name, text := range sshdTemplateCases {
		rendered := renderSshdTemplate(t, text, "", "2001:db8::10")
		if !strings.Contains(rendered, "ListenAddress [2001:db8::10]:222") {
			t.Fatalf("expect %s template to contain IPv6 listen address, got %s", name, rendered)
		}
		if strings.Contains(rendered, "ListenAddress 192.168.1.10") {
			t.Fatalf("expect %s template to skip IPv4 listen address, got %s", name, rendered)
		}
		assertNoWildcardListenAddress(t, rendered)
	}
}

func TestSshdTemplatesRenderDualStackListenAddresses(t *testing.T) {
	for name, text := range sshdTemplateCases {
		rendered := renderSshdTemplate(t, text, "192.168.1.10", "2001:db8::10")
		if !strings.Contains(rendered, "ListenAddress 192.168.1.10:222") {
			t.Fatalf("expect %s template to contain IPv4 listen address, got %s", name, rendered)
		}
		if !strings.Contains(rendered, "ListenAddress [2001:db8::10]:222") {
			t.Fatalf("expect %s template to contain IPv6 listen address, got %s", name, rendered)
		}
		assertNoWildcardListenAddress(t, rendered)
	}
}

func TestSshdSetListenIgnoresInvalidAddress(t *testing.T) {
	sshdInfo := NewSshServer()
	sshdInfo.SetListen("not-an-ip")
	sshdInfo.SetListen("0.0.0.0")
	sshdInfo.SetListen("::")

	if sshdInfo.ListenAddress != "" {
		t.Fatalf("expected IPv4 listen address unchanged, got %s", sshdInfo.ListenAddress)
	}
	if sshdInfo.ListenAddress6 != "" {
		t.Fatalf("expected IPv6 listen address unchanged, got %s", sshdInfo.ListenAddress6)
	}
}

func TestSshdNormalizeListenAddressesDropsWildcardValues(t *testing.T) {
	sshdInfo := &SshdInfo{
		ListenAddress:  "0.0.0.0",
		ListenAddress6: "::",
	}

	sshdInfo.normalizeListenAddresses()

	if sshdInfo.ListenAddress != "" {
		t.Fatalf("expected IPv4 wildcard listen address removed, got %s", sshdInfo.ListenAddress)
	}
	if sshdInfo.ListenAddress6 != "" {
		t.Fatalf("expected IPv6 wildcard listen address removed, got %s", sshdInfo.ListenAddress6)
	}
}

func TestSshdSetListenSeparatesIpv4AndIpv6(t *testing.T) {
	sshdInfo := NewSshServer()
	sshdInfo.SetListen("192.168.1.10")
	sshdInfo.SetListen("2001:db8::10")

	if sshdInfo.ListenAddress != "192.168.1.10" {
		t.Fatalf("expected IPv4 listen address set, got %s", sshdInfo.ListenAddress)
	}
	if sshdInfo.ListenAddress6 != "2001:db8::10" {
		t.Fatalf("expected IPv6 listen address set, got %s", sshdInfo.ListenAddress6)
	}
}
