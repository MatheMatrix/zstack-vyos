package utils

import (
	"bytes"
	"strings"
	"testing"
	"text/template"
)

const (
	expectedSshdIpv4ListenAddress = "ListenAddress 0.0.0.0"
	expectedSshdIpv6ListenAddress = "ListenAddress ::"
)

func TestSshdTemplatesRenderDualStackListenAddresses(t *testing.T) {
	cases := map[string]string{
		"default": sshdTemplate,
		"euler":   sshdTemplateEuler,
		"arm":     sshdTemplateArm,
	}

	data := struct {
		Port                   int
		ListenAddress          string
		ListenAddress6         string
		PasswordAuthentication string
	}{
		Port:                   22,
		ListenAddress:          "0.0.0.0",
		ListenAddress6:         "::",
		PasswordAuthentication: "no",
	}

	for name, text := range cases {
		tmpl, err := template.New("sshd").Parse(text)
		if err != nil {
			t.Fatalf("parse %s template: %v", name, err)
		}

		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, data); err != nil {
			t.Fatalf("render %s template: %v", name, err)
		}

		rendered := buf.String()
		if !strings.Contains(rendered, expectedSshdIpv4ListenAddress) {
			t.Fatalf("expect %s template to contain %s, got %s", name, expectedSshdIpv4ListenAddress, rendered)
		}
		if !strings.Contains(rendered, expectedSshdIpv6ListenAddress) {
			t.Fatalf("expect %s template to contain %s, got %s", name, expectedSshdIpv6ListenAddress, rendered)
		}
	}
}

func TestEulerSshdTemplateAcceptsLegacyJschRsaAuth(t *testing.T) {
	expectedLines := []string{
		"HostKeyAlgorithms +ssh-rsa",
		"PubkeyAcceptedAlgorithms +ssh-rsa",
		"PubkeyAcceptedKeyTypes +ssh-rsa",
	}

	for _, expected := range expectedLines {
		if !strings.Contains(sshdTemplateEuler, expected) {
			t.Fatalf("expect euler sshd template to contain %s", expected)
		}
	}
}

func TestSshdSetListenIgnoresInvalidAddress(t *testing.T) {
	sshdInfo := NewSshServer()
	sshdInfo.SetListen("not-an-ip")

	if sshdInfo.ListenAddress != "0.0.0.0" {
		t.Fatalf("expected IPv4 listen address unchanged, got %s", sshdInfo.ListenAddress)
	}
	if sshdInfo.ListenAddress6 != "::" {
		t.Fatalf("expected IPv6 listen address unchanged, got %s", sshdInfo.ListenAddress6)
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
