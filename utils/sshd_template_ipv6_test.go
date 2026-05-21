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
