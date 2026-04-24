package utils

import (
	"bytes"
	"strings"
	"text/template"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("sshd_ipv6_test", func() {

	// TP-053: sshd 配置模板包含 ListenAddress [::]:port，支持 IPv6 监听
	Describe("sshd template IPv6 ListenAddress", func() {

		It("sshdTemplate contains IPv6 ListenAddress directive", func() {
			Expect(strings.Contains(sshdTemplate, "ListenAddress [::]:{{.Port}}")).To(BeTrue(),
				"TP-053: sshdTemplate should contain 'ListenAddress [::]:{{.Port}}'")
		})

		It("sshdTemplateEuler contains IPv6 ListenAddress directive", func() {
			Expect(strings.Contains(sshdTemplateEuler, "ListenAddress [::]:{{.Port}}")).To(BeTrue(),
				"TP-053: sshdTemplateEuler should contain 'ListenAddress [::]:{{.Port}}'")
		})

		It("sshdTemplateArm contains IPv6 ListenAddress directive", func() {
			Expect(strings.Contains(sshdTemplateArm, "ListenAddress [::]:{{.Port}}")).To(BeTrue(),
				"TP-053: sshdTemplateArm should contain 'ListenAddress [::]:{{.Port}}'")
		})

		It("sshdTemplateEuler renders correctly with IPv6 ListenAddress on port 22", func() {
			tmpl, err := template.New("sshd").Parse(sshdTemplateEuler)
			Expect(err).To(BeNil(), "TP-053: sshdTemplateEuler should parse without error")

			data := &SshdInfo{
				Port:                   22,
				ListenAddress:          "0.0.0.0",
				PasswordAuthentication: "no",
			}

			var buf bytes.Buffer
			err = tmpl.Execute(&buf, data)
			Expect(err).To(BeNil(), "TP-053: template execution should not fail")

			rendered := buf.String()
			Expect(strings.Contains(rendered, "ListenAddress [::]:22")).To(BeTrue(),
				"TP-053: rendered euler sshd config should contain 'ListenAddress [::]:22', got:\n%s", rendered)
			Expect(strings.Contains(rendered, "ListenAddress 0.0.0.0:22")).To(BeTrue(),
				"TP-053: rendered sshd config should also contain IPv4 ListenAddress")
		})

		It("sshdTemplate renders correctly with IPv6 ListenAddress on custom port", func() {
			tmpl, err := template.New("sshd").Parse(sshdTemplate)
			Expect(err).To(BeNil(), "TP-053: sshdTemplate should parse without error")

			data := &SshdInfo{
				Port:                   2222,
				ListenAddress:          "0.0.0.0",
				PasswordAuthentication: "no",
			}

			var buf bytes.Buffer
			err = tmpl.Execute(&buf, data)
			Expect(err).To(BeNil(), "TP-053: template execution should not fail")

			rendered := buf.String()
			Expect(strings.Contains(rendered, "ListenAddress [::]:2222")).To(BeTrue(),
				"TP-053: rendered sshd config should contain 'ListenAddress [::]:2222' for port 2222, got:\n%s", rendered)
		})
	})
})
