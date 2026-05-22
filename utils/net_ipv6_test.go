package utils

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("net ipv6", func() {
	It("gets IPv6 host from bracketed URL", func() {
		ip, err := GetIpFromUrl("http://[2001:db8::1]:7272/test")
		Expect(err).To(BeNil())
		Expect(ip).To(Equal("2001:db8::1"))
	})

	It("keeps IPv4 and hostname URL behavior", func() {
		ip, err := GetIpFromUrl("http://192.168.1.10:7272/test")
		Expect(err).To(BeNil())
		Expect(ip).To(Equal("192.168.1.10"))

		ip, err = GetIpFromUrl("http://zvr.example.com:7272/test")
		Expect(err).To(BeNil())
		Expect(ip).To(Equal("zvr.example.com"))
	})

	It("checks management CIDR with matching address family", func() {
		mgmtNic := map[string]interface{}{
			"ip":           "192.168.1.10",
			"netmask":      "255.255.255.0",
			"gateway":      "192.168.1.1",
			"ip6":          "2001:db8::10",
			"prefixLength": float64(64),
			"gateway6":     "2001:db8::1",
		}

		Expect(CheckMgmtCidrContainsIp("192.168.1.20", mgmtNic)).To(BeTrue())
		Expect(CheckMgmtCidrContainsIp("2001:db8::20", mgmtNic)).To(BeTrue())
		Expect(CheckMgmtCidrContainsIp("2001:db9::20", mgmtNic)).To(BeFalse())
		Expect(GetMgmtGatewayForIp("192.168.1.20", mgmtNic)).To(Equal("192.168.1.1"))
		Expect(GetMgmtGatewayForIp("2001:db8::20", mgmtNic)).To(Equal("2001:db8::1"))
	})
})
