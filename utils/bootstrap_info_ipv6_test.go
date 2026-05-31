package utils

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("bootstrap info ipv6", func() {
	It("returns IPv4 and IPv6 management node CIDRs independently", func() {
		oldBootstrapInfo := BootstrapInfo
		defer func() {
			BootstrapInfo = oldBootstrapInfo
		}()

		BootstrapInfo = map[string]interface{}{
			BootstrapParamManagementNodeCidr:    "192.168.1.0/24",
			BootstrapParamManagementNodeIp6Cidr: "2001:db8::/64",
		}

		Expect(GetManagementNodeCidrs()).To(Equal([]string{"192.168.1.0/24", "2001:db8::/64"}))
	})

	It("checks IPv6-only management CIDR without IPv4 netmask", func() {
		oldBootstrapInfo := BootstrapInfo
		defer func() {
			BootstrapInfo = oldBootstrapInfo
		}()

		BootstrapInfo = map[string]interface{}{
			"managementNic": map[string]interface{}{
				"ip6":          "2001:db8::10",
				"prefixLength": float64(64),
			},
		}

		Expect(IsInManagementCidr("2001:db8::20")).To(BeTrue())
		Expect(IsInManagementCidr("2001:db9::20")).To(BeFalse())
		Expect(IsInManagementCidr("192.168.1.20")).To(BeFalse())
	})

	It("keeps IPv6-only management NIC in bootstrap NIC inventory", func() {
		oldBootstrapInfo := BootstrapInfo
		defer func() {
			BootstrapInfo = oldBootstrapInfo
		}()

		BootstrapInfo = map[string]interface{}{
			"managementNic": map[string]interface{}{
				"deviceName": "eth0",
				"mac":        "fa:16:3e:00:00:01",
				"category":   "Public",
				"ip6":        "2001:db8::10",
			},
			"additionalNics": []interface{}{},
		}

		nics := GetBootStrapNicInfo()
		Expect(nics).To(HaveKey("eth0"))
		Expect(nics["eth0"].Ip).To(BeEmpty())
		Expect(nics["eth0"].Ip6).To(Equal("2001:db8::10"))
	})
})
