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
})
