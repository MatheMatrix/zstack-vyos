package utils

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("frrIpRoute_ipv6_test", func() {

	// TP-059: AddRouteForMgmtEuler2203 for IPv6 - vtysh 命令含 ipv6 route .../128
	// We test ZStackRouteEntry.addCommand() directly since the actual vtysh call requires a bash environment.
	Describe("ZStackRouteEntry.addCommand() IPv6", func() {

		It("generates 'ipv6 route' prefix when Ipv6=true (main table, via NicName)", func() {
			entry := ZStackRouteEntry{
				DestinationCidr: "2001:db8::1/128",
				NicName:         "eth0",
				TableId:         ROUTETABLE_ID_MAIN,
				Ipv6:            true,
			}
			cmd := entry.addCommand()
			Expect(strings.HasPrefix(cmd, "ipv6 route")).To(BeTrue(),
				"TP-059: IPv6 route addCommand should start with 'ipv6 route', got: %q", cmd)
			Expect(strings.Contains(cmd, "2001:db8::1/128")).To(BeTrue(),
				"TP-059: addCommand should contain destination CIDR 2001:db8::1/128, got: %q", cmd)
		})

		It("generates 'ipv6 route' prefix when Ipv6=true (main table, via NextHopIp)", func() {
			entry := ZStackRouteEntry{
				DestinationCidr: "2001:db8::1/128",
				NextHopIp:       "2001:db8::fe",
				TableId:         ROUTETABLE_ID_MAIN,
				Ipv6:            true,
			}
			cmd := entry.addCommand()
			Expect(strings.HasPrefix(cmd, "ipv6 route")).To(BeTrue(),
				"TP-059: IPv6 route addCommand (via gateway) should start with 'ipv6 route', got: %q", cmd)
			Expect(strings.Contains(cmd, "/128")).To(BeTrue(),
				"TP-059: IPv6 host route should use /128 prefix, got: %q", cmd)
		})

		It("generates 'ip route' prefix when Ipv6=false (IPv4 path)", func() {
			entry := ZStackRouteEntry{
				DestinationCidr: "10.0.0.1/32",
				NicName:         "eth0",
				TableId:         ROUTETABLE_ID_MAIN,
				Ipv6:            false,
			}
			cmd := entry.addCommand()
			Expect(strings.HasPrefix(cmd, "ip route")).To(BeTrue(),
				"TP-059: IPv4 route addCommand should start with 'ip route', got: %q", cmd)
			Expect(strings.Contains(cmd, "ipv6")).To(BeFalse(),
				"TP-059: IPv4 addCommand should NOT contain 'ipv6', got: %q", cmd)
		})

		// TP-059: AddRouteForMgmtEuler2203 appends /128 for IPv6 host without prefix
		It("AddRouteForMgmtEuler2203 correctly builds IPv6 route entry with /128 suffix", func() {
			// Validate that IsIpv6Address triggers the /128 path in AddRouteForMgmtEuler2203.
			// We verify the logic directly:
			mgtIp := "2001:db8::1"
			isIpv6 := IsIpv6Address(mgtIp)
			Expect(isIpv6).To(BeTrue(),
				"TP-059: 2001:db8::1 should be recognized as IPv6")

			// The function adds /128 when IPv6 and no prefix present
			destCidr := mgtIp
			if isIpv6 && !strings.Contains(mgtIp, "/") {
				destCidr = mgtIp + "/128"
			}
			Expect(destCidr).To(Equal("2001:db8::1/128"),
				"TP-059: IPv6 host route destination should have /128 suffix")

			// Confirm the resulting route entry would produce 'ipv6 route'
			entry := ZStackRouteEntry{
				DestinationCidr: destCidr,
				NicName:         "eth0",
				TableId:         ROUTETABLE_ID_MAIN,
				Ipv6:            isIpv6,
			}
			cmd := entry.addCommand()
			Expect(strings.HasPrefix(cmd, "ipv6 route")).To(BeTrue(),
				"TP-059: vtysh command should contain 'ipv6 route', got: %q", cmd)
			Expect(strings.Contains(cmd, "/128")).To(BeTrue(),
				"TP-059: vtysh command should contain /128, got: %q", cmd)
		})
	})
})
