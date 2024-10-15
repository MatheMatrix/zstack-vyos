package plugintest

import (
	. "github.com/onsi/ginkgo/v2"
	"zstack-vyos/plugin"
)

var _ = Describe("udp slb test", func() {
	Context("slbha ipvs test", func() {
		env := NewSlbHaEnv()
		It("ipvs :test prepare env", func() {
			env.SetupSlbHaBootStrap()
			env.SetupLb()
			env.SetupVyosHa()
		})

		It("UDP_LB:", func() {
			cmd := plugin.RefreshLbCmd{
				Lbs:              []plugin.LbInfo{env.lb},
				EnableHaproxyLog: true,
			}
			plugin.RefreshLbInternal(&cmd)
		})

		It("UDP_LB: test destroy env", func() {
			env.DestroySlbHaBootStrap()
			env.DestroyLb()
		})
	})
})
