package plugintest

import (
	. "github.com/onsi/ginkgo/v2"
)

var _ = Describe("ipvs test", func() {
	Context("slbha ipvs test", func() {
		env := NewSlbHaIp6Env()
		It("ipvs: test prepare env", func() {
			env.SetupSlbHa6BootStrap()
			env.SetupVyosHa6()
		})

	})
})
