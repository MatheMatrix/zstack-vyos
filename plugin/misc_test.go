package plugin

import (
	. "github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
	"github.com/zstackio/zstack-vyos/server"
	"github.com/zstackio/zstack-vyos/utils"
)

var _ = Describe("misc_test", func() {
	var nicCmd *configureNicCmd
	BeforeEach(func() {
		nicCmd = &configureNicCmd{}
		utils.InitLog(utils.VYOS_UT_LOG_FOLDER+"misc_test.log", false)
	})

	AfterEach(func() {
		removeNic(nicCmd)
	})

	It("test add callback route", func() {
		nicCmd := &configureNicCmd{}
		nicCmd.Nics = append(nicCmd.Nics, utils.MgtNicForUT)
		nicCmd.Nics = append(nicCmd.Nics, utils.PubNicForUT)
		SetKeepalivedStatusForUt(KeepAlivedStatus_Master)
		configureNic(nicCmd)

		ipInPubL3, _ := utils.GetFreePubL3Ip()
		defer utils.ReleasePubL3Ip(ipInPubL3)

		server.CALLBACK_IP = ipInPubL3
		addRouteIfCallbackIpChanged(true)
		gomega.Expect(utils.CheckZStackRouteExists(server.CALLBACK_IP)).To(gomega.BeTrue(),
			"failed to add the callback route for the first time.")

		utils.DeleteRouteIfExists(server.CALLBACK_IP)
		addRouteIfCallbackIpChanged(true)

		gomega.Expect(utils.CheckZStackRouteExists(server.CALLBACK_IP)).To(gomega.BeTrue(),
			"failed to add the callback route for the second time.")

		utils.DeleteRouteIfExists(server.CALLBACK_IP)
		addRouteIfCallbackIpChanged(false)
		gomega.Expect(utils.CheckZStackRouteExists(server.CALLBACK_IP)).To(gomega.BeFalse(),
			"route should not be added this time.")
	})
})
