package plugin

import (
	"strings"
	"testing"

	"zstack-vyos/utils"
)

func TestGetSnatLogTargetMnIp(t *testing.T) {
	original := utils.BootstrapInfo
	defer func() {
		utils.BootstrapInfo = original
	}()

	utils.BootstrapInfo = map[string]interface{}{
		"managementNodeIp": "172.25.116.181",
	}

	ip := getSnatLogTargetMnIp()
	if ip != "172.25.116.181" {
		t.Fatalf("expect managementNodeIp to be preferred, got %s", ip)
	}

	utils.BootstrapInfo = map[string]interface{}{
		"managementPeerNodeIp": "172.25.116.182",
		"managementNodeIp":     "",
	}

	ip = getSnatLogTargetMnIp()
	if ip != "172.25.116.182" {
		t.Fatalf("expect fallback to peer ip, got %s", ip)
	}
}

func TestBuildSnatRsyslogConf(t *testing.T) {
	conf := buildSnatRsyslogConf("10.0.0.10")

	checks := []string{
		"module(load=\"imfile\")",
		"File=\"/var/log/snat_conntrack.log\"",
		"target=\"10.0.0.10\"",
		"port=\"15514\"",
	}

	for _, c := range checks {
		if !strings.Contains(conf, c) {
			t.Fatalf("expect conf contains %s", c)
		}
	}
}

func TestBuildSnatLogRuntimeEnv(t *testing.T) {
	content := buildSnatLogRuntimeEnv(snatLogRuntimeConfig{
		VpcUUID:      "vpc-uuid-1",
		VpcDefaultIP: "10.0.0.10",
		MnIP:         "172.25.116.181",
		MnPeerIP:     "172.25.116.182",
		MgmtIP:       "192.168.100.10",
	})

	checks := []string{
		"VPC_UUID=vpc-uuid-1",
		"VPC_DEFAULT_IP=10.0.0.10",
		"MN_IP=172.25.116.181",
		"MN_PEER_IP=172.25.116.182",
		"MGMT_IP=192.168.100.10",
	}

	for _, c := range checks {
		if !strings.Contains(content, c) {
			t.Fatalf("expect runtime env contains %s", c)
		}
	}
}

func TestGetVpcDefaultPublicIpFromAdditionalNic(t *testing.T) {
	original := utils.BootstrapInfo
	defer func() {
		utils.BootstrapInfo = original
	}()

	utils.BootstrapInfo = map[string]interface{}{
		"managementNic": map[string]interface{}{
			"category":       "Public",
			"ip":             "192.168.100.10",
			"isDefaultRoute": false,
		},
		"additionalNics": []interface{}{
			map[string]interface{}{
				"category":       "Public",
				"ip":             "10.86.0.200",
				"isDefaultRoute": true,
			},
			map[string]interface{}{
				"category":       "Private",
				"ip":             "10.0.0.10",
				"isDefaultRoute": false,
			},
		},
	}

	if ip := getVpcDefaultPublicIp(); ip != "10.86.0.200" {
		t.Fatalf("expect default public ip from additional nic, got %s", ip)
	}
}

func TestGetVpcDefaultPublicIpFromManagementNic(t *testing.T) {
	original := utils.BootstrapInfo
	defer func() {
		utils.BootstrapInfo = original
	}()

	utils.BootstrapInfo = map[string]interface{}{
		"managementNic": map[string]interface{}{
			"category":       "Public",
			"ip":             "172.26.30.19",
			"isDefaultRoute": true,
		},
		"additionalNics": []interface{}{},
	}

	if ip := getVpcDefaultPublicIp(); ip != "172.26.30.19" {
		t.Fatalf("expect default public ip from management nic, got %s", ip)
	}
}
