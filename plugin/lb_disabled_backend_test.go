package plugin

import "testing"

func TestParseListenerParameterExcludesDisabledBackendsFromGobetween(t *testing.T) {
	params, err := parseListenerPrameter(LbInfo{
		LbUuid:          "lb-uuid",
		ListenerUuid:    "listener-uuid",
		InstancePort:    8080,
		CertificateUuid: "certificate-uuid",
		Parameters: []string{
			"balancerWeight::192.0.2.10::20",
			"balancerWeight::192.0.2.11::30",
		},
		ServerGroups: []ServerGroupInfo{{
			BackendServers: []BackendServerInfo{
				{Ip: "192.0.2.10", Weight: 20},
				{Ip: "192.0.2.11", Weight: 30, Disabled: true},
			},
		}},
	})
	if err != nil {
		t.Fatalf("parse listener parameter: %v", err)
	}

	nicIps := params["NicIps"].([]string)
	if len(nicIps) != 1 || nicIps[0] != "192.0.2.10" {
		t.Fatalf("active nic IPs = %v, want [192.0.2.10]", nicIps)
	}
	weights := params["Weight"].(map[string]string)
	if len(weights) != 1 || weights["192.0.2.10"] != "20" {
		t.Fatalf("active weights = %v, want only 192.0.2.10=20", weights)
	}
}
