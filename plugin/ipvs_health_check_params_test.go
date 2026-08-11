package plugin

import "testing"

func TestHaproxyHTTPCheckExpectedStatus(t *testing.T) {
	tests := []struct {
		name     string
		classes  string
		expected string
	}{
		{name: "single", classes: "http_2xx", expected: "^2"},
		{name: "multiple", classes: "http_3xx,http_2xx", expected: "^[23]"},
		{name: "duplicate", classes: "http_2xx,http_2xx", expected: "^2"},
		{name: "invalid falls back to default", classes: "unknown", expected: "^2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if actual := haproxyHttpCheckExpectedStatus(tt.classes); actual != tt.expected {
				t.Fatalf("expected status = %q, want %q", actual, tt.expected)
			}
		})
	}
}

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

func TestParseLbParamsForIPVSHTTPHealthCheck(t *testing.T) {
	params := ParseLbParams(LbInfo{
		Parameters: []string{
			"healthCheckTarget::https:8443",
			"healthCheckParameter::HEAD:/health:http_2xx,http_3xx",
			"healthCheckInterval::5",
			"healthCheckTimeout::2",
			"healthyThreshold::2",
			"unhealthyThreshold::3",
		},
	})

	if params.healthCheckProtocl != "https" {
		t.Fatalf("health check protocol = %q, want https", params.healthCheckProtocl)
	}
	if params.healthCheckPort != 8443 {
		t.Fatalf("health check port = %d, want 8443", params.healthCheckPort)
	}
	if params.healthCheckMethod != "HEAD" {
		t.Fatalf("health check method = %q, want HEAD", params.healthCheckMethod)
	}
	if params.healthCheckURI != "/health" {
		t.Fatalf("health check URI = %q, want /health", params.healthCheckURI)
	}
	if params.healthCheckExpectedCodeClasses != "http_2xx,http_3xx" {
		t.Fatalf("expected code classes = %q, want http_2xx,http_3xx",
			params.healthCheckExpectedCodeClasses)
	}
	if params.healthCheckInterval != 5 || params.healthCheckTimeout != 2 {
		t.Fatalf("interval/timeout = %d/%d, want 5/2",
			params.healthCheckInterval, params.healthCheckTimeout)
	}
	if params.healthyThreshold != 2 || params.unhealthyThreshold != 3 {
		t.Fatalf("healthy/unhealthy threshold = %d/%d, want 2/3",
			params.healthyThreshold, params.unhealthyThreshold)
	}
}

func TestParseLbParamsUsesHTTPHealthCheckDefaults(t *testing.T) {
	params := ParseLbParams(LbInfo{
		Parameters: []string{
			"healthCheckTarget::http:default",
		},
	})

	if params.healthCheckPort != 0 {
		t.Fatalf("default health check port = %d, want 0", params.healthCheckPort)
	}
	if params.healthCheckMethod != "HEAD" {
		t.Fatalf("default health check method = %q, want HEAD", params.healthCheckMethod)
	}
	if params.healthCheckURI != "/" {
		t.Fatalf("default health check URI = %q, want /", params.healthCheckURI)
	}
	if params.healthCheckExpectedCodeClasses != "http_2xx" {
		t.Fatalf("default expected code classes = %q, want http_2xx",
			params.healthCheckExpectedCodeClasses)
	}
}

func TestParseLbParamsIgnoresMalformedHealthCheckParameters(t *testing.T) {
	params := ParseLbParams(LbInfo{
		Parameters: []string{
			"healthCheckTarget::https",
			"healthCheckParameter::HEAD:/health",
		},
	})

	if params.healthCheckProtocl != "" || params.healthCheckPort != 0 {
		t.Fatalf("malformed health check target should be ignored: %+v", params)
	}
	if params.healthCheckMethod != "HEAD" ||
		params.healthCheckURI != "/" ||
		params.healthCheckExpectedCodeClasses != "http_2xx" {
		t.Fatalf("malformed HTTP parameters should preserve defaults: %+v", params)
	}
}

func TestIPVSHealthCheckConfigCarriesHTTPParameters(t *testing.T) {
	info := LbInfo{
		LbUuid:           "lb-uuid",
		ListenerUuid:     "listener-uuid",
		Vip:              "192.0.2.10",
		InstancePort:     8080,
		LoadBalancerPort: 80,
		Mode:             "udp",
		Parameters: []string{
			"healthCheckTarget::https:8443",
			"healthCheckParameter::GET:/ready:http_2xx,http_3xx",
			"healthCheckInterval::5",
			"healthCheckTimeout::2",
			"healthyThreshold::2",
			"unhealthyThreshold::3",
		},
	}
	params := ParseLbParams(info)
	frontService := NewIpvsFrontService(
		info,
		params,
		info.Vip,
		map[string]*IpvsBackendServer{},
	)
	backend := NewIpvsBackendServer("192.0.2.20", "8080", "1", frontService)
	frontService.BackendServers[backend.GetBackendKey()] = backend

	conf := &IpvsConf{
		Services: map[string]*IpvsFrontendService{
			frontService.getFrontendServiceKey(): frontService,
		},
	}
	healthCheckConf := (&IpvsHealthCheckConf{}).FromIpvsConf(conf)

	if len(healthCheckConf.Services) != 1 ||
		len(healthCheckConf.Services[0].BackendServers) != 1 {
		t.Fatalf("unexpected health check config: %+v", healthCheckConf)
	}
	checker := healthCheckConf.Services[0].BackendServers[0]
	if checker.HealthCheckProtocol != "https" ||
		checker.HealthCheckPort != 8443 ||
		checker.HealthCheckMethod != "GET" ||
		checker.HealthCheckURI != "/ready" ||
		checker.HealthCheckExpectedCodeClasses != "http_2xx,http_3xx" {
		t.Fatalf("HTTP health check parameters were not preserved: %+v", checker)
	}
}

func TestIPVSHealthCheckCopyParamsCopiesHTTPParameters(t *testing.T) {
	current := IpvsHealthCheckBackendServer{}
	updated := IpvsHealthCheckBackendServer{
		HealthCheckProtocol:            "https",
		HealthCheckPort:                8443,
		HealthCheckInterval:            5,
		HealthCheckTimeout:             2,
		HealthCheckMethod:              "GET",
		HealthCheckURI:                 "/ready",
		HealthCheckExpectedCodeClasses: "http_2xx,http_3xx",
		HealthyThreshold:               2,
		UnhealthyThreshold:             3,
	}

	current.CopyParamsFrom(&updated)

	if current.HealthCheckProtocol != updated.HealthCheckProtocol ||
		current.HealthCheckPort != updated.HealthCheckPort ||
		current.HealthCheckInterval != updated.HealthCheckInterval ||
		current.HealthCheckTimeout != updated.HealthCheckTimeout ||
		current.HealthCheckMethod != updated.HealthCheckMethod ||
		current.HealthCheckURI != updated.HealthCheckURI ||
		current.HealthCheckExpectedCodeClasses != updated.HealthCheckExpectedCodeClasses ||
		current.HealthyThreshold != updated.HealthyThreshold ||
		current.UnhealthyThreshold != updated.UnhealthyThreshold {
		t.Fatalf("health check parameters were not copied: %+v", current)
	}
}
