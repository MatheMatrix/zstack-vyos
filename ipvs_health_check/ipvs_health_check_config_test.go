package main

import (
	"net/http"
	"testing"

	"zstack-vyos/plugin"
)

func TestIPVSHealthCheckEqualIncludesProbeParameters(t *testing.T) {
	base := IpvsHealthCheckBackendServer{
		IpvsHealthCheckBackendServer: plugin.IpvsHealthCheckBackendServer{
			ConnectionType:                 "nat",
			ProtocolType:                   "udp",
			Scheduler:                      "rr",
			FrontIp:                        "192.0.2.10",
			FrontPort:                      "443",
			Weight:                         "1",
			BackendIp:                      "192.0.2.20",
			BackendPort:                    "8443",
			HealthCheckProtocol:            "https",
			HealthCheckPort:                9443,
			HealthCheckInterval:            5,
			HealthCheckTimeout:             2,
			HealthCheckMethod:              http.MethodHead,
			HealthCheckURI:                 "/health",
			HealthCheckExpectedCodeClasses: "http_2xx",
			HealthyThreshold:               2,
			UnhealthyThreshold:             3,
			MaxConnection:                  2000000,
			MinConnection:                  0,
		},
	}

	tests := []struct {
		name   string
		mutate func(*IpvsHealthCheckBackendServer)
	}{
		{name: "interval", mutate: func(checker *IpvsHealthCheckBackendServer) { checker.HealthCheckInterval++ }},
		{name: "timeout", mutate: func(checker *IpvsHealthCheckBackendServer) { checker.HealthCheckTimeout++ }},
		{name: "method", mutate: func(checker *IpvsHealthCheckBackendServer) { checker.HealthCheckMethod = http.MethodGet }},
		{name: "URI", mutate: func(checker *IpvsHealthCheckBackendServer) { checker.HealthCheckURI = "/ready" }},
		{name: "expected codes", mutate: func(checker *IpvsHealthCheckBackendServer) {
			checker.HealthCheckExpectedCodeClasses = "http_2xx,http_3xx"
		}},
		{name: "healthy threshold", mutate: func(checker *IpvsHealthCheckBackendServer) { checker.HealthyThreshold++ }},
		{name: "unhealthy threshold", mutate: func(checker *IpvsHealthCheckBackendServer) { checker.UnhealthyThreshold++ }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			other := base
			test.mutate(&other)
			if base.equal(&other) {
				t.Fatalf("checker with changed %s must not compare equal", test.name)
			}
		})
	}
}
