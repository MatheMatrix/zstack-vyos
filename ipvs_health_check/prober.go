package main

import (
	"context"
)

// ProbeTarget carries everything a Prober needs to perform a single health
// check.  It is intentionally minimal and decoupled from
// IpvsHealthCheckBackendServer so prober implementations can be unit-tested
// without spinning up the full daemon state machine.
type ProbeTarget struct {
	BackendIp           string
	HealthCheckPort     int
	HealthCheckTimeout  int    // seconds
	HealthCheckProtocol string // "udp" / "tcp" / "http" — lowercase
	FrontPort           string // used by udp probe payload only
}

// Prober is the strategy interface picked per HealthCheckProtocol.
// Implementations MUST be context-aware: a Probe call woken via ctx.Done()
// must abandon any in-flight I/O and return false promptly.
type Prober interface {
	Probe(ctx context.Context) bool
}

// NewProber returns the Prober matching the requested protocol or nil if the
// protocol is unknown.  Callers should treat a nil Prober as a permanent
// failure for that backend rather than silently passing the health check.
//
// F-015 only ships the udp prober; tcp/http are skeletons populated by F-011
// and F-008 in PH-1 / PH-2 respectively.
func NewProber(t ProbeTarget) Prober {
	switch t.HealthCheckProtocol {
	case "udp":
		return &udpProber{target: t}
	case "tcp":
		return &tcpProber{target: t}
	case "http", "https":
		return &httpProber{target: t}
	}
	return nil
}
