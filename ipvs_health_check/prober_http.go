package main

import (
	"context"

	log "github.com/sirupsen/logrus"
)

// httpProber is a placeholder for the HTTP / HTTPS application-layer probe
// described in spec F-008.  PH-2 will land the real implementation
// (configurable method / path / expected status codes / header set / TLS
// SNI / etc.) — until then a configuration that asks for an http probe is a
// configuration error and the backend is reported DOWN so that operators
// notice early instead of routing traffic into an un-checked path.
type httpProber struct {
	target ProbeTarget
}

func (p *httpProber) Probe(ctx context.Context) bool {
	log.Warnf("[http prober] HTTP/HTTPS health check not implemented yet "+
		"(spec F-008, PH-2); reporting backend %s:%d as DOWN",
		p.target.BackendIp, p.target.HealthCheckPort)
	return false
}
