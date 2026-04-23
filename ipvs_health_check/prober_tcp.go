package main

import (
	"context"
	"fmt"
	"net"
	"time"

	log "github.com/sirupsen/logrus"
)

// tcpProber implements Prober for HealthCheckProtocol == "tcp".
//
// F-015 ships a working baseline (TCP three-way-handshake probe) so that
// PH-0b's introduction of TCP IPVS listeners has a usable healthcheck
// out of the box.  PH-1 F-011 will extend this with retries, source-port
// pinning and structured failure metrics.
//
// Detection model: a successful TCP connect (SYN / SYN-ACK / ACK) is taken
// as proof the backend's listener is accepting connections.  We do NOT send
// payload bytes — application-layer probes belong in httpProber.
type tcpProber struct {
	target ProbeTarget
}

func (p *tcpProber) Probe(ctx context.Context) bool {
	t := p.target
	addr := t.BackendIp
	if ip := net.ParseIP(t.BackendIp); ip != nil && ip.To4() == nil {
		addr = fmt.Sprintf("[%s]", addr)
	}

	timeout := time.Duration(t.HealthCheckTimeout) * time.Second
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp",
		fmt.Sprintf("%s:%d", addr, t.HealthCheckPort))
	if err != nil {
		log.Debugf("[tcp prober] dial tcp %s:%d failed: %v", addr, t.HealthCheckPort, err)
		return false
	}
	// Best-effort graceful close: don't linger and don't issue RST on healthy
	// backends — those would pollute the listener's accept queue with spurious
	// half-open connections.
	_ = conn.Close()
	return true
}
