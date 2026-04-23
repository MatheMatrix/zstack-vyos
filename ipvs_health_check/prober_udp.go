package main

import (
	"context"
	"fmt"
	"net"
	"time"

	log "github.com/sirupsen/logrus"
)

// udpProber implements Prober for HealthCheckProtocol == "udp".
//
// Migrated from the former ipvs_health_check_udp.go.  The legacy ICMP-ping
// fallback has been removed (see spec F-018 / D-018): a host that responds to
// ping but whose UDP service is dead must report DOWN, otherwise IPVS keeps
// black-holing traffic.
type udpProber struct {
	target ProbeTarget
}

func (p *udpProber) Probe(ctx context.Context) bool {
	t := p.target
	addr := t.BackendIp
	if ip := net.ParseIP(t.BackendIp); ip != nil && ip.To4() == nil {
		addr = fmt.Sprintf("[%s]", addr)
	}

	timeout := time.Duration(t.HealthCheckTimeout) * time.Second
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "udp",
		fmt.Sprintf("%s:%d", addr, t.HealthCheckPort))
	if err != nil {
		log.Debugf("[udp prober] dial udp %s:%d failed: %v", addr, t.HealthCheckPort, err)
		return false
	}
	defer conn.Close()

	message := []byte("zstack ipvs health check from" + t.FrontPort + "" + t.FrontPort)
	if _, err = conn.Write(message); err != nil {
		log.Debugf("[udp prober] send to %s:%d failed: %v", t.BackendIp, t.HealthCheckPort, err)
		return false
	}

	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	conn.SetReadDeadline(deadline)

	buffer := make([]byte, 4)
	if _, err = conn.Read(buffer); err != nil {
		log.Debugf("[udp prober] recv from %s:%d failed: %v", t.BackendIp, t.HealthCheckPort, err)
		return false
	}
	log.Debugf("[udp prober] recv from %s:%d, result:%s", t.BackendIp, t.HealthCheckPort, buffer)
	return true
}
