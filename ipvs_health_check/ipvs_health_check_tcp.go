package main

import (
	"fmt"
	"net"
	"time"

	log "github.com/sirupsen/logrus"
)

func (bs *IpvsHealthCheckBackendServer) doTcpCheck() {
	addr := bs.BackendIp
	ip := net.ParseIP(addr)
	if ip != nil && ip.To4() == nil {
		addr = fmt.Sprintf("[%s]", addr)
	}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", addr, bs.HealthCheckPort),
		time.Duration(bs.HealthCheckTimeout)*time.Second)
	if err != nil {
		log.Debugf("[tcp checker]: dial tcp %s:%d failed: %v", addr, bs.HealthCheckPort, err)
		bs.result <- false
		return
	}

	_ = conn.Close()
	bs.result <- true
}
