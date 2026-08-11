package main

import (
	"context"
	"time"

	"zstack.io/zstack-vyos/ipvs_health_check/checker"

	log "github.com/sirupsen/logrus"
)

func (bs *IpvsHealthCheckBackendServer) checkTcp() bool {
	if bs.HealthCheckTimeout <= 0 {
		log.Debugf("[tcp checker]: invalid health check timeout %d", bs.HealthCheckTimeout)
		return false
	}

	ctx, cancel := context.WithTimeout(
		context.Background(),
		time.Duration(bs.HealthCheckTimeout)*time.Second,
	)
	defer cancel()

	err := checker.TCP(ctx, bs.BackendIp, bs.HealthCheckPort)
	if err != nil {
		log.Debugf("[tcp checker]: connect to %s:%d failed: %v",
			bs.BackendIp, bs.HealthCheckPort, err)
		return false
	}

	log.Debugf("[tcp checker]: connect to %s:%d success",
		bs.BackendIp, bs.HealthCheckPort)
	return true
}
