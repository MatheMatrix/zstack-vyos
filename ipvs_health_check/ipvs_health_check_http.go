package main

import (
	"context"
	"time"

	"zstack.io/zstack-vyos/ipvs_health_check/checker"

	log "github.com/sirupsen/logrus"
)

func (bs *IpvsHealthCheckBackendServer) checkHttp(useTLS bool) bool {
	if bs.HealthCheckTimeout <= 0 {
		log.Debugf("[http checker]: invalid health check timeout %d", bs.HealthCheckTimeout)
		return false
	}

	ctx, cancel := context.WithTimeout(
		context.Background(),
		time.Duration(bs.HealthCheckTimeout)*time.Second,
	)
	defer cancel()

	result, statusCode, err := checker.HTTP(ctx, checker.HTTPConfig{
		BackendIP:           bs.BackendIp,
		Port:                bs.HealthCheckPort,
		Method:              bs.HealthCheckMethod,
		URI:                 bs.HealthCheckURI,
		ExpectedCodeClasses: bs.HealthCheckExpectedCodeClasses,
		TLS:                 useTLS,
	})
	if err != nil {
		log.Debugf("[http checker]: request to %s:%d failed: %v",
			bs.BackendIp, bs.HealthCheckPort, err)
		return false
	}

	log.Debugf("[http checker]: request to %s:%d returned %d, result: %v",
		bs.BackendIp, bs.HealthCheckPort, statusCode, result)
	return result
}
