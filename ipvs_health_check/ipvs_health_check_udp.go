package main

import (
	"fmt"
	"net"
	"time"

	log "github.com/sirupsen/logrus"
)
	
func (bs *IpvsHealthCheckBackendServer) doUdpCheck() {
	addr := bs.BackendIp
	ip := net.ParseIP(bs.BackendIp)
	if ip != nil && ip.To4() == nil{
		addr = fmt.Sprintf("[%s]", addr)
	}
	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:%s", addr, bs.BackendPort), 
			time.Duration(bs.HealthCheckTimeout) *time.Second)
	if err != nil {
		log.Debugf("[udp checher]: dial udp  %s:%s failed: %v",  addr, bs.BackendPort, err)
		bs.result <- false
		return 
	}
	
	defer conn.Close()
	message := []byte("zstack ipvs health check")
	
	_, err = conn.Write(message)
	if err != nil {
		log.Debugf("[udp checher]: send  udp message to %s:%s failed: %v",  bs.BackendIp, bs.BackendPort, err)
		bs.result <- false
		return 
	}
	
	buffer := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(time.Duration(bs.HealthCheckTimeout) * time.Second))
	_, err = conn.Read(buffer, )
	if err != nil {
		log.Debugf("[udp checher]: recv  udp message from %s:%s failed: %v",  bs.BackendIp, bs.BackendPort, err)
		bs.result <- false
		return
	}
	
	bs.result <- true
}
