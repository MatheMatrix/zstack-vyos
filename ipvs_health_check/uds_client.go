package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"zstack-vyos/plugin"
	"zstack.io/zstack-vyos/ipvshc"

	log "github.com/sirupsen/logrus"
)

// daemonVersion identifies this binary in hello.
const daemonVersion = "ZSTAC-84610-F-013"

var (
	udsClient        *ipvshc.Client
	udsClientMu      sync.Mutex
	udsHelloAccepted atomic.Bool
	udsRsSeq         atomic.Uint64
	// udsStartedAt is captured once at startup and embedded in every RsEvent
	// as the "incarnation" discriminator so the plugin can tell a daemon
	// restart apart from stale out-of-order events from the same incarnation.
	udsStartedAt int64
)

// daemonClientHandler implements ipvshc.ClientHandler.
//
// OnHelloAck flips a global flag so callers (Install/UnInstall/...)
// know the channel is ready.  Today the snapshot is informational
// only — gHealthCheckMap remains driven by the JSON file path
// (reloadIpvsHealthCheckConfig on SIGHUP) so that any miswired plugin
// cannot blackhole the health-check loop.  As the protocol matures
// we can switch the source of truth.
type daemonClientHandler struct{}

func (h *daemonClientHandler) OnHelloAck(a *ipvshc.HelloAck) error {
	if !a.Accepted {
		log.Errorf("[ipvs uds client] plugin REFUSED hello: %s (pluginVer=%s, protoVer=%d)",
			a.Reason, a.PluginVersion, a.ProtocolVersion)
		udsHelloAccepted.Store(false)
		return errors.New("plugin rejected hello")
	}
	log.Infof("[ipvs uds client] plugin accepted hello pluginVer=%s", a.PluginVersion)
	udsHelloAccepted.Store(true)
	return nil
}

func (h *daemonClientHandler) OnSnapshot(s *ipvshc.Snapshot) error {
	// Informational-only in this commit; JSON file path remains the
	// source of truth for gHealthCheckMap (see reloadIpvsHealthCheckConfig).
	log.Debugf("[ipvs uds client] received snapshot seq=%d listeners=%d", s.Seq, len(s.Listeners))
	return nil
}

// initUdsClient performs synchronous handshake.  Per the rolling-upgrade
// policy (hard-block), the daemon refuses to come up if the plugin's
// UDS endpoint is missing or rejects the hello.  Caller MUST treat a
// non-nil error as fatal.
func initUdsClient() error {
	hello := ipvshc.Hello{
		DaemonVersion:   daemonVersion,
		ProtocolVersion: ipvshc.ProtocolVersion,
		StartedAt:       time.Now().Unix(),
	}
	udsStartedAt = hello.StartedAt
	c := ipvshc.NewClient(ipvshc.SocketPath, hello, &daemonClientHandler{})
	c.Start(context.Background())

	udsClientMu.Lock()
	udsClient = c
	udsClientMu.Unlock()

	// Wait up to 15s for plugin to ack the hello.  This bounds boot
	// time on a fresh VR while keeping the failure loud.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if udsHelloAccepted.Load() {
			return nil
		}
		if c.VersionMismatchN.Load() > 0 {
			return fmt.Errorf("plugin protocol version mismatch")
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for plugin hello_ack on %s", ipvshc.SocketPath)
}

// emitRsEvent is the daemon's only entry point for mutating IPVS state.
// It enqueues an rs_event to the plugin; the plugin owns the actual
// ipvsadm shell-out (F-013 D-016 single-point-of-convergence).
//
// Returns immediately after enqueue; back-pressure surfaces as
// QueueDropCount on the underlying ipvshc.Client.
func emitRsEvent(bs *plugin.IpvsHealthCheckBackendServer, op ipvshc.RsEventOp, weight string) {
	udsClientMu.Lock()
	c := udsClient
	udsClientMu.Unlock()
	if c == nil {
		log.Warnf("[ipvs uds client] dropped %s for %s:%s — client not initialized",
			op, bs.BackendIp, bs.BackendPort)
		return
	}
	seq := udsRsSeq.Add(1)
	evt := ipvshc.RsEvent{
		Seq:             seq,
		DaemonStartedAt: udsStartedAt,
		ListenerUuid:    bs.ListenerUuid,
		RsIp:            bs.BackendIp,
		RsPort:          bs.BackendPort,
		Op:              op,
		Weight:          weight,
		ObservedAt:      time.Now().Unix(),
	}
	env, err := ipvshc.MakeEnvelope(fmt.Sprintf("rsevt-%d", seq), time.Now().Unix(), ipvshc.MsgRsEvent, evt)
	if err != nil {
		log.Warnf("[ipvs uds client] envelope build failed: %v", err)
		return
	}
	c.Send(env)
}
