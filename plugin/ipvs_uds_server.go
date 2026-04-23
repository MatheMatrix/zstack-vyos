package plugin

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"zstack-vyos/utils"
	"zstack.io/zstack-vyos/ipvshc"

	log "github.com/sirupsen/logrus"
)

// pluginVersion identifies this binary in hello_ack; bump when wire
// semantics change in a way that demands a coordinated upgrade.
const pluginVersion = "ZSTAC-84610-F-013"

// ipvsServer is the singleton plugin-side UDS server.  Lifecycle
// matches plugin process lifetime; started inside InitIpvs() once
// the in-memory model is ready.
var (
	ipvsServer     *ipvshc.Server
	ipvsAdmin      IpvsAdmin
	ipvsServerMu   sync.Mutex
	snapshotSeq    atomic.Uint64
	rsEventSeenSeq sync.Map // key: listenerUuid+rsIp+rsPort -> uint64 last-seen seq
)

// ipvsServerHandler wires UDS server callbacks to IpvsAdmin and the
// plugin's gIpvsConf state.
type ipvsServerHandler struct{}

func (h *ipvsServerHandler) OnHello(in *ipvshc.Hello) (*ipvshc.HelloAck, error) {
	if in.ProtocolVersion != ipvshc.ProtocolVersion {
		return &ipvshc.HelloAck{
			Accepted:      false,
			PluginVersion: pluginVersion,
			Reason:        fmt.Sprintf("plugin protocol v%d, daemon v%d", ipvshc.ProtocolVersion, in.ProtocolVersion),
		}, nil
	}
	log.Infof("[ipvs uds] daemon connected daemonVer=%s started=%d", in.DaemonVersion, in.StartedAt)
	return &ipvshc.HelloAck{Accepted: true, PluginVersion: pluginVersion}, nil
}

func (h *ipvsServerHandler) BuildSnapshot() (*ipvshc.Snapshot, error) {
	seq := snapshotSeq.Add(1)
	conf := gIpvsConf
	if conf == nil || conf.Services == nil {
		return &ipvshc.Snapshot{Seq: seq}, nil
	}
	out := &ipvshc.Snapshot{Seq: seq, Listeners: make([]ipvshc.SnapshotListener, 0, len(conf.Services))}
	for _, fs := range conf.Services {
		if fs == nil {
			continue
		}
		l := ipvshc.SnapshotListener{
			Protocol:  NormalizeIpvsProto(fs.ProtocolType),
			Scheduler: fs.Scheduler,
			FrontIp:   fs.FrontIp,
			FrontPort: fs.FrontPort,
		}
		for _, b := range fs.BackendServers {
			if b == nil {
				continue
			}
			l.Backends = append(l.Backends, ipvshc.SnapshotBackend{
				BackendIp:      b.BackendIp,
				BackendPort:    b.BackendPort,
				Weight:         b.Weight,
				ConnectionType: b.ConnectionType,
			})
		}
		out.Listeners = append(out.Listeners, l)
	}
	return out, nil
}

func (h *ipvsServerHandler) OnSnapshotAck(a *ipvshc.SnapshotAck) {
	if !a.Accepted {
		log.Warnf("[ipvs uds] daemon refused snapshot seq=%d reason=%s", a.Seq, a.Reason)
	}
}

// rsEventDedupeKey returns the dedupe key for an rs_event.
// daemonStartedAt acts as an incarnation discriminator so that a daemon
// restart (which resets the per-process seq counter) is never silently
// confused with stale events from the previous incarnation.
func rsEventDedupeKey(daemonStartedAt int64, listenerUuid, rsIp, rsPort string) string {
	return fmt.Sprintf("%d|%s|%s|%s", daemonStartedAt, listenerUuid, rsIp, rsPort)
}

// findBackendInService searches the frontend service's backend map for a
// backend matching (rsIp, rsPort).
func findBackendInService(fs *IpvsFrontendService, rsIp, rsPort string) *IpvsBackendServer {
	for _, b := range fs.BackendServers {
		if b != nil && b.BackendIp == rsIp && b.BackendPort == rsPort {
			return b
		}
	}
	return nil
}

func (h *ipvsServerHandler) OnRsEvent(e *ipvshc.RsEvent) (*ipvshc.RsEventAck, error) {
	// Incarnation-aware idempotency: same (daemonStartedAt, listener, rs)
	// dedupe on seq.  A new daemonStartedAt means the daemon restarted and
	// its seq counter reset — those events MUST be processed.
	key := rsEventDedupeKey(e.DaemonStartedAt, e.ListenerUuid, e.RsIp, e.RsPort)
	if prev, ok := rsEventSeenSeq.Load(key); ok {
		if pseq, _ := prev.(uint64); pseq >= e.Seq {
			return &ipvshc.RsEventAck{Seq: e.Seq, Applied: true, Reason: "dup-or-stale"}, nil
		}
	}

	if ipvsAdmin == nil {
		return &ipvshc.RsEventAck{Seq: e.Seq, Applied: false, Reason: "no ipvs admin"}, nil
	}

	// Precise listener lookup via listenerUuid — avoids mis-routing when
	// the same backend IP:port appears under multiple listeners.
	fs := GetIpvsFrontService(e.ListenerUuid)
	if fs == nil {
		return &ipvshc.RsEventAck{Seq: e.Seq, Applied: false, Reason: "listener not found in conf"}, nil
	}

	var applyErr error
	switch e.Op {
	case ipvshc.RsEventUp:
		// Ensure the service row exists in the kernel (idempotent: EEXIST=ok).
		if err := ipvsAdmin.AddService(*fs); err != nil {
			applyErr = fmt.Errorf("AddService: %w", err)
			break
		}
		b := findBackendInService(fs, e.RsIp, e.RsPort)
		if b == nil {
			applyErr = fmt.Errorf("backend %s:%s not in listener %s conf", e.RsIp, e.RsPort, e.ListenerUuid)
			break
		}
		applyErr = ipvsAdmin.AddBackend(*fs, *b)

	case ipvshc.RsEventDown:
		b := findBackendInService(fs, e.RsIp, e.RsPort)
		if b == nil {
			// Already absent — idempotent success; still advance seq.
			rsEventSeenSeq.Store(key, e.Seq)
			return &ipvshc.RsEventAck{Seq: e.Seq, Applied: true, Reason: "backend already absent"}, nil
		}
		if err := ipvsAdmin.DelBackend(*fs, *b); err != nil {
			applyErr = fmt.Errorf("DelBackend: %w", err)
			break
		}
		// If this was the last backend, prune the empty service immediately.
		// Using ipvsAdmin.Save() so we query live kernel state rather than
		// gIpvsConf (which reflects desired state, not current liveness).
		if saved, err := ipvsAdmin.Save(); err == nil {
			fsKey := fs.getFrontendServiceKey()
			remaining := -1 // -1 = service not present at all
			for _, sfs := range saved {
				if sfs.getFrontendServiceKey() == fsKey {
					remaining = len(sfs.BackendServers)
					break
				}
			}
			if remaining == 0 {
				if err := ipvsAdmin.DelService(*fs); err != nil {
					log.Warnf("[ipvs uds] DelService after last backend down listener=%s: %v", e.ListenerUuid, err)
				}
			}
		}

	case ipvshc.RsEventWeight:
		b := findBackendInService(fs, e.RsIp, e.RsPort)
		if b == nil {
			applyErr = fmt.Errorf("backend %s:%s not in listener %s conf", e.RsIp, e.RsPort, e.ListenerUuid)
			break
		}
		bcopy := *b
		if e.Weight != "" {
			bcopy.Weight = e.Weight
		}
		applyErr = ipvsAdmin.EditBackend(*fs, bcopy)

	default:
		return &ipvshc.RsEventAck{Seq: e.Seq, Applied: false, Reason: "unknown op"}, nil
	}

	if applyErr != nil {
		return &ipvshc.RsEventAck{Seq: e.Seq, Applied: false, Reason: applyErr.Error()}, nil
	}
	// Apply succeeded → update seen seq for future dedupe.
	rsEventSeenSeq.Store(key, e.Seq)
	return &ipvshc.RsEventAck{Seq: e.Seq, Applied: true}, nil
}

// StartIpvsUdsServer starts the plugin-side UDS server.  Called from
// InitIpvs() after gIpvsConf is initialized.  Safe to call multiple
// times; second call is a no-op.
func StartIpvsUdsServer() {
	ipvsServerMu.Lock()
	defer ipvsServerMu.Unlock()
	if ipvsServer != nil {
		return
	}
	if ipvsAdmin == nil {
		ipvsAdmin = NewRealIpvsAdmin()
	}
	srv := ipvshc.NewServer(ipvshc.SocketPath, &ipvsServerHandler{})
	if err := srv.Start(); err != nil {
		log.Warnf("[ipvs uds] server start failed: %v (daemon will fail to handshake)", err)
		return
	}
	ipvsServer = srv
	// Best-effort permissions: daemon runs as a non-root user via
	// sudo, so the UDS file must be world-rw.  Failure here is
	// non-fatal (daemon will just see EACCES on connect and we log).
	chmodBash := utils.Bash{Command: "chmod 0666 " + ipvshc.SocketPath, Sudo: true}
	_ = chmodBash.Run()
	log.Infof("[ipvs uds] server listening on %s pluginVersion=%s", ipvshc.SocketPath, pluginVersion)
}

// PushIpvsSnapshot triggers a snapshot push to all connected daemons.
// Called by RefreshIpvsBackend whenever gIpvsConf changes.
func PushIpvsSnapshot() {
	ipvsServerMu.Lock()
	srv := ipvsServer
	ipvsServerMu.Unlock()
	if srv == nil {
		return
	}
	if _, err := srv.PushSnapshot(context.Background()); err != nil {
		log.Warnf("[ipvs uds] PushSnapshot: %v", err)
	}
}
