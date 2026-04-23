// Package ipvshc defines the wire protocol shared between the zvr plugin
// (UDS server, owns ipvsadm writes) and the ipvs_health_check daemon
// (UDS client, probe-only).  The protocol is JSON line-delimited over
// SOCK_SEQPACKET so that message boundaries are preserved at the kernel
// layer and partial reads cannot corrupt envelope framing.
//
// All envelopes carry an explicit version (`v`) field; receivers MUST
// refuse versions other than ProtocolVersion and surface
// ipvs_uds_version_mismatch_total via Prometheus.
package ipvshc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

const ProtocolVersion = 1
const SocketPath = "/var/run/ipvs-health.sock"

type MsgType string

const (
	MsgHello       MsgType = "hello"
	MsgHelloAck    MsgType = "hello_ack"
	MsgSnapshot    MsgType = "snapshot"
	MsgSnapshotAck MsgType = "snapshot_ack"
	MsgRsEvent     MsgType = "rs_event"
	MsgRsEventAck  MsgType = "rs_event_ack"
	MsgPing        MsgType = "ping"
	MsgPong        MsgType = "pong"
)

type Envelope struct {
	V    int             `json:"v"`
	ID   string          `json:"id"`
	Ts   int64           `json:"ts"`
	Type MsgType         `json:"type"`
	Body json.RawMessage `json:"body,omitempty"`
}

type Hello struct {
	DaemonVersion   string `json:"daemonVersion"`
	ProtocolVersion int    `json:"protocolVersion"`
	StartedAt       int64  `json:"startedAt"`
}

type HelloAck struct {
	Accepted        bool   `json:"accepted"`
	PluginVersion   string `json:"pluginVersion"`
	ProtocolVersion int    `json:"protocolVersion"`
	Reason          string `json:"reason,omitempty"`
}

type SnapshotListener struct {
	ListenerUuid string             `json:"listenerUuid"`
	Protocol     string             `json:"protocol"`
	IpvsMode     string             `json:"ipvsMode"`
	Scheduler    string             `json:"scheduler"`
	FrontIp      string             `json:"frontIp"`
	FrontPort    string             `json:"frontPort"`
	Backends     []SnapshotBackend  `json:"backends"`
	HealthCheck  SnapshotHealthSpec `json:"healthCheck"`
}

type SnapshotBackend struct {
	BackendIp      string `json:"backendIp"`
	BackendPort    string `json:"backendPort"`
	Weight         string `json:"weight"`
	ConnectionType string `json:"connectionType"`
}

type SnapshotHealthSpec struct {
	Type               string `json:"type"`
	IntervalSeconds    int    `json:"intervalSeconds"`
	TimeoutSeconds     int    `json:"timeoutSeconds"`
	HealthyThreshold   int    `json:"healthyThreshold"`
	UnhealthyThreshold int    `json:"unhealthyThreshold"`
	HttpPath           string `json:"httpPath,omitempty"`
}

type Snapshot struct {
	Seq       uint64             `json:"seq"`
	Listeners []SnapshotListener `json:"listeners"`
}

type SnapshotAck struct {
	Seq      uint64 `json:"seq"`
	Accepted bool   `json:"accepted"`
	Reason   string `json:"reason,omitempty"`
}

type RsEventOp string

const (
	RsEventUp     RsEventOp = "up"
	RsEventDown   RsEventOp = "down"
	RsEventWeight RsEventOp = "weight"
)

type RsEvent struct {
	Seq             uint64    `json:"seq"`
	// DaemonStartedAt is the Unix timestamp (seconds) captured when the
	// daemon process initialised its UDS client.  Plugin uses it as an
	// incarnation discriminator: events from a new incarnation (higher
	// startedAt value) always win regardless of Seq so that a daemon
	// restart never silently drops health-state changes behind a
	// cached "last-seen seq" that predates the restart.
	DaemonStartedAt int64     `json:"daemonStartedAt"`
	ListenerUuid    string    `json:"listenerUuid"`
	RsIp            string    `json:"rsIp"`
	RsPort          string    `json:"rsPort"`
	Op              RsEventOp `json:"op"`
	Weight          string    `json:"weight,omitempty"`
	ObservedAt      int64     `json:"observedAt"`
}

type RsEventAck struct {
	Seq     uint64 `json:"seq"`
	Applied bool   `json:"applied"`
	Reason  string `json:"reason,omitempty"`
}

type Ping struct {
	Seq uint64 `json:"seq"`
}

type Pong struct {
	Seq uint64 `json:"seq"`
}

// ErrVersionMismatch is returned by Decode when the envelope's V field
// does not match ProtocolVersion.
var ErrVersionMismatch = errors.New("ipvshc: protocol version mismatch")

func Encode(e *Envelope) ([]byte, error) {
	if e.V == 0 {
		e.V = ProtocolVersion
	}
	buf, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	return append(buf, '\n'), nil
}

func Decode(b []byte) (*Envelope, error) {
	b = bytes.TrimRight(b, "\n")
	var e Envelope
	if err := json.Unmarshal(b, &e); err != nil {
		return nil, fmt.Errorf("ipvshc decode: %w", err)
	}
	if e.V != ProtocolVersion {
		return &e, ErrVersionMismatch
	}
	return &e, nil
}

func MakeEnvelope(id string, ts int64, t MsgType, body interface{}) (*Envelope, error) {
	e := &Envelope{V: ProtocolVersion, ID: id, Ts: ts, Type: t}
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("ipvshc encode body: %w", err)
		}
		e.Body = raw
	}
	return e, nil
}

func DecodeBody(e *Envelope, out interface{}) error {
	if len(e.Body) == 0 {
		return nil
	}
	return json.Unmarshal(e.Body, out)
}
