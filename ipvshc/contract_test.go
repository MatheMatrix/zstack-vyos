package ipvshc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// ---- helpers --------------------------------------------------------------

type capturingHandler struct {
	helloCount    atomic.Int32
	rsEventCount  atomic.Int32
	snapshotAcks  atomic.Int32
	snapshotSeq   uint64
	rejectVersion bool
}

func (h *capturingHandler) OnHello(in *Hello) (*HelloAck, error) {
	h.helloCount.Add(1)
	if h.rejectVersion {
		return &HelloAck{Accepted: false, Reason: "test reject"}, nil
	}
	return &HelloAck{Accepted: true, PluginVersion: "test"}, nil
}

func (h *capturingHandler) OnRsEvent(e *RsEvent) (*RsEventAck, error) {
	h.rsEventCount.Add(1)
	return &RsEventAck{Seq: e.Seq, Applied: true}, nil
}

func (h *capturingHandler) OnSnapshotAck(a *SnapshotAck) {
	h.snapshotAcks.Add(1)
}

func (h *capturingHandler) BuildSnapshot() (*Snapshot, error) {
	return &Snapshot{Seq: h.snapshotSeq, Listeners: nil}, nil
}

type clientCapture struct {
	helloAcks    atomic.Int32
	snapshots    atomic.Int32
	lastSnapshot atomic.Uint64
	failSnapshot bool
}

func (c *clientCapture) OnSnapshot(s *Snapshot) error {
	c.snapshots.Add(1)
	c.lastSnapshot.Store(s.Seq)
	if c.failSnapshot {
		return errors.New("test fail")
	}
	return nil
}

func (c *clientCapture) OnHelloAck(a *HelloAck) error {
	c.helloAcks.Add(1)
	return nil
}

func newSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ipvshc-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "ipvs.sock")
}

func waitFor(t *testing.T, cond func() bool, timeout time.Duration, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("waitFor timeout: %s", msg)
}

// ---- 6 contract scenarios -------------------------------------------------

// Scenario 1: plugin cold start — daemon connects, hello ack, snapshot push.
func TestContract_PluginColdStart(t *testing.T) {
	path := newSocketPath(t)
	sh := &capturingHandler{snapshotSeq: 7}
	srv := NewServer(path, sh)
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	ch := &clientCapture{}
	cli := NewClient(path, Hello{DaemonVersion: "t", ProtocolVersion: ProtocolVersion}, ch)
	cli.Start(context.Background())
	defer cli.Stop()

	waitFor(t, func() bool { return ch.helloAcks.Load() >= 1 && ch.snapshots.Load() >= 1 }, 3*time.Second, "hello+snapshot")
	if got := ch.lastSnapshot.Load(); got != 7 {
		t.Fatalf("snapshot seq: got %d want 7", got)
	}
	waitFor(t, func() bool { return sh.snapshotAcks.Load() >= 1 }, 3*time.Second, "server snapshot ack")
}

// Scenario 2: daemon crash & reconnect — kill client, restart, server still serves.
func TestContract_DaemonReconnect(t *testing.T) {
	path := newSocketPath(t)
	sh := &capturingHandler{snapshotSeq: 1}
	srv := NewServer(path, sh)
	_ = srv.Start()
	defer srv.Stop()

	ch1 := &clientCapture{}
	cli1 := NewClient(path, Hello{ProtocolVersion: ProtocolVersion}, ch1)
	cli1.Start(context.Background())
	waitFor(t, func() bool { return ch1.helloAcks.Load() >= 1 }, 3*time.Second, "first hello")
	cli1.Stop()

	// New client (simulating daemon restart).
	ch2 := &clientCapture{}
	cli2 := NewClient(path, Hello{ProtocolVersion: ProtocolVersion}, ch2)
	cli2.Start(context.Background())
	defer cli2.Stop()
	waitFor(t, func() bool { return ch2.helloAcks.Load() >= 1 }, 3*time.Second, "second hello after reconnect")
}

// Scenario 3: plugin crash & reconnect — daemon's runLoop should reconnect
// after server restarts.
func TestContract_PluginReconnect(t *testing.T) {
	path := newSocketPath(t)
	sh1 := &capturingHandler{snapshotSeq: 1}
	srv1 := NewServer(path, sh1)
	_ = srv1.Start()

	ch := &clientCapture{}
	cli := NewClient(path, Hello{ProtocolVersion: ProtocolVersion}, ch)
	cli.Start(context.Background())
	defer cli.Stop()
	waitFor(t, func() bool { return ch.helloAcks.Load() >= 1 }, 3*time.Second, "initial hello")

	// Plugin crash.
	srv1.Stop()
	time.Sleep(200 * time.Millisecond)

	// Plugin restart with new seq.
	sh2 := &capturingHandler{snapshotSeq: 99}
	srv2 := NewServer(path, sh2)
	if err := srv2.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv2.Stop()

	waitFor(t, func() bool { return ch.lastSnapshot.Load() == 99 }, 10*time.Second, "snapshot after plugin restart")
	if got := cli.ReconnectCount.Load(); got == 0 {
		t.Fatalf("reconnect count: got %d want >=1", got)
	}
}

// Scenario 4: seq regression on plugin → daemon receives lower seq and
// applies it (seq regression IS the snapshot replay signal per spec).
func TestContract_SeqRegression(t *testing.T) {
	path := newSocketPath(t)
	sh := &capturingHandler{snapshotSeq: 100}
	srv := NewServer(path, sh)
	_ = srv.Start()
	defer srv.Stop()

	ch := &clientCapture{}
	cli := NewClient(path, Hello{ProtocolVersion: ProtocolVersion}, ch)
	cli.Start(context.Background())
	defer cli.Stop()
	waitFor(t, func() bool { return ch.lastSnapshot.Load() == 100 }, 3*time.Second, "seq=100")

	// Push a regressed snapshot (seq=1 < 100); client must accept it
	// because the contract treats regression as plugin-restart signal.
	sh.snapshotSeq = 1
	if _, err := srv.PushSnapshot(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return ch.lastSnapshot.Load() == 1 }, 3*time.Second, "seq regressed to 1")
}

// Scenario 5: version mismatch refuse — client with bad version, server
// rejects + bumps counter.
func TestContract_VersionMismatch(t *testing.T) {
	path := newSocketPath(t)
	sh := &capturingHandler{}
	srv := NewServer(path, sh)
	_ = srv.Start()
	defer srv.Stop()

	conn, err := Dial(path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Hand-craft a hello envelope with V=99.
	body, _ := json.Marshal(Hello{DaemonVersion: "x", ProtocolVersion: 99})
	env := &Envelope{V: 99, ID: "h1", Ts: time.Now().Unix(), Type: MsgHello, Body: body}
	wire, _ := json.Marshal(env)
	wire = append(wire, '\n')
	if _, err := conn.Write(wire); err != nil {
		t.Fatal(err)
	}

	// Read reject ack.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, MaxMessageSize)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("expected reject ack, got read err: %v", err)
	}
	respEnv, _ := Decode(buf[:n])
	if respEnv.Type != MsgHelloAck {
		t.Fatalf("expected hello_ack, got %s", respEnv.Type)
	}
	var ack HelloAck
	_ = DecodeBody(respEnv, &ack)
	if ack.Accepted {
		t.Fatal("expected accepted=false")
	}
	waitFor(t, func() bool { return srv.VersionMismatchErr.Load() >= 1 }, 2*time.Second, "version mismatch counter")
}

// Scenario 6: queue overflow — caller pushes >QueueCapacity events
// without a connected server; oldest dropped, counter advances.
func TestContract_QueueOverflow(t *testing.T) {
	path := newSocketPath(t)
	// No server: dial will fail in runLoop, queue accumulates.
	cli := NewClient(path, Hello{ProtocolVersion: ProtocolVersion}, &clientCapture{})
	// Don't start; just exercise Send queue semantics directly.
	for i := 0; i < QueueCapacity+50; i++ {
		env, _ := MakeEnvelope(fmt.Sprintf("e-%d", i), 0, MsgRsEvent, RsEvent{Seq: uint64(i)})
		cli.Send(env)
	}
	if got := cli.QueueDropCount.Load(); got < 50 {
		t.Fatalf("drop count: got %d want >=50", got)
	}
	if got := cli.QueueDepth(); got > QueueCapacity {
		t.Fatalf("queue depth %d exceeds cap %d", got, QueueCapacity)
	}
}

// Sanity: Listener Close idempotent.
func TestListenerClose(t *testing.T) {
	path := newSocketPath(t)
	ln, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = ln.Close()
	// Re-listen after close should succeed (no leftover socket file).
	ln2, err := Listen(path)
	if err != nil {
		t.Fatalf("re-listen: %v", err)
	}
	_ = ln2.Close()
}

// Compile-time guard: Conn is a net.Conn.
var _ net.Conn = (*seqpacketConn)(nil)
