package ipvshc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ServerHandler is the application-level callback set surface of the
// plugin-side UDS server.  Methods are invoked on the server's per-conn
// goroutine; implementations must be goroutine-safe and return quickly
// (any blocking I/O — e.g. ipvsadm — should be serialized at the
// implementation layer).
type ServerHandler interface {
	OnHello(h *Hello) (*HelloAck, error)
	OnRsEvent(e *RsEvent) (*RsEventAck, error)
	OnSnapshotAck(a *SnapshotAck)
	BuildSnapshot() (*Snapshot, error)
}

// Server hosts the plugin-side UDS endpoint.
type Server struct {
	path    string
	handler ServerHandler
	ln      net.Listener

	mu       sync.Mutex
	clients  map[string]*serverConn
	stopOnce sync.Once
	stopped  chan struct{}

	// Metrics (exported as plain counters; wired to Prom by caller).
	MessagesIn         atomic.Uint64
	MessagesOut        atomic.Uint64
	VersionMismatchErr atomic.Uint64
}

type serverConn struct {
	id   string
	conn net.Conn
	enc  chan *Envelope
	done chan struct{}
}

func NewServer(path string, h ServerHandler) *Server {
	return &Server{
		path:    path,
		handler: h,
		clients: map[string]*serverConn{},
		stopped: make(chan struct{}),
	}
}

func (s *Server) Start() error {
	ln, err := Listen(s.path)
	if err != nil {
		return fmt.Errorf("ipvshc listen %s: %w", s.path, err)
	}
	s.ln = ln
	go s.acceptLoop()
	return nil
}

func (s *Server) Stop() {
	s.stopOnce.Do(func() {
		close(s.stopped)
		if s.ln != nil {
			_ = s.ln.Close()
		}
		s.mu.Lock()
		for _, c := range s.clients {
			_ = c.conn.Close()
		}
		s.mu.Unlock()
	})
}

func (s *Server) acceptLoop() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			select {
			case <-s.stopped:
				return
			default:
				time.Sleep(50 * time.Millisecond)
				continue
			}
		}
		sc := &serverConn{
			id:   fmt.Sprintf("conn-%d", time.Now().UnixNano()),
			conn: c,
			enc:  make(chan *Envelope, 256),
			done: make(chan struct{}),
		}
		s.mu.Lock()
		s.clients[sc.id] = sc
		s.mu.Unlock()
		go s.writeLoop(sc)
		go s.readLoop(sc)
	}
}

func (s *Server) writeLoop(sc *serverConn) {
	for {
		select {
		case <-sc.done:
			return
		case env := <-sc.enc:
			wire, err := Encode(env)
			if err != nil {
				continue
			}
			if _, err := sc.conn.Write(wire); err != nil {
				return
			}
			s.MessagesOut.Add(1)
		}
	}
}

func (s *Server) readLoop(sc *serverConn) {
	defer func() {
		close(sc.done)
		_ = sc.conn.Close()
		s.mu.Lock()
		delete(s.clients, sc.id)
		s.mu.Unlock()
	}()
	buf := make([]byte, MaxMessageSize)
	for {
		n, err := sc.conn.Read(buf)
		if err != nil {
			return
		}
		s.MessagesIn.Add(1)
		env, err := Decode(buf[:n])
		if errors.Is(err, ErrVersionMismatch) {
			s.VersionMismatchErr.Add(1)
			if env != nil && env.Type == MsgHello {
				ack, _ := MakeEnvelope(env.ID, time.Now().Unix(), MsgHelloAck, HelloAck{
					Accepted:        false,
					ProtocolVersion: ProtocolVersion,
					Reason:          "protocol version mismatch",
				})
				// Write synchronously: returning here closes the
				// connection and would race with writeLoop.
				if wire, werr := Encode(ack); werr == nil {
					_, _ = sc.conn.Write(wire)
					s.MessagesOut.Add(1)
				}
			}
			return
		}
		if err != nil {
			continue
		}
		s.dispatch(sc, env)
	}
}

func (s *Server) dispatch(sc *serverConn, env *Envelope) {
	switch env.Type {
	case MsgHello:
		var h Hello
		_ = DecodeBody(env, &h)
		ack, err := s.handler.OnHello(&h)
		if err != nil || ack == nil {
			ack = &HelloAck{Accepted: false, Reason: "plugin refused"}
		}
		ack.ProtocolVersion = ProtocolVersion
		out, _ := MakeEnvelope(env.ID, time.Now().Unix(), MsgHelloAck, ack)
		s.send(sc, out)
		// Push initial snapshot.
		if ack.Accepted {
			if snap, err := s.handler.BuildSnapshot(); err == nil && snap != nil {
				snapEnv, _ := MakeEnvelope(fmt.Sprintf("snap-%d", time.Now().UnixNano()), time.Now().Unix(), MsgSnapshot, snap)
				s.send(sc, snapEnv)
			}
		}
	case MsgRsEvent:
		var e RsEvent
		_ = DecodeBody(env, &e)
		ack, _ := s.handler.OnRsEvent(&e)
		if ack == nil {
			ack = &RsEventAck{Seq: e.Seq, Applied: false, Reason: "no handler ack"}
		}
		out, _ := MakeEnvelope(env.ID, time.Now().Unix(), MsgRsEventAck, ack)
		s.send(sc, out)
	case MsgSnapshotAck:
		var a SnapshotAck
		_ = DecodeBody(env, &a)
		s.handler.OnSnapshotAck(&a)
	case MsgPing:
		var p Ping
		_ = DecodeBody(env, &p)
		out, _ := MakeEnvelope(env.ID, time.Now().Unix(), MsgPong, Pong{Seq: p.Seq})
		s.send(sc, out)
	}
}

func (s *Server) send(sc *serverConn, env *Envelope) {
	select {
	case sc.enc <- env:
	default:
		// Per-connection queue full — drop oldest by reading once and
		// pushing again.  Simpler bounded-queue strategy until F-013
		// commit 5 wires the proper drop-oldest accounting.
		select {
		case <-sc.enc:
		default:
		}
		select {
		case sc.enc <- env:
		default:
		}
	}
}

// Broadcast pushes the envelope to every connected client.  Used to
// re-emit a snapshot when plugin state changes (e.g. listener
// add/remove via RefreshIpvsBackend).
func (s *Server) Broadcast(env *Envelope) {
	s.mu.Lock()
	conns := make([]*serverConn, 0, len(s.clients))
	for _, c := range s.clients {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	for _, sc := range conns {
		s.send(sc, env)
	}
}

// PushSnapshot is a convenience for sending a fresh snapshot to all
// clients.  Returns the seq used (for caller bookkeeping).
func (s *Server) PushSnapshot(ctx context.Context) (uint64, error) {
	snap, err := s.handler.BuildSnapshot()
	if err != nil {
		return 0, err
	}
	if snap == nil {
		return 0, nil
	}
	env, err := MakeEnvelope(fmt.Sprintf("snap-%d", time.Now().UnixNano()), time.Now().Unix(), MsgSnapshot, snap)
	if err != nil {
		return 0, err
	}
	s.Broadcast(env)
	return snap.Seq, nil
}
