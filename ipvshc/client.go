package ipvshc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	// QueueCapacity is the bound for the daemon-side outgoing queue.
	// Per spec: drop-oldest with log when full.
	QueueCapacity = 1000
	// PingInterval is how often the client emits ping.
	PingInterval = 10 * time.Second
	// PongTimeout: 30s without pong forces reconnect.
	PongTimeout = 30 * time.Second
	// ReconnectMin/Max: exponential backoff.
	ReconnectMin = 500 * time.Millisecond
	ReconnectMax = 30 * time.Second
)

// ClientHandler is the daemon-side surface where snapshot apply and
// hello-ack happen.
type ClientHandler interface {
	OnSnapshot(s *Snapshot) error
	OnHelloAck(a *HelloAck) error
}

// Client is the daemon-side UDS endpoint with reconnect, queue,
// heartbeat, and snapshot replay (server pushes after hello-ack).
type Client struct {
	path    string
	hello   Hello
	handler ClientHandler

	mu        sync.Mutex
	conn      net.Conn
	out       chan *Envelope
	pendingMu sync.Mutex
	lastPong  time.Time

	stopOnce sync.Once
	stopCh   chan struct{}

	// Counters; caller wires to Prom.
	MessagesIn       atomic.Uint64
	MessagesOut      atomic.Uint64
	ReconnectCount   atomic.Uint64
	QueueDropCount   atomic.Uint64
	VersionMismatchN atomic.Uint64
}

func NewClient(path string, hello Hello, h ClientHandler) *Client {
	return &Client{
		path:    path,
		hello:   hello,
		handler: h,
		out:     make(chan *Envelope, QueueCapacity),
		stopCh:  make(chan struct{}),
	}
}

func (c *Client) Start(ctx context.Context) {
	go c.runLoop(ctx)
}

func (c *Client) Stop() {
	c.stopOnce.Do(func() {
		close(c.stopCh)
		c.mu.Lock()
		if c.conn != nil {
			_ = c.conn.Close()
		}
		c.mu.Unlock()
	})
}

// Send enqueues an envelope.  When the queue is full, the oldest is
// dropped per spec; QueueDropCount increments.
func (c *Client) Send(env *Envelope) {
	for {
		select {
		case c.out <- env:
			return
		default:
			select {
			case <-c.out:
				c.QueueDropCount.Add(1)
				log.Warnf("[ipvshc client] queue full, dropping oldest (cap=%d)", QueueCapacity)
			default:
			}
		}
	}
}

func (c *Client) runLoop(ctx context.Context) {
	backoff := ReconnectMin
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		default:
		}
		if err := c.connectAndServe(ctx); err != nil {
			log.Warnf("[ipvshc client] connection lost: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		case <-time.After(backoff):
		}
		c.ReconnectCount.Add(1)
		backoff *= 2
		if backoff > ReconnectMax {
			backoff = ReconnectMax
		}
	}
}

func (c *Client) connectAndServe(ctx context.Context) error {
	conn, err := Dial(c.path)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	c.mu.Lock()
	c.conn = conn
	c.lastPong = time.Now()
	c.mu.Unlock()

	// Send hello synchronously.
	helloEnv, _ := MakeEnvelope(fmt.Sprintf("hello-%d", time.Now().UnixNano()), time.Now().Unix(), MsgHello, c.hello)
	wire, _ := Encode(helloEnv)
	if _, err := conn.Write(wire); err != nil {
		_ = conn.Close()
		return fmt.Errorf("write hello: %w", err)
	}
	c.MessagesOut.Add(1)

	doneCh := make(chan error, 3)
	go c.readLoop(conn, doneCh)
	go c.writeLoop(conn, doneCh)
	go c.heartbeatLoop(conn, doneCh)

	select {
	case <-ctx.Done():
		_ = conn.Close()
		return ctx.Err()
	case <-c.stopCh:
		_ = conn.Close()
		return errors.New("stopped")
	case err := <-doneCh:
		_ = conn.Close()
		return err
	}
}

func (c *Client) readLoop(conn net.Conn, done chan<- error) {
	buf := make([]byte, MaxMessageSize)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			done <- fmt.Errorf("read: %w", err)
			return
		}
		c.MessagesIn.Add(1)
		env, derr := Decode(buf[:n])
		if errors.Is(derr, ErrVersionMismatch) {
			c.VersionMismatchN.Add(1)
			done <- ErrVersionMismatch
			return
		}
		if derr != nil {
			log.Warnf("[ipvshc client] malformed envelope: %v", derr)
			continue
		}
		c.dispatch(env)
	}
}

func (c *Client) writeLoop(conn net.Conn, done chan<- error) {
	for {
		select {
		case <-c.stopCh:
			done <- errors.New("stopped")
			return
		case env := <-c.out:
			wire, err := Encode(env)
			if err != nil {
				continue
			}
			if _, err := conn.Write(wire); err != nil {
				done <- fmt.Errorf("write: %w", err)
				return
			}
			c.MessagesOut.Add(1)
		}
	}
}

func (c *Client) heartbeatLoop(conn net.Conn, done chan<- error) {
	pingTicker := time.NewTicker(PingInterval)
	defer pingTicker.Stop()
	checkTicker := time.NewTicker(5 * time.Second)
	defer checkTicker.Stop()
	var seq uint64
	for {
		select {
		case <-c.stopCh:
			done <- errors.New("stopped")
			return
		case <-pingTicker.C:
			seq++
			env, _ := MakeEnvelope(fmt.Sprintf("ping-%d", seq), time.Now().Unix(), MsgPing, Ping{Seq: seq})
			c.Send(env)
		case <-checkTicker.C:
			c.mu.Lock()
			last := c.lastPong
			c.mu.Unlock()
			if time.Since(last) > PongTimeout {
				done <- fmt.Errorf("pong timeout: %s since last", time.Since(last))
				return
			}
		}
	}
}

func (c *Client) dispatch(env *Envelope) {
	switch env.Type {
	case MsgHelloAck:
		var a HelloAck
		_ = DecodeBody(env, &a)
		_ = c.handler.OnHelloAck(&a)
	case MsgSnapshot:
		var s Snapshot
		_ = DecodeBody(env, &s)
		if err := c.handler.OnSnapshot(&s); err != nil {
			log.Warnf("[ipvshc client] OnSnapshot: %v", err)
			return
		}
		ack, _ := MakeEnvelope(env.ID, time.Now().Unix(), MsgSnapshotAck, SnapshotAck{Seq: s.Seq, Accepted: true})
		c.Send(ack)
	case MsgRsEventAck:
		// Plugin acked an rs_event; consume silently.
	case MsgPong:
		c.mu.Lock()
		c.lastPong = time.Now()
		c.mu.Unlock()
	}
}

// QueueDepth reports the current outgoing queue depth.
func (c *Client) QueueDepth() int {
	return len(c.out)
}
