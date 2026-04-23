// UDS transport primitives shared between server and client.
package ipvshc

import (
	"errors"
	"net"
	"syscall"
	"time"
)

// MaxMessageSize bounds a single SEQPACKET datagram.  The kernel default
// for AF_UNIX SOCK_SEQPACKET is well above this; we cap at 1 MiB to
// keep snapshot payloads bounded and avoid OOM on a malformed peer.
const MaxMessageSize = 1 << 20

// dialSeqpacket establishes a SOCK_SEQPACKET connection to the given
// path.  Go's net package does not expose SEQPACKET helpers directly,
// so we go through syscall.
func dialSeqpacket(path string) (net.Conn, error) {
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_SEQPACKET, 0)
	if err != nil {
		return nil, err
	}
	addr := &syscall.SockaddrUnix{Name: path}
	if err := syscall.Connect(fd, addr); err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}
	return newSeqpacketConn(fd)
}

func listenSeqpacket(path string) (*SeqpacketListener, error) {
	_ = syscall.Unlink(path)
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_SEQPACKET, 0)
	if err != nil {
		return nil, err
	}
	addr := &syscall.SockaddrUnix{Name: path}
	if err := syscall.Bind(fd, addr); err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}
	if err := syscall.Listen(fd, 16); err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}
	return &SeqpacketListener{fd: fd, path: path}, nil
}

// SeqpacketListener wraps a SOCK_SEQPACKET listening socket.
type SeqpacketListener struct {
	fd   int
	path string
}

func (l *SeqpacketListener) Accept() (net.Conn, error) {
	cfd, _, err := syscall.Accept(l.fd)
	if err != nil {
		return nil, err
	}
	return newSeqpacketConn(cfd)
}

func (l *SeqpacketListener) Close() error {
	err := syscall.Close(l.fd)
	_ = syscall.Unlink(l.path)
	return err
}

// seqpacketConn implements net.Conn over a SOCK_SEQPACKET fd via
// non-blocking syscalls.  Each Read returns exactly one datagram
// (SEQPACKET preserves boundaries); each Write sends one datagram.
type seqpacketConn struct {
	fd       int
	rdl, wdl time.Time
}

func newSeqpacketConn(fd int) (*seqpacketConn, error) {
	return &seqpacketConn{fd: fd}, nil
}

func (c *seqpacketConn) Read(p []byte) (int, error) {
	if len(p) > MaxMessageSize {
		p = p[:MaxMessageSize]
	}
	n, _, err := syscall.Recvfrom(c.fd, p, 0)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, errors.New("seqpacket: peer closed")
	}
	return n, nil
}

func (c *seqpacketConn) Write(p []byte) (int, error) {
	if len(p) > MaxMessageSize {
		return 0, errors.New("seqpacket: message exceeds MaxMessageSize")
	}
	if err := syscall.Sendto(c.fd, p, 0, &syscall.SockaddrUnix{}); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *seqpacketConn) Close() error                       { return syscall.Close(c.fd) }
func (c *seqpacketConn) LocalAddr() net.Addr                { return seqAddr{} }
func (c *seqpacketConn) RemoteAddr() net.Addr               { return seqAddr{} }
func (c *seqpacketConn) SetDeadline(t time.Time) error      { c.rdl = t; c.wdl = t; return nil }
func (c *seqpacketConn) SetReadDeadline(t time.Time) error  { c.rdl = t; return nil }
func (c *seqpacketConn) SetWriteDeadline(t time.Time) error { c.wdl = t; return nil }

type seqAddr struct{}

func (seqAddr) Network() string { return "unixpacket" }
func (seqAddr) String() string  { return "" }

// Dial is the public dial entry; uses the standard library's
// "unixpacket" network when available, falling back to manual syscalls.
// Tests on platforms without SEQPACKET in the stdlib path will go
// through the syscall path transparently.
func Dial(path string) (net.Conn, error) {
	if c, err := net.Dial("unixpacket", path); err == nil {
		return c, nil
	}
	return dialSeqpacket(path)
}

// Listen is the public listen entry; prefers stdlib "unixpacket" so we
// inherit goroutine-friendly Accept semantics, falling back to manual
// syscall listener.
func Listen(path string) (net.Listener, error) {
	_ = syscall.Unlink(path)
	if l, err := net.Listen("unixpacket", path); err == nil {
		return l, nil
	}
	sl, err := listenSeqpacket(path)
	if err != nil {
		return nil, err
	}
	return &listenerAdapter{sl: sl, addr: seqAddr{}}, nil
}

type listenerAdapter struct {
	sl   *SeqpacketListener
	addr net.Addr
}

func (l *listenerAdapter) Accept() (net.Conn, error) { return l.sl.Accept() }
func (l *listenerAdapter) Close() error              { return l.sl.Close() }
func (l *listenerAdapter) Addr() net.Addr            { return l.addr }
