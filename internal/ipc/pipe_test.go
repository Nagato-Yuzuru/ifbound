package ipc

import (
	"context"
	"net"
	"sync"
	"testing"
)

// The uids of the two ends of a pipe connection.
const (
	pipeServerUID = 0 // ifboundd runs as root
	pipeClientUID = 501
)

// pipeConn is one end of a net.Pipe. The uid of its peer is fixed.
type pipeConn struct {
	net.Conn
	peer uint32
}

func (c pipeConn) PeerUID() (uint32, error) { return c.peer, nil }

// pipeListener is an in-memory listener for a test in a synctest bubble.
// All its blocking is on channels, so the bubble can become idle. A pipe
// has no buffer: a write waits for the read on the other end.
type pipeListener struct {
	conns chan peerConn
	done  chan struct{}
	once  sync.Once
}

func newPipeListener() *pipeListener {
	return &pipeListener{conns: make(chan peerConn), done: make(chan struct{})}
}

// Accept returns the server end of the next dial, or net.ErrClosed after
// Close.
func (l *pipeListener) Accept() (peerConn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

// dial opens a connection from pipeClientUID to pipeServerUID. It has no
// queue: a dial waits until Serve has a free slot and accepts, as a client
// waits in a full kernel backlog. It fails when ctx ends or the listener
// closes.
func (l *pipeListener) dial(ctx context.Context) (peerConn, error) {
	client, server := net.Pipe()
	select {
	case l.conns <- pipeConn{Conn: server, peer: pipeClientUID}:
		return pipeConn{Conn: client, peer: pipeServerUID}, nil
	case <-ctx.Done():
		_, _ = client.Close(), server.Close() //nolint:errcheck // a pipe close never fails
		return nil, ctx.Err()
	case <-l.done:
		_, _ = client.Close(), server.Close() //nolint:errcheck // a pipe close never fails
		return nil, net.ErrClosed
	}
}

// hold opens n connections that send nothing. Each one takes a slot of
// the server until the test closes it or ends.
func (l *pipeListener) hold(t *testing.T, n int) []peerConn {
	t.Helper()
	conns := make([]peerConn, n)
	for i := range conns {
		conn, err := l.dial(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() }) //nolint:errcheck // a pipe close never fails
		conns[i] = conn
	}
	return conns
}

// pipeReport serves a report server for cfg on a pipe listener until the
// test ends, and returns a client of it.
func pipeReport(t *testing.T, cfg ServerConfig) (*Client, *pipeListener) {
	t.Helper()
	ln := newPipeListener()
	cfg.AllowedUIDs = []uint32{pipeClientUID}
	serve(t, newServer(ln, cfg))
	return newClient(ln.dial, pipeServerUID), ln
}

// pipeStatus serves a status server for h on a pipe listener until the
// test ends, and returns a client of it.
func pipeStatus(t *testing.T, h StatusHandler) (*ControlClient, *pipeListener) {
	t.Helper()
	ln := newPipeListener()
	serve(t, serverOf(ln, statusSpec(StatusConfig{Handler: h})))
	return newControlClient(ln.dial, pipeServerUID), ln
}

// pipeAdmin serves an admin server for h on a pipe listener until the
// test ends, and returns a client of it.
func pipeAdmin(t *testing.T, h ControlHandler) (*ControlClient, *pipeListener) {
	t.Helper()
	ln := newPipeListener()
	serve(t, serverOf(ln, adminSpec(AdminConfig{Handler: h, UIDs: []uint32{pipeClientUID}})))
	return newControlClient(ln.dial, pipeServerUID), ln
}
