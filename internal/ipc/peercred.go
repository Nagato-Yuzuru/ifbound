package ipc

import (
	"context"
	"fmt"
	"net"
)

// peerConn is a connection that knows the uid of the process on its other
// end. The server admits a peer by this uid, and the client trusts a
// server by it.
type peerConn interface {
	net.Conn
	PeerUID() (uint32, error)
}

// peerListener accepts connections that know their peer uid.
type peerListener interface {
	Accept() (peerConn, error)
	Close() error
}

// dialFunc opens one connection to the server.
type dialFunc func(ctx context.Context) (peerConn, error)

// unixConn is a unix socket connection. The kernel gives the peer uid.
type unixConn struct{ *net.UnixConn }

// PeerUID asks the kernel for the uid of the peer.
func (c unixConn) PeerUID() (uint32, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("getting raw connection: %w", err)
	}
	var uid uint32
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		uid, credErr = peerUIDFromFD(int(fd))
	}); err != nil {
		return 0, fmt.Errorf("reading peer credentials: %w", err)
	}
	return uid, credErr
}

// unixListener is a unix socket listener.
type unixListener struct{ *net.UnixListener }

// Accept waits for the next connection.
func (l unixListener) Accept() (peerConn, error) {
	c, err := l.AcceptUnix()
	if err != nil {
		return nil, err
	}
	return unixConn{c}, nil
}

// dialUnix returns a dialFunc for the unix socket at path. Its errors are
// those of net.Dialer, so a caller can test them for fs.ErrPermission.
func dialUnix(path string) dialFunc {
	return func(ctx context.Context) (peerConn, error) {
		var d net.Dialer
		c, err := d.DialContext(ctx, "unix", path)
		if err != nil {
			return nil, err
		}
		return unixConn{c.(*net.UnixConn)}, nil //nolint:forcetypeassert // "unix" always gives *net.UnixConn
	}
}
