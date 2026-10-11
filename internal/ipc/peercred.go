package ipc

import (
	"fmt"
	"net"
)

// peerUID asks the kernel for the uid of the process on the other end of c.
func peerUID(c net.Conn) (uint32, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, fmt.Errorf("%w: not a unix connection", ErrProtocol)
	}
	raw, err := uc.SyscallConn()
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
