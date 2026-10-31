package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/ipc"
)

// TestApplyErrorClassification checks the exit code of each error that
// ControlClient.Apply returns. The CLI matches the error types only.
func TestApplyErrorClassification(t *testing.T) {
	// The peer-credential failures happen before the send. The kernel
	// gives them only in a race, so the test builds the errors in the
	// format of internal/ipc.
	peerCred := fmt.Errorf("%w: %v", ipc.ErrUnavailable, fmt.Errorf("LOCAL_PEERCRED: %w", syscall.ENOTCONN))
	peerConn := fmt.Errorf("%w: %v", ipc.ErrUnavailable, fmt.Errorf("reading peer credentials: %w", syscall.EBADF))
	noReply := fmt.Errorf("%w: %w", ipc.ErrNoReply, fmt.Errorf("%w: EOF", ipc.ErrUnavailable))
	timedOut := fmt.Errorf("requesting apply: %w: %w", context.DeadlineExceeded, ipc.ErrNoReply)
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"peer credentials fail", peerCred, 1},
		{"peer connection fails", peerConn, 1},
		{"context ended before the send", context.Canceled, 1},
		{"refused", fmt.Errorf("%w: bad policy", ipc.ErrRejected), 1},
		{"no reply", noReply, 6},
		{"context ended after the send", timedOut, 6},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := exitCode(applyError(tt.err)); got != tt.want {
				t.Errorf("exit = %d, want %d: %v", got, tt.want, applyError(tt.err))
			}
		})
	}
}

func TestApplyTimeoutWhileTheDaemonWorksExits6(t *testing.T) {
	f := &fakeDaemon{block: true, reached: make(chan struct{}, 1), release: make(chan struct{})}
	c := serveAdmin(t, f)
	t.Cleanup(func() { close(f.release) })
	ctx, cancel := context.WithTimeout(t.Context(), 1500*time.Millisecond)
	defer cancel()

	got := executeCtx(ctx, t, deps{admin: c}, "apply", writeFile(t, validConfig))

	if got.code != 6 || !strings.Contains(got.stderr, "ifbound status") {
		t.Errorf("exit = %d, stderr %q, want 6 and the status hint", got.code, got.stderr)
	}
}

func TestApplyStaleSocketExits1(t *testing.T) {
	path := socketPath(t)
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	// Keep the socket file after the close: a crashed daemon leaves it.
	ln.(*net.UnixListener).SetUnlinkOnClose(false) //nolint:forcetypeassert // a unix listener
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}

	got := execute(t, deps{admin: ipc.NewControlClient(path, uid())}, "apply", writeFile(t, validConfig))

	if got.code != 1 || strings.Contains(got.stderr, "ifbound status") {
		t.Errorf("exit = %d, stderr %q, want 1 and no lost-reply text", got.code, got.stderr)
	}
}

func TestApplyEmptyFileDoesNotCallTheServer(t *testing.T) {
	f := ready()

	got := execute(t, deps{admin: serveAdmin(t, f)}, "apply", writeFile(t, ""))

	if got.code != 1 || len(f.appliedFiles()) != 0 {
		t.Errorf("exit = %d, calls = %d, want 1 and 0 (stderr %q)", got.code, len(f.appliedFiles()), got.stderr)
	}
}
