package ipc

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
)

// signalControl signals on reached when Apply starts, then waits for its
// context.
type signalControl struct {
	fakeControl
	reached chan struct{}
}

func (h *signalControl) Apply(ctx context.Context, _ []byte) (StatusReport, error) {
	h.reached <- struct{}{}
	<-ctx.Done()
	return StatusReport{}, ctx.Err()
}

// closeAfterRequest serves a socket that reads one whole request and then
// closes the connection with no reply.
func closeAfterRequest(t *testing.T) string {
	t.Helper()
	path := shortPath(t)
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = readFrame(c) //nolint:errcheck // the close is the test
			_ = c.Close()       //nolint:errcheck // test connection
		}
	})
	t.Cleanup(func() {
		_ = ln.Close() //nolint:errcheck // the accept loop ends on the error
		wg.Wait()
	})
	return path
}

func TestApplyErrNoReply(t *testing.T) {
	t.Run("connection closed after the request", func(t *testing.T) {
		c := NewControlClient(closeAfterRequest(t), self())

		_, err := c.Apply(t.Context(), []byte("x"))

		if !errors.Is(err, ErrNoReply) || !errors.Is(err, ErrUnavailable) {
			t.Errorf("err = %v, want ErrNoReply and ErrUnavailable", err)
		}
	})
	t.Run("context ends while the server works", func(t *testing.T) {
		path := shortPath(t)
		h := &signalControl{reached: make(chan struct{}, 1)}
		listenAdmin(t, path, h, self())
		ctx, cancel := context.WithCancel(t.Context())
		go func() {
			<-h.reached
			cancel()
		}()

		_, err := NewControlClient(path, self()).Apply(ctx, []byte("x"))

		if !errors.Is(err, ErrNoReply) || !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want ErrNoReply and context.Canceled", err)
		}
	})
}

func TestErrNoReplyNeverComesBeforeTheSend(t *testing.T) {
	t.Run("dial refused", func(t *testing.T) {
		_, err := NewControlClient(shortPath(t), self()).Apply(t.Context(), []byte("x"))

		if errors.Is(err, ErrNoReply) || !errors.Is(err, ErrUnavailable) {
			t.Errorf("err = %v, want ErrUnavailable and no ErrNoReply", err)
		}
	})
	t.Run("wrong server uid", func(t *testing.T) {
		path := shortPath(t)
		h := &fakeControl{}
		listenAdmin(t, path, h, self())

		_, err := NewControlClient(path, self()+1).Apply(t.Context(), []byte("x"))

		if errors.Is(err, ErrNoReply) || !errors.Is(err, ErrUnavailable) {
			t.Errorf("err = %v, want ErrUnavailable and no ErrNoReply", err)
		}
		if n := h.calls(); n != 0 {
			t.Errorf("handler got %d calls, want 0", n)
		}
	})
	t.Run("context ended before the call", func(t *testing.T) {
		path := shortPath(t)
		listenAdmin(t, path, &fakeControl{}, self())
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		_, err := NewControlClient(path, self()).Apply(ctx, []byte("x"))

		if errors.Is(err, ErrNoReply) || !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled and no ErrNoReply", err)
		}
	})
	t.Run("socket closed to the caller", func(t *testing.T) {
		if os.Getuid() == 0 {
			t.Skip("root connects to any socket")
		}
		path := shortPath(t)
		listenAdmin(t, path, &fakeControl{}, self())
		if err := os.Chmod(path, 0); err != nil {
			t.Fatal(err)
		}

		_, err := NewControlClient(path, self()).Apply(t.Context(), []byte("x"))

		if errors.Is(err, ErrNoReply) || !errors.Is(err, ErrDenied) {
			t.Errorf("err = %v, want ErrDenied and no ErrNoReply", err)
		}
	})
}
