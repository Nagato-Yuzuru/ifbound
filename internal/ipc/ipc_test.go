package ipc

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type handlerFunc func(ctx context.Context, o Observation) error

func (f handlerFunc) Observe(ctx context.Context, o Observation) error { return f(ctx, o) }

var errNo = errors.New("no such policy")

// shortPath returns a socket path short enough for macOS (104 bytes).
func shortPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ipc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "s.sock")
}

func listen(t *testing.T, path string, h Handler, uids ...uint32) *Server {
	t.Helper()
	srv, err := Listen(ServerConfig{Path: path, Handler: h, AllowedUIDs: uids})
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- srv.Serve(context.Background()) }()
	t.Cleanup(func() {
		_ = srv.Close()
		select {
		case err := <-served:
			if err != nil {
				t.Errorf("Serve returned %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Serve did not return after Close")
		}
	})
	return srv
}

func self() uint32 { return uint32(os.Getuid()) } //nolint:gosec // uid is never negative on unix

func start(t *testing.T, h Handler) (*Client, string) {
	t.Helper()
	path := shortPath(t)
	listen(t, path, h, self())
	return NewClient(path, self()), path
}

func ack(context.Context, Observation) error { return nil }

func TestRoundTrip(t *testing.T) {
	var got Observation
	c, path := start(t, handlerFunc(func(_ context.Context, o Observation) error {
		got = o
		return nil
	}))
	want := Observation{
		QName: "example.com.",
		Addrs: []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")},
		TTL:   30 * time.Second,
	}
	if err := c.Report(t.Context(), want); err != nil {
		t.Fatal(err)
	}
	if got.QName != want.QName || got.TTL != want.TTL || len(got.Addrs) != 2 ||
		got.Addrs[0] != want.Addrs[0] || got.Addrs[1] != want.Addrs[1] {
		t.Errorf("got %+v, want %+v", got, want)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := fi.Mode().Perm(); mode != 0o660 {
		t.Errorf("socket mode = %o, want 660", mode)
	}
}

func TestRejection(t *testing.T) {
	c, _ := start(t, handlerFunc(func(context.Context, Observation) error { return errNo }))
	err := c.Report(t.Context(), Observation{QName: "a.test."})
	if !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), errNo.Error()) {
		t.Errorf("err = %v, want ErrRejected with the reason", err)
	}
}

func TestTimeout(t *testing.T) {
	release := make(chan struct{})
	c, _ := start(t, handlerFunc(func(context.Context, Observation) error {
		<-release
		return nil
	}))
	t.Cleanup(func() { close(release) }) // runs before the server cleanup

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	err := c.Report(ctx, Observation{QName: "slow.test."})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want DeadlineExceeded", err)
	}
}

func TestHandlerContextCarriesClientDeadline(t *testing.T) {
	var remaining atomic.Int64
	c, _ := start(t, handlerFunc(func(ctx context.Context, _ Observation) error {
		dl, ok := ctx.Deadline()
		if ok {
			remaining.Store(int64(time.Until(dl)))
		}
		return nil
	}))
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := c.Report(ctx, Observation{QName: "a.test."}); err != nil {
		t.Fatal(err)
	}
	got := time.Duration(remaining.Load())
	if got < 2*time.Second || got > 3*time.Second {
		t.Errorf("handler deadline in %v, want within (2s, 3s]", got)
	}
}

func TestInvalidObservationsAreRejectedBeforeHandler(t *testing.T) {
	var calls atomic.Int32
	c, _ := start(t, handlerFunc(func(context.Context, Observation) error {
		calls.Add(1)
		return nil
	}))
	tests := map[string]Observation{
		"empty qname":    {},
		"qname too long": {QName: strings.Repeat("a", MaxQNameLen+1)},
	}
	for name, o := range tests {
		t.Run(name, func(t *testing.T) {
			if err := c.Report(t.Context(), o); !errors.Is(err, ErrRejected) {
				t.Errorf("err = %v, want ErrRejected", err)
			}
		})
	}
	for name, q := range map[string]string{
		"qname at the limit":           strings.Repeat("a", MaxQNameLen),
		"escaped non-ASCII, 258 chars": strings.Repeat(`\195\175`, 31) + ".bing.com.",
	} {
		t.Run(name, func(t *testing.T) {
			if err := c.Report(t.Context(), Observation{QName: q}); err != nil {
				t.Error(err)
			}
		})
	}
	if calls.Load() != 2 {
		t.Errorf("handler called %d times, want 2", calls.Load())
	}
}

// rawExchange sends raw bytes and returns the first reply frame.
func rawExchange(t *testing.T, path string, raw []byte) (envelope, net.Conn) {
	t.Helper()
	var d net.Dialer
	conn, err := d.DialContext(t.Context(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(raw); err != nil {
		t.Fatal(err)
	}
	env, err := readFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	return env, conn
}

func frameOf(payload string) []byte {
	buf := binary.BigEndian.AppendUint32(nil, uint32(len(payload))) //nolint:gosec // test payloads are small
	return append(buf, payload...)
}

func assertClosed(t *testing.T, conn net.Conn) {
	t.Helper()
	if _, err := readFrame(conn); !errors.Is(err, io.EOF) {
		t.Errorf("err = %v, want EOF after rejection", err)
	}
}

func TestOversizeFrame(t *testing.T) {
	_, path := start(t, handlerFunc(ack))
	hdr := binary.BigEndian.AppendUint32(nil, MaxFrameSize+1)
	env, conn := rawExchange(t, path, hdr)
	if env.Type != typeReject {
		t.Errorf("type = %q, want reject", env.Type)
	}
	assertClosed(t, conn)
}

func TestMalformedFrame(t *testing.T) {
	_, path := start(t, handlerFunc(ack))
	env, conn := rawExchange(t, path, frameOf("not json"))
	if env.Type != typeReject {
		t.Errorf("type = %q, want reject", env.Type)
	}
	assertClosed(t, conn)
}

func TestUnknownTypeAndVersion(t *testing.T) {
	_, path := start(t, handlerFunc(ack))
	tests := map[string]string{
		"unknown type":    `{"v":1,"type":"bogus"}`,
		"unknown version": `{"v":2,"type":"observe","body":{"qname":"a.test."}}`,
		"bad address":     `{"v":1,"type":"observe","body":{"qname":"a.test.","addrs":["nope"],"timeout_ms":1000}}`,
		"missing body":    `{"v":1,"type":"observe"}`,
		"zero timeout":    `{"v":1,"type":"observe","body":{"qname":"a.test.","timeout_ms":0}}`,
		"huge timeout":    `{"v":1,"type":"observe","body":{"qname":"a.test.","timeout_ms":9223372036854775807}}`,
		"zoned address":   `{"v":1,"type":"observe","body":{"qname":"a.test.","addrs":["fe80::1%en0"],"timeout_ms":1000}}`,
	}
	for name, payload := range tests {
		t.Run(name, func(t *testing.T) {
			env, _ := rawExchange(t, path, frameOf(payload))
			if env.Type != typeReject {
				t.Errorf("type = %q, want reject", env.Type)
			}
		})
	}
}

func TestClientRejectsBadReplies(t *testing.T) {
	tests := []struct {
		name  string
		reply []byte
		want  error
	}{
		{"unknown type", frameOf(`{"v":1,"type":"bogus"}`), ErrProtocol},
		{"bad version", frameOf(`{"v":9,"type":"ack"}`), ErrProtocol},
		{"no version", frameOf(`{"type":"ack"}`), ErrProtocol},
		{"version as string", frameOf(`{"v":"1","type":"ack"}`), ErrProtocol},
		{"no type", frameOf(`{"v":1}`), ErrProtocol},
		{"upper case type", frameOf(`{"v":1,"type":"ACK"}`), ErrProtocol},
		{"type with space", frameOf(`{"v":1,"type":"ack "}`), ErrProtocol},
		{"echoed request type", frameOf(`{"v":1,"type":"observe"}`), ErrProtocol},
		{"empty object", frameOf(`{}`), ErrProtocol},
		{"null", frameOf(`null`), ErrProtocol},
		{"array", frameOf(`[1,"ack"]`), ErrProtocol},
		{"not json", frameOf(`xx`), ErrProtocol},
		{"empty frame", frameOf(``), ErrProtocol},
		{"bad reject body", frameOf(`{"v":1,"type":"reject","body":5}`), ErrProtocol},
		{"oversize header", binary.BigEndian.AppendUint32(nil, MaxFrameSize+1), ErrFrameTooLarge},
		{"half header", []byte{0, 0}, ErrUnavailable},
		{"short body", []byte{0, 0, 0, 30, '{'}, ErrUnavailable},
		{"close without reply", nil, ErrUnavailable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := shortPath(t)
			var lc net.ListenConfig
			ln, err := lc.Listen(t.Context(), "unix", path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = ln.Close() })
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				defer func() { _ = conn.Close() }()
				_, _ = readFrame(conn)
				_, _ = conn.Write(tc.reply)
			}()
			err = NewClient(path, self()).Report(t.Context(), Observation{QName: "a.test."})
			if !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestConcurrentReport(t *testing.T) {
	var seen sync.Map
	c, _ := start(t, handlerFunc(func(_ context.Context, o Observation) error {
		seen.Store(o.QName, true)
		return nil
	}))
	const n = 50
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := range n {
		wg.Go(func() {
			name := strings.Repeat("a", i+1) + ".test."
			errs <- c.Report(t.Context(), Observation{QName: name})
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	count := 0
	seen.Range(func(any, any) bool { count++; return true })
	if count != n {
		t.Errorf("handler saw %d names, want %d", count, n)
	}
}

func TestClientRecoversAfterServerRestart(t *testing.T) {
	path := shortPath(t)
	c := NewClient(path, self())
	if err := c.Report(t.Context(), Observation{QName: "a.test."}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	srv := listen(t, path, handlerFunc(ack), self())
	if err := c.Report(t.Context(), Observation{QName: "a.test."}); err != nil {
		t.Fatalf("after start: %v", err)
	}
	_ = srv.Close()
	if err := c.Report(t.Context(), Observation{QName: "a.test."}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("after stop: err = %v, want ErrUnavailable", err)
	}
	listen(t, path, handlerFunc(ack), self())
	if err := c.Report(t.Context(), Observation{QName: "a.test."}); err != nil {
		t.Fatalf("after restart: %v", err)
	}
}

func TestDisallowedUIDGetsNoAck(t *testing.T) {
	var calls atomic.Int32
	path := shortPath(t)
	listen(t, path, handlerFunc(func(context.Context, Observation) error {
		calls.Add(1)
		return nil
	}), self()+1)
	err := NewClient(path, self()).Report(t.Context(), Observation{QName: "a.test."})
	if !errors.Is(err, ErrUnavailable) {
		t.Errorf("err = %v, want ErrUnavailable", err)
	}
	if calls.Load() != 0 {
		t.Error("handler ran for a disallowed uid")
	}
}

func TestServeStopsOnContextCancel(t *testing.T) {
	path := shortPath(t)
	started := make(chan struct{})
	handlerDone := make(chan struct{})
	srv, err := Listen(ServerConfig{Path: path, AllowedUIDs: []uint32{self()}, Handler: handlerFunc(
		func(ctx context.Context, _ Observation) error {
			close(started)
			<-ctx.Done() // shutdown must end the handler context
			close(handlerDone)
			return ctx.Err()
		})})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ctx) }()

	go func() { _ = NewClient(path, self()).Report(t.Context(), Observation{QName: "a.test."}) }()
	<-started
	cancel()
	select {
	case err := <-served:
		if err != nil {
			t.Errorf("Serve = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after cancel")
	}
	select {
	case <-handlerDone:
	default:
		t.Error("Serve returned before the handler finished")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("socket file still exists: %v", err)
	}
}

func TestFrameRoundTripJSON(t *testing.T) {
	b, _ := json.Marshal(envelopeOf(typeAck, nil))
	if string(b) != `{"v":1,"type":"ack"}` {
		t.Errorf("wire = %s", b)
	}
}

func TestBurstOfReportsAllSucceeds(t *testing.T) {
	c, _ := start(t, handlerFunc(ack))
	const n = 1200
	var wg sync.WaitGroup
	var fails atomic.Int32
	gate := make(chan struct{})
	for range n {
		wg.Go(func() {
			<-gate
			if err := c.Report(t.Context(), Observation{QName: "a.test.", Addrs: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}); err != nil {
				fails.Add(1)
			}
		})
	}
	close(gate)
	wg.Wait()
	if fails.Load() != 0 {
		t.Errorf("%d of %d reports failed", fails.Load(), n)
	}
}

func TestReportWaitingForSlotHonorsContext(t *testing.T) {
	release := make(chan struct{})
	c, _ := start(t, handlerFunc(func(context.Context, Observation) error {
		<-release
		return nil
	}))
	t.Cleanup(func() { close(release) })
	var wg sync.WaitGroup
	for range maxInFlight {
		wg.Go(func() { _ = c.Report(t.Context(), Observation{QName: "a.test."}) })
	}
	for len(c.inflight) < maxInFlight {
		time.Sleep(time.Millisecond) // waits for the pool to fill; no other signal exists
	}
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	err := c.Report(ctx, Observation{QName: "a.test."})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want DeadlineExceeded", err)
	}
	cancel()
	// The blocked reports end when the cleanup releases the handler.
	t.Cleanup(wg.Wait)
}

func TestServerConnectionCap(t *testing.T) {
	c, path := start(t, handlerFunc(ack))
	var idle []net.Conn
	var d net.Dialer
	for range maxConns {
		conn, err := d.DialContext(t.Context(), "unix", path)
		if err != nil {
			t.Fatal(err)
		}
		idle = append(idle, conn)
	}
	// Every slot is taken: the next client waits in the kernel backlog.
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	if err := c.Report(ctx, Observation{QName: "a.test."}); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want DeadlineExceeded while the cap is full", err)
	}
	for _, conn := range idle {
		_ = conn.Close()
	}
	if err := c.Report(t.Context(), Observation{QName: "a.test."}); err != nil {
		t.Errorf("after the idle connections close: %v", err)
	}
}

func TestOneRequestPerConnection(t *testing.T) {
	_, path := start(t, handlerFunc(ack))
	req := frameOf(`{"v":1,"type":"observe","body":{"qname":"a.test.","timeout_ms":1000}}`)
	env, conn := rawExchange(t, path, req)
	if env.Type != typeAck {
		t.Fatalf("type = %q, want ack", env.Type)
	}
	assertClosed(t, conn)
}

func TestClientRejectsServerWithOtherUID(t *testing.T) {
	path := shortPath(t)
	listen(t, path, handlerFunc(ack), self())
	err := NewClient(path, self()+1).Report(t.Context(), Observation{QName: "a.test."})
	if !errors.Is(err, ErrUnavailable) {
		t.Errorf("err = %v, want ErrUnavailable", err)
	}
}

func TestHandlerGetsCanonicalAddrs(t *testing.T) {
	var got []netip.Addr
	c, _ := start(t, handlerFunc(func(_ context.Context, o Observation) error {
		got = o.Addrs
		return nil
	}))
	mapped := netip.MustParseAddr("::ffff:192.0.2.7")
	if err := c.Report(t.Context(), Observation{QName: "a.test.", Addrs: []netip.Addr{mapped}}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != netip.MustParseAddr("192.0.2.7") || got[0].Is4In6() {
		t.Errorf("got %v, want the unmapped IPv4 address", got)
	}
	zoned := netip.MustParseAddr("fe80::1%en0")
	if err := c.Report(t.Context(), Observation{QName: "a.test.", Addrs: []netip.Addr{zoned}}); !errors.Is(err, ErrRejected) {
		t.Errorf("zoned address: err = %v, want ErrRejected", err)
	}
}

func TestLargestDNSAnswer(t *testing.T) {
	var n atomic.Int32
	c, _ := start(t, handlerFunc(func(_ context.Context, o Observation) error {
		n.Store(int32(len(o.Addrs))) //nolint:gosec // 2400 fits
		return nil
	}))
	addrs := make([]netip.Addr, 2400)
	for i := range addrs {
		addrs[i] = netip.MustParseAddr(fmt.Sprintf("2001:db8:1234:5678:9abc:def0:%x:%x", i>>8, i&0xff))
	}
	if err := c.Report(t.Context(), Observation{QName: "big.test.", Addrs: addrs}); err != nil {
		t.Fatal(err)
	}
	if n.Load() != 2400 {
		t.Errorf("handler saw %d addresses", n.Load())
	}
}

func TestLongRejectionReasonStillArrives(t *testing.T) {
	_, path := start(t, handlerFunc(ack))
	long := strings.Repeat("x", 20<<10)
	tests := map[string]string{
		"long unknown type": `{"v":1,"type":"` + long + `"}`,
		"long bad address":  `{"v":1,"type":"observe","body":{"qname":"a.test.","addrs":["` + long + `"],"timeout_ms":1000}}`,
	}
	for name, payload := range tests {
		t.Run(name, func(t *testing.T) {
			env, _ := rawExchange(t, path, frameOf(payload))
			if env.Type != typeReject {
				t.Fatalf("type = %q, want reject", env.Type)
			}
			if len(env.Body) > 2*maxReasonLen*3 {
				t.Errorf("reject body is %d bytes", len(env.Body))
			}
		})
	}
	t.Run("handler error", func(t *testing.T) {
		c, _ := start(t, handlerFunc(func(context.Context, Observation) error { return fmt.Errorf("%w: %s", errNo, long) }))
		if err := c.Report(t.Context(), Observation{QName: "a.test."}); !errors.Is(err, ErrRejected) {
			t.Errorf("err = %v, want ErrRejected", err)
		}
	})
}

func TestListenRefusals(t *testing.T) {
	t.Run("nil handler", func(t *testing.T) {
		if _, err := Listen(ServerConfig{Path: shortPath(t)}); err == nil {
			t.Error("want error")
		}
	})
	t.Run("live server", func(t *testing.T) {
		path := shortPath(t)
		listen(t, path, handlerFunc(ack), self())
		_, err := Listen(ServerConfig{Path: path, Handler: handlerFunc(ack)})
		if !errors.Is(err, ErrAlreadyRunning) {
			t.Errorf("err = %v, want ErrAlreadyRunning", err)
		}
		if err := NewClient(path, self()).Report(t.Context(), Observation{QName: "a.test."}); err != nil {
			t.Errorf("first server broken: %v", err)
		}
	})
	t.Run("regular file", func(t *testing.T) {
		path := shortPath(t)
		if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := Listen(ServerConfig{Path: path, Handler: handlerFunc(ack)})
		if !errors.Is(err, ErrNotSocket) {
			t.Errorf("err = %v, want ErrNotSocket", err)
		}
		if b, _ := os.ReadFile(path); string(b) != "keep" {
			t.Error("file was changed")
		}
	})
	t.Run("directory", func(t *testing.T) {
		path := shortPath(t)
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := Listen(ServerConfig{Path: path, Handler: handlerFunc(ack)}); !errors.Is(err, ErrNotSocket) {
			t.Errorf("err = %v, want ErrNotSocket", err)
		}
		if fi, err := os.Stat(path); err != nil || !fi.IsDir() {
			t.Error("directory was removed")
		}
	})
}

func TestListenReplacesStaleSocket(t *testing.T) {
	path := shortPath(t)
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false) //nolint:forcetypeassert // unix listener
	_ = ln.Close()                                 // leaves a dead socket file, as a crash does
	listen(t, path, handlerFunc(ack), self())
	if err := NewClient(path, self()).Report(t.Context(), Observation{QName: "a.test."}); err != nil {
		t.Error(err)
	}
}

func TestOldServerCloseKeepsNewerSocket(t *testing.T) {
	path := shortPath(t)
	old, err := Listen(ServerConfig{Path: path, Handler: handlerFunc(ack), AllowedUIDs: []uint32{self()}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil { // an operator displaces the file
		t.Fatal(err)
	}
	var lc net.ListenConfig
	newer, err := lc.Listen(t.Context(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = newer.Close() })
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(path); err != nil || fi.Mode().Type() != os.ModeSocket {
		t.Errorf("old server's Close removed the newer socket: %v", err)
	}
}

func TestLockReleasedOnCloseAndLockFileKept(t *testing.T) {
	path := shortPath(t)
	srv, err := Listen(ServerConfig{Path: path, Handler: handlerFunc(ack)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(ServerConfig{Path: path, Handler: handlerFunc(ack)}); !errors.Is(err, ErrAlreadyRunning) {
		t.Errorf("second Listen: err = %v, want ErrAlreadyRunning", err)
	}
	_ = srv.Close()
	if _, err := os.Lstat(path + ".lock"); err != nil {
		t.Errorf("lock file was removed: %v", err)
	}
	again, err := Listen(ServerConfig{Path: path, Handler: handlerFunc(ack)})
	if err != nil {
		t.Fatalf("Listen after Close: %v", err)
	}
	_ = again.Close()
}

// TestListenSaturatedLiveServer: a live server with a full accept queue
// refuses connects on darwin, like a dead socket. Listen must still refuse
// to take the path.
func TestListenSaturatedLiveServer(t *testing.T) {
	release := make(chan struct{})
	path := shortPath(t)
	listen(t, path, handlerFunc(func(ctx context.Context, _ Observation) error {
		select {
		case <-release:
		case <-ctx.Done():
		}
		return nil
	}), self())
	var conns []net.Conn
	t.Cleanup(func() {
		close(release)
		for _, c := range conns {
			_ = c.Close()
		}
	})
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	req := frameOf(`{"v":1,"type":"observe","body":{"qname":"a.test.","timeout_ms":30000}}`)
	saturated := false
	for range 6000 {
		d := net.Dialer{Timeout: 200 * time.Millisecond}
		c, err := d.DialContext(t.Context(), "unix", path)
		if err != nil {
			saturated = true
			break
		}
		_, _ = c.Write(req)
		conns = append(conns, c)
	}
	if !saturated {
		t.Skip("accept queue never filled")
	}
	_, err = Listen(ServerConfig{Path: path, Handler: handlerFunc(ack)})
	if !errors.Is(err, ErrAlreadyRunning) {
		t.Errorf("err = %v, want ErrAlreadyRunning", err)
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) {
		t.Errorf("the live server's socket was replaced: %v", err)
	}
}

func TestServeTwiceFails(t *testing.T) {
	path := shortPath(t)
	srv := listen(t, path, handlerFunc(ack), self())
	for srv.serveStarted() == false {
		time.Sleep(time.Millisecond) // waits for the first Serve goroutine to start
	}
	if err := srv.Serve(t.Context()); err == nil {
		t.Error("second Serve returned nil")
	}
	if err := NewClient(path, self()).Report(t.Context(), Observation{QName: "a.test."}); err != nil {
		t.Errorf("first Serve was disturbed: %v", err)
	}
}

func (s *Server) serveStarted() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.serving
}

// fakeListener fails Accept a fixed number of times, then blocks until Close.
type fakeListener struct {
	failures int
	calls    chan struct{}
	done     chan struct{}
	once     sync.Once
	closes   atomic.Int32
}

var errEMFILE = errors.New("accept: too many open files")

func (f *fakeListener) Accept() (net.Conn, error) {
	select {
	case f.calls <- struct{}{}:
	case <-f.done:
		return nil, net.ErrClosed
	}
	if f.failures > 0 {
		f.failures--
		return nil, errEMFILE
	}
	<-f.done
	return nil, net.ErrClosed
}

func (f *fakeListener) Close() error {
	f.closes.Add(1)
	f.once.Do(func() { close(f.done) })
	return nil
}

func (f *fakeListener) Addr() net.Addr { return &net.UnixAddr{Net: "unix"} }

func TestAcceptErrorsDoNotStopServe(t *testing.T) {
	fl := &fakeListener{failures: 3, calls: make(chan struct{}), done: make(chan struct{})}
	srv := newServer(fl, ServerConfig{Handler: handlerFunc(ack)})
	served := make(chan error, 1)
	go func() { served <- srv.Serve(t.Context()) }()

	for i := range 4 { // three failures, then the retry that blocks
		select {
		case <-fl.calls:
		case err := <-served:
			t.Fatalf("Serve returned %v after %d Accept calls", err, i)
		case <-time.After(5 * time.Second):
			t.Fatal("Accept was not retried")
		}
	}
	if fl.closes.Load() != 0 {
		t.Error("listener was closed after a transient Accept error")
	}
	_ = srv.Close()
	select {
	case err := <-served:
		if err != nil {
			t.Errorf("Serve = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after Close")
	}
}

// TestHelperReport is the client side of TestCrossUID. It runs in a child
// process that the test starts under another uid. It prints one marker line:
// ACKED, UNAVAILABLE, or OTHER with the error.
func TestHelperReport(t *testing.T) {
	path := os.Getenv("IPC_HELPER_PATH")
	if path == "" {
		t.Skip("child process only")
	}
	err := NewClient(path, 0).Report(t.Context(), Observation{QName: "x.test."})
	switch {
	case err == nil:
		fmt.Println("RESULT ACKED")
	case errors.Is(err, ErrUnavailable):
		fmt.Println("RESULT UNAVAILABLE")
	default:
		fmt.Println("RESULT OTHER", err)
	}
}

// TestCrossUID checks the kernel uid check with a real second uid. It needs
// root: the server runs as root and the client as uid 65534.
func TestCrossUID(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to run the client under another uid")
	}
	const nobody = 65534
	dir, err := os.MkdirTemp("", "ipc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // the other uid must reach the socket and the binary copy
		t.Fatal(err)
	}
	bin := copyTestBinary(t, dir)
	tests := []struct {
		allowed uint32
		want    string
	}{{0, "RESULT UNAVAILABLE"}, {nobody, "RESULT ACKED"}}
	for _, tc := range tests {
		t.Run(fmt.Sprintf("allowed=%d", tc.allowed), func(t *testing.T) {
			path := filepath.Join(dir, fmt.Sprintf("s%d.sock", tc.allowed))
			listen(t, path, handlerFunc(ack), tc.allowed)
			if err := os.Chmod(path, 0o666); err != nil { //nolint:gosec // the uid check is under test, not the file mode
				t.Fatal(err)
			}
			cmd := exec.CommandContext(t.Context(), bin, "-test.run=^TestHelperReport$", "-test.v")
			cmd.Env = append(os.Environ(), "IPC_HELPER_PATH="+path)
			cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: nobody, Gid: nobody}}
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("child failed: %v\n%s", err, out)
			}
			var result string
			for line := range strings.SplitSeq(string(out), "\n") {
				if strings.HasPrefix(line, "RESULT ") {
					result = strings.Join(strings.Fields(line)[:2], " ")
				}
			}
			if result != tc.want {
				t.Errorf("result = %q, want %q\n%s", result, tc.want, out)
			}
		})
	}
}

// copyTestBinary copies the running test binary into dir. The go-build
// directory of the original is private, so another uid cannot execute it.
func copyTestBinary(t *testing.T, dir string) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "ipc.test")
	if err := os.WriteFile(bin, data, 0o755); err != nil { //nolint:gosec // the other uid must execute it
		t.Fatal(err)
	}
	return bin
}

func TestCloseCancelsHandlersAndServeReturns(t *testing.T) {
	path := shortPath(t)
	started := make(chan struct{}, 3)
	var cancelled atomic.Int32
	srv, err := Listen(ServerConfig{Path: path, AllowedUIDs: []uint32{self()}, Handler: handlerFunc(
		func(ctx context.Context, _ Observation) error {
			started <- struct{}{}
			<-ctx.Done()
			cancelled.Add(1)
			return ctx.Err()
		})})
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- srv.Serve(context.Background()) }()
	c := NewClient(path, self())
	results := make(chan error, 3)
	for range 3 {
		go func() {
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			results <- c.Report(ctx, Observation{QName: "a.test."})
		}()
	}
	for range 3 {
		<-started
	}
	_ = srv.Close()
	select {
	case err := <-served:
		if err != nil {
			t.Errorf("Serve = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after Close")
	}
	if cancelled.Load() != 3 {
		t.Errorf("%d handlers cancelled, want 3", cancelled.Load())
	}
	for range 3 {
		if err := <-results; err == nil {
			t.Error("Report returned nil after Close")
		}
	}
}

func TestTimeoutBounds(t *testing.T) {
	_, path := start(t, handlerFunc(ack))
	tests := map[string]string{"0": typeReject, "-1": typeReject, "1": typeAck, "30000": typeAck, "30001": typeReject}
	for ms, want := range tests {
		t.Run(ms, func(t *testing.T) {
			env, _ := rawExchange(t, path, frameOf(`{"v":1,"type":"observe","body":{"qname":"a.test.","timeout_ms":`+ms+`}}`))
			if env.Type != want {
				t.Errorf("type = %q, want %q", env.Type, want)
			}
		})
	}
}

// TestTrickleCannotExtendDeadline sends one byte every 50 ms. The server must
// close the connection at its one connection deadline anyway.
func TestTrickleCannotExtendDeadline(t *testing.T) {
	path := shortPath(t)
	srv, err := Listen(ServerConfig{Path: path, Handler: handlerFunc(ack), AllowedUIDs: []uint32{self()}})
	if err != nil {
		t.Fatal(err)
	}
	srv.connTimeout = 200 * time.Millisecond // set before Serve starts
	served := make(chan struct{})
	go func() { _ = srv.Serve(t.Context()); close(served) }()
	t.Cleanup(func() { _ = srv.Close(); <-served })

	var d net.Dialer
	conn, err := d.DialContext(t.Context(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	begin := time.Now()
	_, _ = conn.Write([]byte{0, 0, 1, 0}) // a 256-byte body follows, slowly
	closed := make(chan time.Duration, 1)
	go func() {
		var b [1]byte
		_, _ = conn.Read(b[:])
		closed <- time.Since(begin)
	}()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case got := <-closed:
			if got < 150*time.Millisecond || got > time.Second {
				t.Errorf("closed after %v, want about 200ms", got)
			}
			return
		case <-tick.C:
			_, _ = conn.Write([]byte{' '})
		case <-time.After(3 * time.Second):
			t.Fatal("connection still open after 3s of trickling")
		}
	}
}

// TestCrossUIDImpostor: a server that runs as another uid owns the
// path. A client that expects root must not accept its ack. Root only.
func TestCrossUIDImpostor(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to run the impostor under another uid")
	}
	const nobody = 65534
	dir, err := os.MkdirTemp("", "ipc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o777); err != nil { //nolint:gosec // the other uid must bind here and reach the binary copy
		t.Fatal(err)
	}
	path := filepath.Join(dir, "imp.sock")
	stdin := startImpostor(t, copyTestBinary(t, dir), path, nobody)
	defer func() { _ = stdin.Close() }() // ends the impostor

	// The fixture is sound: the same ack is trusted when the uid matches.
	if err := NewClient(path, nobody).Report(t.Context(), Observation{QName: "a.test."}); err != nil {
		t.Fatalf("expecting uid %d: %v (fixture broken)", nobody, err)
	}
	err = NewClient(path, 0).Report(t.Context(), Observation{QName: "a.test."})
	if !errors.Is(err, ErrUnavailable) {
		t.Errorf("err = %v, want ErrUnavailable", err)
	}
}

func startImpostor(t *testing.T, bin, path string, uid uint32) io.WriteCloser {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), bin, "-test.run=^TestHelperImpostor$", "-test.v")
	cmd.Env = append(os.Environ(), "IPC_HELPER_IMPOSTOR="+path)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid}}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stdin.Close(); _ = cmd.Wait() })
	sc := bufio.NewScanner(out)
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "LISTENING") {
			return stdin
		}
	}
	t.Fatal("impostor did not start")
	return nil
}

// TestHelperImpostor is a fake server that acks every request. It runs only
// in a child process under another uid.
func TestHelperImpostor(t *testing.T) {
	path := os.Getenv("IPC_HELPER_IMPOSTOR")
	if path == "" {
		t.Skip("child process only")
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "unix", path)
	if err != nil {
		fmt.Println("CHILD-ERR", err)
		return
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				if _, err := readFrame(c); err == nil {
					_, _ = c.Write(frameOf(`{"v":1,"type":"ack"}`))
				}
			}()
		}
	}()
	fmt.Println("LISTENING")
	_, _ = io.Copy(io.Discard, os.Stdin) // until the parent closes stdin
	_ = ln.Close()
}
