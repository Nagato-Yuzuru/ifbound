package ipc_test

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/ipc"
)

// shortSocket returns a socket path short enough for sun_path.
func shortSocket(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ipo")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	return filepath.Join(dir, "s")
}

type recordedCall struct {
	obs      ipc.Observation
	deadline time.Duration // the time left on the handler ctx at entry
}

// recordingHandler records each observation. When gate is not nil, Observe
// waits for it or for ctx.
type recordingHandler struct {
	mu      sync.Mutex
	calls   []recordedCall
	entered chan struct{}
	gate    chan struct{}
	active  atomic.Int32
	peak    atomic.Int32
	probes  chan string
	// deaf makes Observe ignore its ctx and wait for gate only.
	deaf bool
	// protected is the flag of each ack.
	protected bool
}

func (h *recordingHandler) Observe(ctx context.Context, o ipc.Observation) (ipc.Ack, error) {
	if err := h.observe(ctx, o); err != nil {
		return ipc.Ack{}, err
	}
	return ipc.Ack{Protected: h.protected}, nil
}

func (h *recordingHandler) observe(ctx context.Context, o ipc.Observation) error {
	dl, _ := ctx.Deadline()
	h.mu.Lock()
	h.calls = append(h.calls, recordedCall{obs: o, deadline: time.Until(dl)})
	h.mu.Unlock()
	n := h.active.Add(1)
	defer h.active.Add(-1)
	for {
		p := h.peak.Load()
		if n <= p || h.peak.CompareAndSwap(p, n) {
			break
		}
	}
	if h.entered != nil {
		h.entered <- struct{}{}
	}
	if h.gate == nil {
		return nil
	}
	if h.deaf {
		<-h.gate // no reply before the client gives up
		return nil
	}
	select {
	case <-h.gate:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (h *recordingHandler) ProbeSeen(qname string) {
	if h.probes != nil {
		h.probes <- qname
	}
}

func serveRecording(t *testing.T, h *recordingHandler) string {
	t.Helper()
	path := shortSocket(t)
	uid := uint32(os.Getuid()) //nolint:gosec // a uid fits in uint32
	srv, err := ipc.Listen(ipc.ServerConfig{Path: path, Handler: h, Probes: h, AllowedUIDs: []uint32{uid}})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	return path
}

// rawRoundTrip sends one frame with the given JSON payload, as a plugin of
// another version would, and returns the reply payload.
func rawRoundTrip(t *testing.T, path string, payload []byte) map[string]json.RawMessage {
	t.Helper()
	var dialer net.Dialer
	conn, err := dialer.DialContext(t.Context(), "unix", path)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }() //nolint:errcheck // the server closes first; this call only frees the descriptor
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	frame := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(frame, uint32(len(payload))) //nolint:gosec // test payloads are small
	copy(frame[4:], payload)
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("write: %v", err)
	}
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		t.Fatalf("read reply header: %v", err)
	}
	body := make([]byte, binary.BigEndian.Uint32(hdr[:]))
	if _, err := io.ReadFull(conn, body); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	var reply map[string]json.RawMessage
	if err := json.Unmarshal(body, &reply); err != nil {
		t.Fatalf("reply %q: %v", body, err)
	}
	return reply
}

func observeFrame(version int, extra string) []byte {
	body := `{"qname":"www.example.com","addrs":["192.0.2.1","::ffff:198.51.100.7","2001:db8::1"],"ttl_s":300,"timeout_ms":5000` + extra + `}`
	return []byte(`{"v":` + strconv.Itoa(version) + `,"type":"observe","body":` + body + `}`)
}

// A report of this version with an unknown field, such as the "aliases"
// that the plugin of version 2 sent, is acked and gives the handler the
// same observation as the report without it.
func TestUnknownObserveFieldIsIgnored(t *testing.T) {
	h := &recordingHandler{}
	path := serveRecording(t, h)
	want := ipc.Observation{
		QName: "www.example.com",
		Addrs: []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.7"), netip.MustParseAddr("2001:db8::1")},
		TTL:   300 * time.Second,
	}
	extras := map[string]string{
		"none":              ``,
		"old aliases":       `,"aliases":[{"name":"cdn.example.net","ttl_s":60},{"name":"Edge.Example.ORG.","ttl_s":0}]`,
		"empty aliases":     `,"aliases":[]`,
		"null aliases":      `,"aliases":null`,
		"invalid aliases":   `,"aliases":[{"name":"","ttl_s":-1}]`,
		"33 aliases":        `,"aliases":[` + manyAliasesJSON(33) + `]`,
		"aliases string":    `,"aliases":"x"`,
		"other future key":  `,"future":{"a":[1,2,{"b":null}]}`,
		"aliases and other": `,"aliases":[{"name":"a.example"}],"zzz":true`,
	}
	for name, extra := range extras {
		t.Run(name, func(t *testing.T) {
			h.mu.Lock()
			h.calls = nil
			h.mu.Unlock()
			reply := rawRoundTrip(t, path, observeFrame(3, extra))
			if string(reply["type"]) != `"ack"` {
				t.Fatalf("reply = %s, want an ack", reply)
			}
			h.mu.Lock()
			defer h.mu.Unlock()
			if len(h.calls) != 1 {
				t.Fatalf("handler calls = %d, want 1", len(h.calls))
			}
			got := h.calls[0]
			if got.obs.QName != want.QName || got.obs.TTL != want.TTL || !slices.Equal(got.obs.Addrs, want.Addrs) {
				t.Errorf("observation = %+v, want %+v", got.obs, want)
			}
			if got.deadline <= 4*time.Second || got.deadline > 5*time.Second {
				t.Errorf("handler deadline = %v, want the 5 s that the old plugin asked for", got.deadline)
			}
		})
	}
}

// The plugin of version 2 does not read the protected flag, so it would
// pass the aliases of a protected name to the client. The daemon refuses
// its reports, and the reply has version 3, which that plugin refuses
// too. Both sides fail closed, and the plugin gives SERVFAIL.
func TestReportOfVersion2IsRefused(t *testing.T) {
	h := &recordingHandler{protected: true}
	path := serveRecording(t, h)
	for name, extra := range map[string]string{
		"without aliases": ``,
		"with aliases":    `,"aliases":[{"name":"cdn.example.net","ttl_s":60}]`,
	} {
		t.Run(name, func(t *testing.T) {
			reply := rawRoundTrip(t, path, observeFrame(2, extra))
			if string(reply["type"]) != `"reject"` || string(reply["v"]) != "3" {
				t.Errorf("reply = %s, want a reject of version 3", reply)
			}
		})
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.calls) != 0 {
		t.Errorf("handler calls = %d, want 0", len(h.calls))
	}
}

// The daemon of version 2 replies to a report of version 3 with a reject
// of version 2. Report gives a protocol error, never an ack.
func TestReplyOfVersion2DaemonIsAnError(t *testing.T) {
	for name, reply := range map[string]string{
		"reject": `{"v":2,"type":"reject","body":{"reason":"unsupported version 3"}}`,
		"ack":    `{"v":2,"type":"ack"}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := fakeServer(t, func(map[string]json.RawMessage) string { return reply })
			c := ipc.NewClient(path, uint32(os.Getuid())) //nolint:gosec // a uid fits in uint32
			ack, err := c.Report(t.Context(), ipc.Observation{QName: "www.example.com."})
			if !errors.Is(err, ipc.ErrProtocol) || ack.Protected {
				t.Errorf("Report = %+v, %v; want ErrProtocol", ack, err)
			}
		})
	}
}

func manyAliasesJSON(n int) string {
	out := ""
	for i := range n {
		if i > 0 {
			out += ","
		}
		out += `{"name":"a` + string(rune('a'+i%26)) + `.example","ttl_s":1}`
	}
	return out
}

// A Report whose ctx has no deadline waits 2 s for the ack, and asks
// the server for that deadline.
func TestReportDefaultTimeoutIsTwoSeconds(t *testing.T) {
	t.Parallel()
	h := &recordingHandler{gate: make(chan struct{}), deaf: true}
	path := serveRecording(t, h)
	defer close(h.gate)
	c := ipc.NewClient(path, uint32(os.Getuid())) //nolint:gosec // a uid fits in uint32
	start := time.Now()
	_, err := c.Report(context.Background(), ipc.Observation{QName: "example.com", Addrs: []netip.Addr{netip.MustParseAddr("192.0.2.1")}})
	elapsed := time.Since(start)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Report = %v, want DeadlineExceeded", err)
	}
	if elapsed < 1900*time.Millisecond || elapsed > 2600*time.Millisecond {
		t.Errorf("Report returned after %v, want about 2 s", elapsed)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.calls) != 1 {
		t.Fatalf("handler calls = %d, want 1", len(h.calls))
	}
	if d := h.calls[0].deadline; d < 1500*time.Millisecond || d > 2*time.Second {
		t.Errorf("handler deadline = %v, want at most 2 s and close to it", d)
	}
}

// With every report slot of a Client held, a probe still reaches the
// daemon, and the reports never exceed their slots.
func TestProbeGetsThroughWhileReportSlotsAreFull(t *testing.T) {
	t.Parallel()
	const reports = 40 // more than the 32 report slots
	h := &recordingHandler{
		gate:    make(chan struct{}),
		entered: make(chan struct{}, reports),
		probes:  make(chan string, 1),
	}
	path := serveRecording(t, h)
	c := ipc.NewClient(path, uint32(os.Getuid())) //nolint:gosec // a uid fits in uint32
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	errs := make(chan error, reports)
	for range reports {
		wg.Go(func() {
			errs <- errOf(c.Report(ctx, ipc.Observation{QName: "example.com", Addrs: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}))
		})
	}
	for i := range 32 {
		select {
		case <-h.entered:
		case <-time.After(10 * time.Second):
			t.Fatalf("only %d reports reached the handler, want 32", i)
		}
	}
	// No 33rd report gets in while the 32 wait.
	select {
	case <-h.entered:
		t.Fatal("a 33rd report reached the handler while 32 were in flight")
	case <-time.After(100 * time.Millisecond):
	}

	pctx, pcancel := context.WithTimeout(context.Background(), time.Second)
	defer pcancel()
	if err := c.ReportProbe(pctx, "ifbound-probe-0123456789abcdef.example.com"); err != nil {
		t.Fatalf("ReportProbe with every report slot held = %v, want nil", err)
	}
	select {
	case got := <-h.probes:
		if got != "ifbound-probe-0123456789abcdef.example.com" {
			t.Errorf("ProbeSeen(%q)", got)
		}
	default:
		t.Error("ReportProbe acked, but ProbeSeen did not run")
	}

	close(h.gate)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("Report = %v, want nil after the gate opened", err)
		}
	}
	if p := h.peak.Load(); p > 32 {
		t.Errorf("peak in-flight reports = %d, want at most 32", p)
	}
}

// fakeServer accepts one connection at a new socket, reads one request,
// and writes the payload that reply returns for its body.
func fakeServer(t *testing.T, reply func(body map[string]json.RawMessage) string) string {
	t.Helper()
	path := shortSocket(t)
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := ln.Close(); err != nil {
			t.Error(err)
		}
	})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }() //nolint:errcheck // the peer may have closed first
		var hdr [4]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return
		}
		payload := make([]byte, binary.BigEndian.Uint32(hdr[:]))
		if _, err := io.ReadFull(conn, payload); err != nil {
			return
		}
		var env struct {
			Body map[string]json.RawMessage `json:"body"`
		}
		if err := json.Unmarshal(payload, &env); err != nil {
			t.Errorf("decoding request: %v", err)
			return
		}
		out := []byte(reply(env.Body))
		frame := binary.BigEndian.AppendUint32(nil, uint32(len(out))) //nolint:gosec // test replies are small
		_, _ = conn.Write(append(frame, out...))                      //nolint:errcheck // the client side asserts on a failed reply
	}()
	return path
}

// The observe body that a Client sends has the qname, the addresses, the
// TTL and the timeout, and no other key.
func TestReportBodyHasOnlyKnownKeys(t *testing.T) {
	got := make(chan map[string]json.RawMessage, 1)
	path := fakeServer(t, func(body map[string]json.RawMessage) string {
		got <- body
		return `{"v":3,"type":"ack","body":{"protected":false}}`
	})
	c := ipc.NewClient(path, uint32(os.Getuid())) //nolint:gosec // a uid fits in uint32
	if _, err := c.Report(context.Background(), ipc.Observation{QName: "www.example.com.", Addrs: []netip.Addr{netip.MustParseAddr("192.0.2.7")}, TTL: time.Minute}); err != nil {
		t.Fatalf("Report = %v", err)
	}
	body := <-got
	keys := make([]string, 0, len(body))
	for k := range body {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	if want := []string{"addrs", "qname", "timeout_ms", "ttl_s"}; !slices.Equal(keys, want) {
		t.Errorf("observe body keys = %q, want %q", keys, want)
	}
}

// errOf drops the ack of a Report, for a test that checks only the error.
func errOf(_ ipc.Ack, err error) error { return err }
