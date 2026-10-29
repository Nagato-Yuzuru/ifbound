package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"
)

// fakeControl answers Status with status or statusErr, and Apply with the
// status or applyErr. It records every cfg that reaches Apply and the
// deadline of every handler context. With block set, each handler waits
// for its context to end and returns the context error.
type fakeControl struct {
	status    StatusReport
	statusErr error
	applyErr  error
	block     bool

	mu        sync.Mutex
	statuses  int
	applied   [][]byte
	deadlines []time.Time
}

func (f *fakeControl) Status(ctx context.Context) (StatusReport, error) {
	f.record(ctx, nil)
	if f.block {
		<-ctx.Done()
		return StatusReport{}, ctx.Err()
	}
	return f.status, f.statusErr
}

func (f *fakeControl) Apply(ctx context.Context, cfg []byte) (StatusReport, error) {
	f.record(ctx, cfg)
	if f.block {
		<-ctx.Done()
		return StatusReport{}, ctx.Err()
	}
	if f.applyErr != nil {
		return StatusReport{}, f.applyErr
	}
	return f.status, nil
}

func (f *fakeControl) record(ctx context.Context, cfg []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	dl, _ := ctx.Deadline()
	f.deadlines = append(f.deadlines, dl)
	if cfg == nil {
		f.statuses++
		return
	}
	f.applied = append(f.applied, cfg)
}

func (f *fakeControl) appliedConfigs() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.applied
}

func (f *fakeControl) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.statuses + len(f.applied)
}

func (f *fakeControl) lastDeadline() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.deadlines[len(f.deadlines)-1]
}

// serve runs srv until the test ends. The returned stop closes srv and
// waits for Serve to return; all handlers have returned then.
func serve(t *testing.T, srv *Server) (stop func()) {
	t.Helper()
	served := make(chan error, 1)
	go func() { served <- srv.Serve(context.Background()) }()
	stop = sync.OnceFunc(func() {
		_ = srv.Close() //nolint:errcheck // Serve's result is checked below
		select {
		case err := <-served:
			if err != nil {
				t.Errorf("Serve returned %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Serve did not return after Close")
		}
	})
	t.Cleanup(stop)
	return stop
}

func newStatusServer(t *testing.T, path string, h StatusHandler, logger *slog.Logger) *Server {
	t.Helper()
	srv, err := ListenStatus(StatusConfig{Path: path, Handler: h, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

func newAdminServer(t *testing.T, path string, h ControlHandler, logger *slog.Logger, uids ...uint32) *Server {
	t.Helper()
	srv, err := ListenAdmin(AdminConfig{Path: path, Handler: h, UIDs: uids, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

func listenStatus(t *testing.T, path string, h StatusHandler) {
	t.Helper()
	serve(t, newStatusServer(t, path, h, nil))
}

func listenAdmin(t *testing.T, path string, h ControlHandler, uids ...uint32) {
	t.Helper()
	serve(t, newAdminServer(t, path, h, nil, uids...))
}

func fullStatus() StatusReport {
	return StatusReport{
		Daemon:        "v1.2.3",
		State:         StateDegraded,
		Reasons:       []string{"resolver conflict on en0"},
		Warnings:      []Warning{{Source: "config", Text: "retain changes only after a restart"}},
		Policies:      []PolicyCount{{Name: "work", Addrs: 3}, {Name: "home", Addrs: 0}},
		RetainRestart: true,
		// The sha256 of the empty input.
		Config: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}
}

func TestStatusRoundTripOnBothSockets(t *testing.T) {
	want := fullStatus()
	status, admin := shortPath(t), shortPath(t)
	listenStatus(t, status, &fakeControl{status: want})
	listenAdmin(t, admin, &fakeControl{status: want}, self())
	for _, path := range []string{status, admin} {
		got, err := NewControlClient(path, self()).Status(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("Status = %+v, want %+v", got, want)
		}
	}
}

func TestAdminApplyRoundTrip(t *testing.T) {
	path := shortPath(t)
	want := fullStatus()
	h := &fakeControl{status: want}
	listenAdmin(t, path, h, self())
	cfg := []byte("[[policy]]\nname = \"work\"\n\xff\x00") // not UTF-8: the bytes must arrive as sent

	got, err := NewControlClient(path, self()).Apply(t.Context(), cfg)

	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Apply = %+v, want %+v", got, want)
	}
	if applied := h.appliedConfigs(); len(applied) != 1 || string(applied[0]) != string(cfg) {
		t.Errorf("handler got %q, want one call with %q", applied, cfg)
	}
}

func rejectReason(t *testing.T, err error) string {
	t.Helper()
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("err = %v, want ErrRejected", err)
	}
	return strings.TrimPrefix(err.Error(), ErrRejected.Error()+": ")
}

func TestAdminRejectionCarriesTheWholeErrorText(t *testing.T) {
	// A parse error names the bad value last.
	parseErr := `"policy[0].to[0]": domain must be ASCII: ` + strings.Repeat("a", 2000) + `é"`
	huge := strings.Repeat("b", maxAdminReasonLen+1)
	for _, tc := range []struct {
		name, text, want string
	}{
		{"long parse error", parseErr, parseErr},
		{"longer than the bound", huge, huge[:maxAdminReasonLen-len(cutMarker)] + cutMarker},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := shortPath(t)
			listenAdmin(t, path, &fakeControl{applyErr: errors.New(tc.text)}, self())

			_, err := NewControlClient(path, self()).Apply(t.Context(), []byte("x"))

			if got := rejectReason(t, err); got != tc.want {
				t.Errorf("reason of %d bytes ends in %q, want %d bytes", len(got), got[max(len(got)-20, 0):], len(tc.want))
			}
		})
	}
}

func TestStatusSocketCutsTheErrorTextVisibly(t *testing.T) {
	path := shortPath(t)
	text := strings.Repeat("c", maxReasonLen+1)
	listenStatus(t, path, &fakeControl{statusErr: errors.New(text)})

	_, err := NewControlClient(path, self()).Status(t.Context())

	if got, want := rejectReason(t, err), text[:maxReasonLen-len(cutMarker)]+cutMarker; got != want {
		t.Errorf("reason = %q, want %q", got, want)
	}
}

// TestReportReasonCutIsUnchanged: the control sockets mark a cut, but the
// report socket keeps its reply as before: the first 256 bytes, no marker.
func TestReportReasonCutIsUnchanged(t *testing.T) {
	text := strings.Repeat("d", maxReasonLen+1)
	c, _ := start(t, handlerFunc(func(context.Context, Observation) error { return errors.New(text) }))

	_, err := c.Report(t.Context(), Observation{QName: "a.test."})

	if got, want := rejectReason(t, err), text[:256]; got != want {
		t.Errorf("reason = %q, want %q", got, want)
	}
}

func TestAdminServesOnlyListedUIDs(t *testing.T) {
	for _, tc := range []struct {
		name string
		uids []uint32
	}{
		{"other uid", []uint32{self() + 1}}, // as root, this shows that root has no bypass
		{"empty list", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := shortPath(t)
			h := &fakeControl{status: fullStatus()}
			listenAdmin(t, path, h, tc.uids...)
			c := NewControlClient(path, self())

			_, applyErr := c.Apply(t.Context(), []byte("x"))
			_, statusErr := c.Status(t.Context())

			if !errors.Is(applyErr, ErrUnavailable) || !errors.Is(statusErr, ErrUnavailable) {
				t.Errorf("Apply = %v, Status = %v; want ErrUnavailable", applyErr, statusErr)
			}
			if n := h.calls(); n != 0 {
				t.Errorf("%d requests reached the handler", n)
			}
		})
	}
}

func TestStatusSocketServesNoApply(t *testing.T) {
	path := shortPath(t)
	h := &fakeControl{status: fullStatus()}
	listenStatus(t, path, h)

	_, err := NewControlClient(path, self()).Apply(t.Context(), []byte("x"))

	if reason := rejectReason(t, err); !strings.Contains(reason, `unknown message type "apply"`) {
		t.Errorf("reason = %q, want an unknown message type", reason)
	}
	if len(h.appliedConfigs()) != 0 {
		t.Error("Apply reached the handler through the status socket")
	}
}

func applyFrame(deadline time.Time) []byte {
	return frameOf(fmt.Sprintf(`{"v":1,"type":"apply","body":{"config":"eA==","deadline_unix_ms":%d}}`, deadline.UnixMilli()))
}

func TestApplyIsNotStartedAfterItsDeadline(t *testing.T) {
	path := shortPath(t)
	h := &fakeControl{status: fullStatus()}
	listenAdmin(t, path, h, self())
	tests := map[string][]byte{
		"deadline passed":              applyFrame(time.Now().Add(-time.Second)),
		"deadline in the reply margin": applyFrame(time.Now().Add(controlReplyMargin / 2)),
		"no deadline":                  frameOf(`{"v":1,"type":"apply","body":{"config":"eA=="}}`),
		"zero deadline":                frameOf(`{"v":1,"type":"apply","body":{"config":"eA==","deadline_unix_ms":0}}`),
	}
	for name, frame := range tests {
		t.Run(name, func(t *testing.T) {
			env, _ := rawExchange(t, path, frame)
			if env.Type != typeReject {
				t.Errorf("reply %+v, want a reject", env)
			}
		})
	}
	if n := len(h.appliedConfigs()); n != 0 {
		t.Fatalf("%d late requests reached Apply", n)
	}
	// The fixture is sound: a deadline in time reaches Apply.
	if env, _ := rawExchange(t, path, applyFrame(time.Now().Add(3*time.Second))); env.Type != typeAck {
		t.Errorf("reply %+v, want an ack", env)
	}
}

// TestTimedOutApplyIsNotAppliedLater: the client writes its request while
// the connection waits in the backlog, and gives up. When the server
// accepts the connection later, it must not apply the config.
func TestTimedOutApplyIsNotAppliedLater(t *testing.T) {
	path := shortPath(t)
	h := &fakeControl{status: fullStatus()}
	srv := newAdminServer(t, path, h, nil, self())
	// One slot serves the connections in order, so the late Apply is done
	// when the Status below returns.
	srv.slots = make(chan struct{}, 1) // set before Serve starts
	serve(t, srv)
	var d net.Dialer
	hold, err := d.DialContext(t.Context(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	c := NewControlClient(path, self())

	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	_, applyErr := c.Apply(ctx, []byte("late config"))
	if err := hold.Close(); err != nil {
		t.Fatal(err)
	}
	_, statusErr := c.Status(t.Context())

	if !errors.Is(applyErr, context.DeadlineExceeded) {
		t.Fatalf("Apply = %v, want DeadlineExceeded while the slot is held (fixture broken)", applyErr)
	}
	if statusErr != nil {
		t.Fatalf("Status after the slot is free: %v", statusErr)
	}
	if applied := h.appliedConfigs(); len(applied) != 0 {
		t.Errorf("the handler applied %q after the client gave up", applied)
	}
}

func TestHandlerContextLeavesTimeForTheReply(t *testing.T) {
	t.Run("blocking handler", func(t *testing.T) {
		path := shortPath(t)
		srv := newStatusServer(t, path, &fakeControl{block: true}, nil)
		srv.connTimeout = time.Second // set before Serve starts
		serve(t, srv)

		_, err := NewControlClient(path, self()).Status(t.Context())

		// A reply, not a lost connection: the client knows the outcome.
		if reason := rejectReason(t, err); !strings.Contains(reason, context.DeadlineExceeded.Error()) {
			t.Errorf("reason = %q, want the handler's context error", reason)
		}
	})
	t.Run("connection deadline", func(t *testing.T) {
		path := shortPath(t)
		h := &fakeControl{status: fullStatus()}
		listenStatus(t, path, h)
		begin := time.Now()

		if _, err := NewControlClient(path, self()).Status(t.Context()); err != nil {
			t.Fatal(err)
		}

		left := h.lastDeadline().Sub(begin)
		if want := 5*time.Second - controlReplyMargin; left > want+100*time.Millisecond || left < want-time.Second {
			t.Errorf("handler deadline %v after the call, want about %v", left, want)
		}
	})
	t.Run("client deadline", func(t *testing.T) {
		path := shortPath(t)
		h := &fakeControl{status: fullStatus()}
		listenAdmin(t, path, h, self())
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()
		client, _ := ctx.Deadline()

		if _, err := NewControlClient(path, self()).Apply(ctx, []byte("x")); err != nil {
			t.Fatal(err)
		}

		if got, want := h.lastDeadline(), client.Add(-controlReplyMargin); got.After(want) || got.Before(want.Add(-10*time.Millisecond)) {
			t.Errorf("handler deadline %v before the client deadline, want %v", client.Sub(got), controlReplyMargin)
		}
	})
}

// requestServer accepts one connection, sends the request to the test,
// and answers with a status.
func requestServer(t *testing.T) (string, <-chan envelope) {
	t.Helper()
	path := shortPath(t)
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
	got := make(chan envelope, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }() //nolint:errcheck // the peer may have closed first
		req, err := readFrame(conn)
		if err != nil {
			return
		}
		got <- req
		_, _ = conn.Write(statusFrame(`{"state":"ready"}`)) //nolint:errcheck // the client side asserts on a failed reply
	}()
	return path, got
}

func TestApplyWithoutContextDeadlineWaitsSixSeconds(t *testing.T) {
	path, got := requestServer(t)
	begin := time.Now()

	if _, err := NewControlClient(path, self()).Apply(context.Background(), []byte("x")); err != nil {
		t.Fatal(err)
	}

	var b applyBody
	if err := json.Unmarshal((<-got).Body, &b); err != nil {
		t.Fatal(err)
	}
	if wait, want := time.UnixMilli(b.DeadlineMS).Sub(begin), 6*time.Second; wait > want || wait < want-time.Second {
		t.Errorf("request deadline %v after the call, want about %v", wait, want)
	}
}

func TestApplyRefusesAnEmptyConfig(t *testing.T) {
	path := shortPath(t)
	h := &fakeControl{status: fullStatus()}
	listenAdmin(t, path, h, self())
	c := NewControlClient(path, self())
	for name, cfg := range map[string][]byte{"nil": nil, "empty": {}} {
		if _, err := c.Apply(t.Context(), cfg); !errors.Is(err, errNoConfig) {
			t.Errorf("Apply(%s) = %v, want errNoConfig", name, err)
		}
	}
	// The server refuses an empty config too.
	empty := frameOf(fmt.Sprintf(`{"v":1,"type":"apply","body":{"config":"","deadline_unix_ms":%d}}`, time.Now().Add(3*time.Second).UnixMilli()))
	if env, _ := rawExchange(t, path, empty); env.Type != typeReject {
		t.Errorf("reply to an empty config %+v, want a reject", env)
	}
	if len(h.appliedConfigs()) != 0 {
		t.Error("an empty config reached Apply")
	}
}

func TestListenRefusesNilHandler(t *testing.T) {
	path := shortPath(t)
	if _, err := ListenStatus(StatusConfig{Path: path}); !errors.Is(err, errNilHandler) {
		t.Errorf("ListenStatus = %v, want errNilHandler", err)
	}
	if _, err := ListenAdmin(AdminConfig{Path: path, UIDs: []uint32{self()}}); !errors.Is(err, errNilHandler) {
		t.Errorf("ListenAdmin = %v, want errNilHandler", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("socket file after a refusal: %v", err)
	}
}

func TestControlServerRejectsBadRequests(t *testing.T) {
	path := shortPath(t)
	h := &fakeControl{status: fullStatus()}
	listenAdmin(t, path, h, self())
	tests := map[string]string{
		"report version":   `{"v":3,"type":"status"}`,
		"unknown version":  `{"v":2,"type":"status"}`,
		"report request":   `{"v":1,"type":"observe","body":{"qname":"a.test.","timeout_ms":1000}}`,
		"unknown type":     `{"v":1,"type":"bogus"}`,
		"apply no body":    `{"v":1,"type":"apply"}`,
		"apply no config":  `{"v":1,"type":"apply","body":{"deadline_unix_ms":99999999999999}}`,
		"apply null":       `{"v":1,"type":"apply","body":{"config":null,"deadline_unix_ms":99999999999999}}`,
		"apply not base64": `{"v":1,"type":"apply","body":{"config":"!!","deadline_unix_ms":99999999999999}}`,
	}
	for name, payload := range tests {
		t.Run(name, func(t *testing.T) {
			env, conn := rawExchange(t, path, frameOf(payload))
			if env.Type != typeReject || env.Version != controlVersion {
				t.Errorf("reply %+v, want a v%d reject", env, controlVersion)
			}
			assertClosed(t, conn)
		})
	}
	if len(h.appliedConfigs()) != 0 {
		t.Error("a bad request reached Apply")
	}
}

// cannedServer accepts one connection, reads the request, and writes reply.
func cannedServer(t *testing.T, reply []byte) string {
	t.Helper()
	path := shortPath(t)
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
		_, _ = readFrame(conn)              //nolint:errcheck // the canned reply goes out whatever the request was
		_, _ = conn.Write(reply)            //nolint:errcheck // the client side asserts on a failed reply
	}()
	return path
}

func statusFrame(body string) []byte { return frameOf(`{"v":1,"type":"ack","body":` + body + `}`) }

func jsonList(item string, n int) string {
	return "[" + strings.Repeat(item+",", n-1) + item + "]"
}

func TestControlClientRejectsBadReplies(t *testing.T) {
	long := strings.Repeat("a", maxStatusText+1)
	tests := []struct {
		name  string
		reply []byte
		want  error
	}{
		{"unknown state", statusFrame(`{"state":"broken"}`), ErrProtocol},
		{"upper case state", statusFrame(`{"state":"READY"}`), ErrProtocol},
		{"no state", statusFrame(`{}`), ErrProtocol},
		{"no body", frameOf(`{"v":1,"type":"ack"}`), ErrProtocol},
		{"report version", frameOf(`{"v":3,"type":"ack","body":{"state":"ready"}}`), ErrProtocol},
		{"too many reasons", statusFrame(`{"state":"ready","reasons":` + jsonList(`"r"`, maxStatusItems+1) + `}`), ErrProtocol},
		{"too many warnings", statusFrame(`{"state":"ready","warnings":` + jsonList(`{"source":"s","text":"t"}`, maxStatusItems+1) + `}`), ErrProtocol},
		{"too many policies", statusFrame(`{"state":"ready","policies":` + jsonList(`{"name":"p","addrs":1}`, maxStatusItems+1) + `}`), ErrProtocol},
		{"long reason", statusFrame(`{"state":"ready","reasons":["` + long + `"]}`), ErrProtocol},
		{"long daemon", statusFrame(`{"state":"ready","daemon":"` + long + `"}`), ErrProtocol},
		{"long warning source", statusFrame(`{"state":"ready","warnings":[{"source":"` + long + `","text":"t"}]}`), ErrProtocol},
		{"long warning text", statusFrame(`{"state":"ready","warnings":[{"source":"s","text":"` + long + `"}]}`), ErrProtocol},
		{"long policy name", statusFrame(`{"state":"ready","policies":[{"name":"` + long + `","addrs":1}]}`), ErrProtocol},
		{"negative policy addrs", statusFrame(`{"state":"ready","policies":[{"name":"p","addrs":-1}]}`), ErrProtocol},
		{"short config hash", statusFrame(`{"state":"ready","config":"abcd"}`), ErrProtocol},
		{"config not hex", statusFrame(`{"state":"ready","config":"` + strings.Repeat("z", 64) + `"}`), ErrProtocol},
		{"rejected", frameOf(`{"v":1,"type":"reject","body":{"reason":"line 1: bad"}}`), ErrRejected},
		{"close without reply", nil, ErrUnavailable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := cannedServer(t, tc.reply)

			_, err := NewControlClient(path, self()).Status(t.Context())

			if !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestControlClientAcceptsStatusAtTheBounds(t *testing.T) {
	text := strings.Repeat("a", maxStatusText)
	reasons := make([]string, maxStatusItems)
	for i := range reasons {
		reasons[i] = "r"
	}
	want := StatusReport{Daemon: text, State: StateUnenforced, Reasons: reasons}
	path := shortPath(t)
	listenStatus(t, path, &fakeControl{status: want})

	got, err := NewControlClient(path, self()).Status(t.Context())

	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Error("a status at the bounds changed on the way")
	}
}

func repeated[T any](item T, n int) []T {
	list := make([]T, n)
	for i := range list {
		list[i] = item
	}
	return list
}

// boundsCase is a status that the server must bound, and a check of
// what the client gets.
type boundsCase struct {
	name  string
	rep   StatusReport
	check func(t *testing.T, got StatusReport)
}

func runBoundsCases(t *testing.T, tests []boundsCase) {
	t.Helper()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := shortPath(t)
			listenStatus(t, path, &fakeControl{status: tc.rep})

			got, err := NewControlClient(path, self()).Status(t.Context())

			if err != nil {
				t.Fatalf("Status = %v, want the bounded status", err)
			}
			tc.check(t, got)
		})
	}
}

func TestServerCutsStatusStrings(t *testing.T) {
	runBoundsCases(t, []boundsCase{
		{"long reason", StatusReport{Reasons: []string{strings.Repeat("r", 1100)}}, func(t *testing.T, got StatusReport) {
			if want := strings.Repeat("r", maxStatusText-len(cutMarker)) + cutMarker; got.Reasons[0] != want {
				t.Errorf("reason of %d bytes, want %d bytes that end in %q", len(got.Reasons[0]), len(want), cutMarker)
			}
		}},
		{"cut inside a rune", StatusReport{Daemon: strings.Repeat("é", 600)}, func(t *testing.T, got StatusReport) {
			if !utf8.ValidString(got.Daemon) || !strings.HasSuffix(got.Daemon, cutMarker) {
				t.Errorf("daemon %q, want valid UTF-8 that ends in %q", got.Daemon[len(got.Daemon)-10:], cutMarker)
			}
		}},
		{"invalid UTF-8", StatusReport{Reasons: []string{strings.Repeat("\xff", 400)}}, func(t *testing.T, got StatusReport) {
			if got.Reasons[0] != "\uFFFD" {
				t.Errorf("reason %q, want one U+FFFD", got.Reasons[0])
			}
		}},
	})
}

func TestServerCapsStatusLists(t *testing.T) {
	runBoundsCases(t, []boundsCase{
		{"too many warnings", StatusReport{Warnings: repeated(Warning{Source: "s", Text: "t"}, maxStatusItems+1)}, func(t *testing.T, got StatusReport) {
			if n := len(got.Warnings); n != maxStatusItems || got.Warnings[n-1].Text != "[2 more warnings]" {
				t.Errorf("%d warnings, last %+v; want %d, last counts 2", n, got.Warnings[n-1], maxStatusItems)
			}
		}},
		{"too many policies", StatusReport{Policies: repeated(PolicyCount{Name: "p", Addrs: 1}, maxStatusItems+1)}, func(t *testing.T, got StatusReport) {
			want := PolicyCount{Name: "[2 more policies]", Addrs: 2}
			if n := len(got.Policies); n != maxStatusItems || got.Policies[n-1] != want {
				t.Errorf("%d policies, last %+v; want %d, last %+v", n, got.Policies[n-1], maxStatusItems, want)
			}
		}},
		{"more than one frame", StatusReport{Reasons: repeated(strings.Repeat("x", 1000), 700)}, func(t *testing.T, got StatusReport) {
			n := len(got.Reasons)
			var left int
			if _, err := fmt.Sscanf(got.Reasons[n-1], "[%d more reasons]", &left); err != nil || n-1+left != 700 {
				t.Errorf("%d reasons, last %q; want a last item that counts the rest of 700", n, got.Reasons[n-1])
			}
		}},
		{"escapes grow the frame", StatusReport{Reasons: repeated(strings.Repeat("\x00", maxStatusText), maxStatusItems)}, func(t *testing.T, got StatusReport) {
			if len(got.Reasons) >= maxStatusItems {
				t.Errorf("%d reasons, want fewer", len(got.Reasons))
			}
		}},
	})
}

func TestCutText(t *testing.T) {
	const limit = 16
	for _, tc := range []struct{ in, want string }{
		{"", ""},
		{strings.Repeat("a", limit), strings.Repeat("a", limit)},
		{strings.Repeat("a", limit+1), strings.Repeat("a", limit-len(cutMarker)) + cutMarker},
		// "é" is 2 bytes. The cut at byte 10 falls inside one, so cutText
		// ends before it.
		{"a" + strings.Repeat("é", 8), "a" + strings.Repeat("é", 4) + cutMarker},
		{"a\xffb", "a\uFFFDb"},
	} {
		if got := cutText(tc.in, limit); got != tc.want {
			t.Errorf("cutText(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestStateNames(t *testing.T) {
	for _, tc := range []struct {
		state State
		name  string
	}{
		{StateStarting, "starting"},
		{StateReady, "ready"},
		{StateDegraded, "degraded"},
		{StateUnenforced, "unenforced"},
	} {
		if got := tc.state.String(); got != tc.name {
			t.Errorf("%d.String() = %q, want %q", tc.state, got, tc.name)
		}
		if got, err := parseState(tc.name); err != nil || got != tc.state {
			t.Errorf("parseState(%q) = %v, %v; want %v", tc.name, got, err, tc.state)
		}
	}
	// An out-of-range state goes on the wire as a name that no client reads.
	if _, err := parseState(State(9).String()); !errors.Is(err, ErrProtocol) {
		t.Errorf("parseState(State(9).String()) = %v, want ErrProtocol", err)
	}
}

func TestControlClientRejectsServerWithOtherUID(t *testing.T) {
	path := shortPath(t)
	listenStatus(t, path, &fakeControl{status: fullStatus()})

	_, err := NewControlClient(path, self()+1).Status(t.Context())

	if !errors.Is(err, ErrUnavailable) {
		t.Errorf("err = %v, want ErrUnavailable", err)
	}
}

func TestControlSocketModes(t *testing.T) {
	status, admin, report := shortPath(t), shortPath(t), shortPath(t)
	listenStatus(t, status, &fakeControl{})
	listenAdmin(t, admin, &fakeControl{}, self())
	listen(t, report, handlerFunc(ack), self())
	for path, want := range map[string]os.FileMode{status: 0o666, admin: 0o600, report: 0o660} {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != want {
			t.Errorf("mode of %s = %o, want %o", filepath.Base(filepath.Dir(path)), got, want)
		}
	}
}

func TestApplyIsDeniedWhenTheSocketFileRefusesTheCaller(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root connects whatever the mode")
	}
	path := shortPath(t)
	h := &fakeControl{status: fullStatus()}
	listenAdmin(t, path, h, self())
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}

	_, err := NewControlClient(path, self()).Apply(t.Context(), []byte("x"))

	if !errors.Is(err, ErrDenied) {
		t.Errorf("Apply = %v, want ErrDenied", err)
	}
}

// TestStatusFloodDelaysNeitherReportsNorAdmin fills every slot of the
// status socket. A report and an Apply on the other sockets must still
// get through.
func TestStatusFloodDelaysNeitherReportsNorAdmin(t *testing.T) {
	status, admin := shortPath(t), shortPath(t)
	listenStatus(t, status, &fakeControl{status: fullStatus()})
	listenAdmin(t, admin, &fakeControl{status: fullStatus()}, self())
	reports, _ := start(t, handlerFunc(ack))

	var d net.Dialer
	for range 16 { // more than the 4 status slots
		conn, err := d.DialContext(t.Context(), "unix", status)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() }) //nolint:errcheck // frees the slot; the server may have closed first
	}

	// The fixture is sound: the status socket is full.
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	if _, err := NewControlClient(status, self()).Status(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Status = %v, want DeadlineExceeded while the status slots are full (fixture broken)", err)
	}
	// Many requests in sequence: each one frees its slot, and a status
	// connection in the backlog would take a slot that two sockets share.
	for i := range 16 {
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		_, reportErr := reports.Report(ctx, Observation{QName: "a.test."})
		_, applyErr := NewControlClient(admin, self()).Apply(ctx, []byte("x"))
		cancel()
		if reportErr != nil || applyErr != nil {
			t.Fatalf("request %d: Report = %v, Apply = %v while the status slots are full", i, reportErr, applyErr)
		}
	}
}

// TestControlSocketSlots: the status socket serves 4 connections at once,
// and the admin socket 2.
func TestControlSocketSlots(t *testing.T) {
	status, admin := shortPath(t), shortPath(t)
	listenStatus(t, status, &fakeControl{status: fullStatus()})
	listenAdmin(t, admin, &fakeControl{status: fullStatus()}, self())
	for _, tc := range []struct {
		path  string
		slots int
	}{{status, 4}, {admin, 2}} {
		var d net.Dialer
		var idle []net.Conn
		hold := func() {
			conn, err := d.DialContext(t.Context(), "unix", tc.path)
			if err != nil {
				t.Fatal(err)
			}
			idle = append(idle, conn)
		}
		ask := func() error {
			ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
			defer cancel()
			_, err := NewControlClient(tc.path, self()).Status(ctx)
			return err
		}
		for range tc.slots - 1 {
			hold()
		}
		if err := ask(); err != nil {
			t.Errorf("%d slots: Status with %d idle connections = %v", tc.slots, tc.slots-1, err)
		}
		hold()
		if err := ask(); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("%d slots: Status with %d idle connections = %v, want DeadlineExceeded", tc.slots, tc.slots, err)
		}
		for _, conn := range idle {
			if err := conn.Close(); err != nil {
				t.Error(err)
			}
		}
	}
}

// levelCounter counts log records by level.
type levelCounter struct {
	debug, info *atomic.Int64 // info counts Info and above
}

func newLevelCounter() levelCounter {
	return levelCounter{debug: new(atomic.Int64), info: new(atomic.Int64)}
}

func (h levelCounter) Enabled(context.Context, slog.Level) bool { return true }

func (h levelCounter) Handle(_ context.Context, r slog.Record) error {
	if r.Level >= slog.LevelInfo {
		h.info.Add(1)
	} else {
		h.debug.Add(1)
	}
	return nil
}

func (h levelCounter) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h levelCounter) WithGroup(string) slog.Handler      { return h }

// hangUp sends n status requests and closes each connection before the
// reply comes.
func hangUp(t *testing.T, path string, n int) {
	t.Helper()
	var d net.Dialer
	for range n {
		conn, err := d.DialContext(t.Context(), "unix", path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write(frameOf(`{"v":1,"type":"status"}`)); err != nil {
			t.Fatal(err)
		}
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestOnlyTrustedPeersCanLogAboveDebug(t *testing.T) {
	const hangups = 32
	t.Run("status socket", func(t *testing.T) {
		path := shortPath(t)
		logs := newLevelCounter()
		stop := serve(t, newStatusServer(t, path, &fakeControl{status: fullStatus()}, slog.New(logs)))

		hangUp(t, path, hangups)
		if _, err := NewControlClient(path, self()).Status(t.Context()); err != nil {
			t.Fatal(err)
		}
		stop()

		if logs.debug.Load() == 0 {
			t.Fatal("no peer event logged (fixture broken)")
		}
		if n := logs.info.Load(); n != 0 {
			t.Errorf("%d records at Info or above from untrusted peers", n)
		}
	})
	t.Run("admin socket", func(t *testing.T) {
		path := shortPath(t)
		logs := newLevelCounter()
		stop := serve(t, newAdminServer(t, path, &fakeControl{status: fullStatus()}, slog.New(logs), self()))

		hangUp(t, path, hangups)
		if _, err := NewControlClient(path, self()).Status(t.Context()); err != nil {
			t.Fatal(err)
		}
		stop()

		if logs.info.Load() == 0 {
			t.Error("a failed reply to a trusted peer is not logged at Warn")
		}
	})
}

// TestHelperControl is the client side of TestCrossUIDControl. It runs in a
// child process under another uid and prints one marker line with the
// outcome of Status and of Apply.
func TestHelperControl(t *testing.T) {
	path := os.Getenv("IPC_HELPER_CONTROL")
	if path == "" {
		t.Skip("child process only")
	}
	c := NewControlClient(path, 0)
	_, statusErr := c.Status(t.Context())
	_, applyErr := c.Apply(t.Context(), []byte("x"))
	fmt.Printf("RESULT status=%s apply=%s\n", outcome(statusErr), outcome(applyErr))
}

func outcome(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, ErrDenied):
		return "denied"
	case errors.Is(err, ErrUnavailable):
		return "unavailable"
	case errors.Is(err, ErrRejected):
		return "rejected"
	default:
		return fmt.Sprintf("other(%v)", err)
	}
}

// TestCrossUIDControl checks both checks of the admin socket, the file
// mode and the peer uid, with a real second uid. It needs root: the
// server runs as root and the client as uid 65534.
func TestCrossUIDControl(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to run the client under another uid")
	}
	const nobody = 65534
	dir, err := os.MkdirTemp("", "ipc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })  //nolint:errcheck // best-effort cleanup; files made by the other uid can block removal
	if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // the other uid must reach the sockets and the binary copy
		t.Fatal(err)
	}
	bin := copyTestBinary(t, dir)
	tests := []struct {
		name   string
		listen func(t *testing.T, path string)
		want   string
	}{
		{"status socket", func(t *testing.T, path string) {
			listenStatus(t, path, &fakeControl{status: fullStatus()})
		}, "RESULT status=ok apply=rejected"},
		{"admin socket", func(t *testing.T, path string) {
			listenAdmin(t, path, &fakeControl{status: fullStatus()}, 0)
		}, "RESULT status=denied apply=denied"},
		{"admin socket mode wins over uids", func(t *testing.T, path string) {
			listenAdmin(t, path, &fakeControl{status: fullStatus()}, nobody)
		}, "RESULT status=denied apply=denied"},
		{"admin socket opened, uid refused", func(t *testing.T, path string) {
			listenAdmin(t, path, &fakeControl{status: fullStatus()}, 0)
			if err := os.Chmod(path, 0o666); err != nil { //nolint:gosec // the uid check is under test, not the file mode
				t.Fatal(err)
			}
		}, "RESULT status=unavailable apply=unavailable"},
		// The fixture is sound: the other uid gets through both checks.
		{"admin socket opened, uid listed", func(t *testing.T, path string) {
			listenAdmin(t, path, &fakeControl{status: fullStatus()}, nobody)
			if err := os.Chmod(path, 0o666); err != nil { //nolint:gosec // the uid check is under test, not the file mode
				t.Fatal(err)
			}
		}, "RESULT status=ok apply=ok"},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, fmt.Sprintf("c%d.sock", i))
			tc.listen(t, path)
			if got := controlAs(t, bin, path, nobody); got != tc.want {
				t.Errorf("result = %q, want %q", got, tc.want)
			}
		})
	}
}

// controlAs runs TestHelperControl against path under uid and returns its
// marker line.
func controlAs(t *testing.T, bin, path string, uid uint32) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), bin, "-test.run=^TestHelperControl$", "-test.v")
	cmd.Env = append(os.Environ(), "IPC_HELPER_CONTROL="+path)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid}}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child failed: %v\n%s", err, out)
	}
	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.HasPrefix(line, "RESULT ") {
			return line
		}
	}
	t.Fatalf("no result line\n%s", out)
	return ""
}
