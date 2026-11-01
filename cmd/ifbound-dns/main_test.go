package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	_ "github.com/coredns/coredns/plugin/hosts"
	"github.com/miekg/dns"

	"github.com/Nagato-Yuzuru/ifbound/internal/configstore"
	"github.com/Nagato-Yuzuru/ifbound/internal/dnsconf"
	"github.com/Nagato-Yuzuru/ifbound/internal/dnsplugin"
	"github.com/Nagato-Yuzuru/ifbound/internal/layout"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

const (
	upstreamA = "[\"tls://9.9.9.9@dns.quad9.net\"]"
	upstreamB = "[\"tls://1.1.1.1@one.one.one.one\"]"
	policyA   = "[[policy]]\nname = \"a\"\nto = [\"a.example\"]\nonly_via = [\"utun*\"]\n"
	policyB   = "[[policy]]\nname = \"b\"\nto = [\"b.example\"]\nonly_via = [\"utun*\"]\n"
)

// registerOnce registers the plugin for the test binary: CoreDNS accepts a
// plugin name once per process.
var registerOnce = sync.OnceValue(dnsplugin.Register)

// syncBuffer is a bytes.Buffer that several goroutines can write.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func testLogger() (*slog.Logger, *syncBuffer) {
	buf := new(syncBuffer)
	return slog.New(slog.NewTextHandler(buf, nil)), buf
}

// freeAddr returns a loopback address with a port that nothing uses.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := new(net.ListenConfig).Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

// testLayout returns a layout with short directories. The state directory
// holds no stored configuration yet.
func testLayout(t *testing.T) layout.Layout {
	t.Helper()
	dir, err := os.MkdirTemp("", "ifb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	l := layout.Default()
	l.StateDir, l.RunDir = dir, dir
	return l
}

func store(t *testing.T, l layout.Layout, listen, upstream, policies string) {
	t.Helper()
	cfg := fmt.Sprintf("[dns]\nlisten = %q\nupstream = %s\n%s", listen, upstream, policies)
	if _, _, err := configstore.Store(l.StoredConfig(), []byte(cfg), -1); err != nil {
		t.Fatal(err)
	}
}

// ticker is a hand-driven clock for watch and run.
type ticker chan time.Time

// tick sends one tick. The channel has no buffer, so the call returns after
// watch has taken the tick.
func (c ticker) tick(t *testing.T) {
	t.Helper()
	select {
	case c <- time.Time{}:
	case <-time.After(10 * time.Second):
		t.Fatal("the watch takes no tick")
	}
}

// tickOrDone is tick for a watch that may return while the test sends.
func (c ticker) tickOrDone(done <-chan struct{}) {
	select {
	case c <- time.Time{}:
	case <-done:
	}
}

func requireRunning(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
		t.Fatal("the watch returned, want it to keep running")
	default:
	}
}

func requireReturns(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the watch did not return")
	}
}

func startWatch(t *testing.T, l layout.Layout, ticks ticker, logger *slog.Logger) <-chan struct{} {
	t.Helper()
	cfg, _, err := configstore.Load(l.StoredConfig())
	if err != nil {
		t.Fatal(err)
	}
	r, err := dnsconf.New("/run/ifbound/report.sock", "")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		watch(t.Context(), ticks, l.StoredConfig(), r.Corefile, r.Corefile(cfg.DNS), logger)
	}()
	return done
}

func TestWatchExitsOnlyWhenDNSChanges(t *testing.T) {
	l := testLayout(t)
	store(t, l, "127.0.0.1:10053", upstreamA, policyA)
	logger, _ := testLogger()
	ticks := make(ticker)
	done := startWatch(t, l, ticks, logger)

	store(t, l, "127.0.0.1:10053", upstreamA, policyB)
	ticks.tick(t)
	ticks.tick(t) // goes in only after watch has finished the first tick
	requireRunning(t, done)

	store(t, l, "127.0.0.1:10053", upstreamB, policyB)
	ticks.tick(t)
	requireReturns(t, done)
}

func TestWatchReturnsWhenContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	logger, _ := testLogger()
	done := make(chan struct{})
	go func() {
		defer close(done)
		watch(ctx, make(ticker), "/nonexistent", nil, nil, logger)
	}()
	requireReturns(t, done)
}

func TestWatchKeepsRunningWhenTheFileCannotBeLoaded(t *testing.T) {
	l := testLayout(t)
	store(t, l, "127.0.0.1:10053", upstreamA, policyA)
	logger, logs := testLogger()
	ticks := make(ticker)
	done := startWatch(t, l, ticks, logger)

	if err := os.Remove(l.StoredConfig()); err != nil {
		t.Fatal(err)
	}
	ticks.tick(t)
	ticks.tick(t)
	ticks.tick(t)
	requireRunning(t, done)
	if got := strings.Count(logs.String(), "cannot read the stored configuration"); got != 1 {
		t.Errorf("unreadable lines = %d after three failed reads, want 1:\n%s", got, logs.String())
	}

	// The same configuration is back: the watch logs it once and goes on.
	store(t, l, "127.0.0.1:10053", upstreamA, policyA)
	ticks.tick(t)
	ticks.tick(t)
	requireRunning(t, done)
	if got := strings.Count(logs.String(), "readable again"); got != 1 {
		t.Errorf("recovery lines = %d, want 1:\n%s", got, logs.String())
	}

	// After a failure, a changed [dns] still ends the watch.
	if err := os.Remove(l.StoredConfig()); err != nil {
		t.Fatal(err)
	}
	ticks.tick(t)
	ticks.tick(t)
	store(t, l, "127.0.0.1:10053", upstreamB, policyA)
	ticks.tickOrDone(done)
	requireReturns(t, done)
}

func TestRunFailsWithoutAStoredConfiguration(t *testing.T) {
	if err := registerOnce(); err != nil {
		t.Fatal(err)
	}
	logger, _ := testLogger()
	err := run(t.Context(), testLayout(t), "", make(ticker), logger)
	if !errors.Is(err, configstore.ErrNotApplied) {
		t.Errorf("run = %v, want ErrNotApplied", err)
	}
}

func TestRunReturnsNilWhenContextEnds(t *testing.T) {
	if err := registerOnce(); err != nil {
		t.Fatal(err)
	}
	l := testLayout(t)
	store(t, l, freeAddr(t), upstreamA, policyA)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	logger, _ := testLogger()
	if err := run(ctx, l, "", make(ticker), logger); err != nil {
		t.Errorf("run = %v, want nil", err)
	}
}

func TestRunReturnsNilWhenDNSChanges(t *testing.T) {
	if err := registerOnce(); err != nil {
		t.Fatal(err)
	}
	l := testLayout(t)
	listen := freeAddr(t)
	store(t, l, listen, upstreamA, policyA)
	logger, _ := testLogger()
	ticks := make(ticker)
	result := make(chan error, 1)
	go func() { result <- run(t.Context(), l, "", ticks, logger) }()

	store(t, l, listen, upstreamB, policyA)
	ticks.tick(t)
	select {
	case err := <-result:
		if err != nil {
			t.Errorf("run = %v, want nil (exit 0)", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return after a change in [dns]")
	}
}

func TestRunRefusesARunDirWithATooLongSocketPath(t *testing.T) {
	if err := registerOnce(); err != nil {
		t.Fatal(err)
	}
	l := testLayout(t)
	l.RunDir = filepath.Join(l.RunDir, strings.Repeat("d", 100))
	logger, _ := testLogger()
	if err := run(t.Context(), l, "", make(ticker), logger); !errors.Is(err, dnsconf.ErrSocketTooLong) {
		t.Errorf("run = %v, want ErrSocketTooLong", err)
	}
}

func TestRunNamesATestCA(t *testing.T) {
	logger, logs := testLogger()
	_ = run(t.Context(), testLayout(t), "/nonexistent/ca.pem", make(ticker), logger) //nolint:errcheck // the test reads the log, not the result
	if !strings.Contains(logs.String(), "test CA") {
		t.Errorf("no line names the test CA:\n%s", logs.String())
	}
}

// startRendered starts CoreDNS with the Corefile of dnsconf for socket. The
// test has no TLS upstream, so it swaps the forward line for a hosts block;
// every other line is the rendered one.
func startRendered(t *testing.T, socket string) string {
	t.Helper()
	if err := registerOnce(); err != nil {
		t.Fatal(err)
	}
	r, err := dnsconf.New(socket, "")
	if err != nil {
		t.Fatal(err)
	}
	d := policy.DNS{
		Listen:   netip.MustParseAddrPort("127.0.0.1:1"),
		Upstream: []policy.Upstream{{Addr: netip.MustParseAddrPort("9.9.9.9:853")}},
	}
	var out []string
	var swapped bool
	for l := range strings.SplitSeq(string(r.Corefile(d)), "\n") {
		switch {
		case strings.HasPrefix(l, "\tforward"):
			out = append(out, "\thosts {", "\t\t192.0.2.7 app.example", "\t}")
			swapped = true
		case strings.HasPrefix(l, ".:"):
			out = append(out, ".:0 {")
		default:
			out = append(out, l)
		}
	}
	if !swapped {
		t.Fatal("Corefile has no forward line")
	}
	dnsserver.Quiet = true
	inst, err := caddy.Start(caddy.CaddyfileInput{
		Contents:       []byte(strings.Join(out, "\n")),
		Filepath:       "Corefile",
		ServerTypeName: "dns",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inst.Stop() }) //nolint:errcheck // Stop always returns nil
	return inst.Servers()[0].LocalAddr().String()
}

// TestNoAckGivesServfail has no ifboundd behind the socket. The test that
// holds the answer for a slow ack runs as root, in the e2e package.
func TestNoAckGivesServfail(t *testing.T) {
	dir, err := os.MkdirTemp("", "ifb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	addr := startRendered(t, filepath.Join(dir, "r.sock"))
	r, err := dns.Exchange(new(dns.Msg).SetQuestion("app.example.", dns.TypeA), addr)
	if err != nil {
		t.Fatal(err)
	}
	if r.Rcode != dns.RcodeServerFailure || len(r.Answer) != 0 {
		t.Errorf("reply = %v, want SERVFAIL without an answer", r)
	}
}

// goFiles lists the Go files of this package that a build with tags uses.
func goFiles(t *testing.T, tags string) []string {
	t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go tool on PATH")
	}
	out, err := exec.CommandContext(t.Context(), goBin, "list", "-tags", tags, "-f", `{{join .GoFiles "\n"}}`, ".").Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.Fields(string(out))
}

// testCAEnvName is the variable that only the e2e build reads.
const testCAEnvName = "IFBOUND_TEST_UPSTREAM_CA"

func TestProductionBuildHasNoTestCA(t *testing.T) {
	const marker = "testca_e2e.go"
	if !slices.Contains(goFiles(t, "e2e"), marker) {
		t.Fatalf("a build with tag e2e lacks %s", marker)
	}
	prod := goFiles(t, "")
	if slices.Contains(prod, marker) {
		t.Fatalf("a production build has %s", marker)
	}
	for _, f := range prod {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(src), testCAEnvName) {
			t.Errorf("%s in a production build names the test CA variable", f)
		}
	}
}
