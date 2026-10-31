//go:build e2e && darwin

package e2e

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	_ "github.com/coredns/coredns/plugin/cache"
	_ "github.com/coredns/coredns/plugin/errors"
	_ "github.com/coredns/coredns/plugin/hosts" // the answer source that replaces forward
	"github.com/miekg/dns"

	"github.com/Nagato-Yuzuru/ifbound/internal/dnsconf"
	"github.com/Nagato-Yuzuru/ifbound/internal/ipc"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/testenv"
)

// delayedAck is a fake ifboundd that acks every report after delay.
type delayedAck struct {
	delay   time.Duration
	reports atomic.Int64
}

func (d *delayedAck) Observe(ctx context.Context, _ ipc.Observation) (ipc.Ack, error) {
	d.reports.Add(1)
	select {
	case <-time.After(d.delay):
		return ipc.Ack{Protected: true}, nil
	case <-ctx.Done():
		return ipc.Ack{}, ctx.Err()
	}
}

// startFakeIfboundd serves h on a new socket as uid 0 and returns the path.
func startFakeIfboundd(t *testing.T, h ipc.Handler) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ifbe2e")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	sock := filepath.Join(dir, "r.sock")
	srv, err := ipc.Listen(ipc.ServerConfig{Path: sock, Handler: h, AllowedUIDs: []uint32{0}})
	if err != nil {
		t.Fatalf("ipc.Listen: %v", err)
	}
	served := make(chan error, 1)
	go func() { served <- srv.Serve(context.Background()) }()
	t.Cleanup(func() {
		_ = srv.Close() //nolint:errcheck // Serve returns the close error below, and the test fails on it
		if err := <-served; err != nil {
			t.Errorf("Serve returned %v", err)
		}
	})
	return sock
}

// renderedWithHosts renders the Corefile for sock. The test has no TLS
// upstream, so a hosts block replaces the forward line. Every other line is
// the rendered one.
func renderedWithHosts(t *testing.T, sock string) []byte {
	t.Helper()
	r, err := dnsconf.New(sock, "")
	if err != nil {
		t.Fatal(err)
	}
	d := policy.DNS{
		Listen:   netip.MustParseAddrPort("127.0.0.1:1"),
		Upstream: []policy.Upstream{{Addr: netip.MustParseAddrPort("9.9.9.9:853")}},
	}
	var lines []string
	for l := range strings.SplitSeq(string(r.Corefile(d)), "\n") {
		switch {
		case strings.HasPrefix(l, "\tforward"):
			lines = append(lines, "\thosts {", "\t\t192.0.2.7 app.example", "\t}")
		case strings.HasPrefix(l, ".:"):
			lines = append(lines, ".:0 {")
		default:
			lines = append(lines, l)
		}
	}
	return []byte(strings.Join(lines, "\n"))
}

// The plugin trusts only an ifboundd that runs as uid 0, so this test runs
// as root in the guest. Both queries must wait for the ack: ifbound stands
// before cache in the rendered Corefile, so a cache hit does not skip it.
func TestRenderedCorefileHoldsEachAnswerUntilTheAck(t *testing.T) {
	testenv.RequireDisposableHost(t)
	testenv.RequireRoot(t)
	if err := registerPlugin(); err != nil {
		t.Fatalf("Register: %v", err)
	}
	const delay = 300 * time.Millisecond
	fake := &delayedAck{delay: delay}
	sock := startFakeIfboundd(t, fake)

	dnsserver.Quiet = true
	inst, err := caddy.Start(caddy.CaddyfileInput{
		Contents:       renderedWithHosts(t, sock),
		Filepath:       "Corefile",
		ServerTypeName: "dns",
	})
	if err != nil {
		t.Fatalf("start CoreDNS: %v", err)
	}
	t.Cleanup(func() { _ = inst.Stop() }) //nolint:errcheck // Stop always returns nil
	addr := inst.Servers()[0].LocalAddr().String()

	for i := range 2 {
		start := time.Now()
		reply, err := dns.Exchange(new(dns.Msg).SetQuestion("app.example.", dns.TypeA), addr)
		if err != nil {
			t.Fatal(err)
		}
		if reply.Rcode != dns.RcodeSuccess || len(reply.Answer) != 1 {
			t.Fatalf("query %d: reply = %v, want the answer", i, reply)
		}
		if took := time.Since(start); took < delay {
			t.Errorf("query %d: answer came after %v, before the ack", i, took)
		}
	}
	if got := fake.reports.Load(); got != 2 {
		t.Errorf("reports = %d, want 2: the cache answered one query without a report", got)
	}
}
