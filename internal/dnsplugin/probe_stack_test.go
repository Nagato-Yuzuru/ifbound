package dnsplugin

// A probe of ifboundd must not wait for a report: the warm-up proves with
// probes that the queries for a name go to ifbound-dns, and the reports
// can hold every report slot and the daemon loop for a long time. This
// check wires the real parts: the plugin handler, the ipc Client and
// Server, and the daemon on the reconciletest fakes. A platform write
// that does not end blocks the daemon loop, every report slot of the
// Client holds a report that waits for the loop, and one more report
// waits for a slot. A probe query must still get its reply.

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"

	"github.com/Nagato-Yuzuru/ifbound/internal/daemon"
	"github.com/Nagato-Yuzuru/ifbound/internal/ipc"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile/reconciletest"
	"github.com/Nagato-Yuzuru/ifbound/internal/syslookup"
)

// pvReportSlots is the in-flight limit of one ipc.Client for reports. The
// test fills it; a smaller value would not prove the claim.
const pvReportSlots = 32

const pvStackConfig = `
[dns]
listen = "127.0.0.1:10053"
upstream = ["tls://1.1.1.1@cloudflare-dns.com"]
[addrbook]
retain = "1h"

[[policy]]
name = "web"
to = ["*.prot.test"]
only_via = ["en0"]
`

// pvMDNS is the system resolver: it sends a probe name to the plugin when
// an applied resolver entry with the address of ifbound-dns covers it.
// Every other name gets "no such name" at once. The daemon resolves its
// warm-up names through it.
type pvMDNS struct {
	world  *reconciletest.World
	plugin *handler
	listen netip.AddrPort
}

func (m *pvMDNS) Resolve(ctx context.Context, name string) ([]netip.Addr, error) {
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	if ipc.IsProbe(n) && m.routed(n) {
		rec := dnstest.NewRecorder(&test.ResponseWriter{})
		_, _ = m.plugin.ServeDNS(ctx, rec, new(dns.Msg).SetQuestion(dns.Fqdn(n), dns.TypeA))
	}
	return nil, fmt.Errorf("resolve %s: %w", n, syslookup.ErrNotFound)
}

func (m *pvMDNS) routed(name string) bool {
	best := ""
	var srv netip.AddrPort
	for _, e := range m.world.AppliedResolverEntries() {
		d := e.Domain.String()
		if (name == d || strings.HasSuffix(name, "."+d)) && len(d) > len(best) {
			best, srv = d, e.Server
		}
	}
	return best != "" && srv == m.listen
}

// pvAnswer answers w<i>.prot.test with one address.
func pvAnswer() plugin.Handler {
	return plugin.HandlerFunc(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
		q := r.Question[0].Name
		var i int
		if _, err := fmt.Sscanf(q, "w%d.prot.test.", &i); err != nil {
			return dns.RcodeServerFailure, err
		}
		m := new(dns.Msg).SetReply(r)
		m.Answer = []dns.RR{pvRR(fmt.Sprintf("%s 60 IN A 198.18.%d.%d", q, i/250, 1+i%250))}
		if err := w.WriteMsg(m); err != nil {
			return dns.RcodeServerFailure, err
		}
		return dns.RcodeSuccess, nil
	})
}

func pvRR(s string) dns.RR {
	r, err := dns.NewRR(s)
	if err != nil {
		panic(err)
	}
	return r
}

func pvSocket(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "pv")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "s.sock")
}

// pvCounter is the ipc.Handler of the daemon. It counts the reports that
// reached the server.
type pvCounter struct {
	*daemon.Daemon
	in atomic.Int32
}

func (c *pvCounter) Observe(ctx context.Context, o ipc.Observation) (ipc.Ack, error) {
	c.in.Add(1)
	return c.Daemon.Observe(ctx, o)
}

func pvUID() uint32 { return uint32(os.Getuid()) } //nolint:gosec // a uid is never negative on unix

// pvStack starts the daemon and the ipc server until the test ends. It
// returns the plugin handler, the report counter, and the World. timeout
// is the ack timeout of the plugin.
func pvStack(t *testing.T, timeout time.Duration) (*handler, *pvCounter, *reconciletest.World) {
	t.Helper()
	ctx := t.Context()
	cfg, err := policy.ParseBytes([]byte(pvStackConfig))
	if err != nil {
		t.Fatal(err)
	}
	world := reconciletest.NewWorld()
	mdns := &pvMDNS{world: world, listen: cfg.DNS.Listen}
	d := daemon.New(daemon.Config{
		Policy:   cfg,
		Snapshot: filepath.Join(t.TempDir(), "addrbook.json"),
		Platform: reconcile.Reconciler{
			Compiler: reconciletest.Compiler{}, Backend: world.Backend(), Resolver: world.Resolver(),
			Inventory: reconciletest.NewInventory(reconcile.Interface{Name: "en0", Class: policy.ClassHardware}),
		},
		Lookup: mdns,
	})
	counter := &pvCounter{Daemon: d}
	path := pvSocket(t)
	srv, err := ipc.Listen(ipc.ServerConfig{Path: path, Handler: counter, Probes: d, AllowedUIDs: []uint32{pvUID()}})
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ctx) }()
	t.Cleanup(func() {
		_ = srv.Close()
		<-served
	})
	client := ipc.NewClient(path, pvUID())
	h := &handler{key: testKey, next: pvAnswer(), reporter: client, probes: client, timeout: timeout}
	mdns.plugin = h
	// The warm-up of the daemon sends probes to the plugin, so Run starts
	// after the plugin is set.
	go func() { _ = d.Run(ctx) }() // ends with ctx
	for {
		st, err := d.Status(ctx)
		if err == nil && st.State == daemon.StateReady {
			return h, counter, world
		}
		select {
		case <-ctx.Done():
			t.Fatalf("daemon not ready: %+v %v", st, err)
		case <-time.After(10 * time.Millisecond): // polls the daemon start; no other signal exists
		}
	}
}

func TestPVProbesPassWhileTheLoopAndEveryReportSlotWait(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	h, counter, world := pvStack(t, 20*time.Second)
	blocked, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	world.SetBeforeWrite(func(int) error {
		once.Do(func() { close(blocked) })
		<-release
		return nil
	})
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})

	type result struct {
		q     string
		rcode int
		err   error
		msg   *dns.Msg
	}
	results := make(chan result, pvReportSlots+1)
	for i := range pvReportSlots + 1 { // one more than the slots: it waits for a slot
		go func() {
			q := fmt.Sprintf("w%d.prot.test.", i)
			rec := dnstest.NewRecorder(&test.ResponseWriter{})
			rcode, err := h.ServeDNS(ctx, rec, new(dns.Msg).SetQuestion(q, dns.TypeA))
			results <- result{q, rcode, err, rec.Msg}
		}()
	}
	select {
	case <-blocked:
	case <-ctx.Done():
		t.Fatal("no report reached the platform")
	}
	for counter.in.Load() < pvReportSlots {
		time.Sleep(time.Millisecond) // waits for the slots to fill; no other signal exists
	}

	for i := range 4 {
		q := fmt.Sprintf("%s%d.prot.test.", ipc.ProbePrefix, i)
		pctx, pcancel := context.WithTimeout(ctx, 2*time.Second)
		rec := dnstest.NewRecorder(&test.ResponseWriter{})
		rcode, err := h.ServeDNS(pctx, rec, new(dns.Msg).SetQuestion(q, dns.TypeA))
		pcancel()
		if err != nil || rcode != dns.RcodeNameError {
			t.Errorf("probe %s: rcode %d, err %v; want NXDOMAIN while the reports wait", q, rcode, err)
		}
	}
	select {
	case r := <-results:
		t.Fatalf("%s returned while the loop is blocked: rcode %d, err %v", r.q, r.rcode, r.err)
	default:
	}

	close(release)
	for range pvReportSlots + 1 {
		r := <-results
		if r.err != nil || r.rcode != dns.RcodeSuccess || r.msg == nil || r.msg.Rcode != dns.RcodeSuccess {
			t.Errorf("%s: rcode %d, err %v, reply %v; want the upstream answer after an ack", r.q, r.rcode, r.err, r.msg)
		}
	}
}
