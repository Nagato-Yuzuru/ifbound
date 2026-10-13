package dnsplugin

// Owner decision 5 for the alias work: "The probe report must not need an
// ack slot that the waiting outer report holds ... Design the probe
// report so it cannot deadlock." This check wires the real parts: the
// plugin handler, the ipc Client and Server, and the daemon on the
// reconciletest fakes. Every report slot of the Client holds a report
// whose ack waits for the probe of its alias, and one more report waits
// for a slot. The system resolver sends each probe name to the plugin, as
// mDNSResponder does once the resolver entry applies. Every report must
// get its ack.

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

const pvDeadlockConfig = `
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
// an applied resolver entry with the address of ifbound-dns covers it. It
// holds the probes until every report waits for its probe.
type pvMDNS struct {
	world  *reconciletest.World
	plugin *handler
	listen netip.AddrPort

	mu      sync.Mutex
	waiting map[string]bool
	gate    chan struct{}
	want    int
	reached int // probes that reached the plugin
}

func (m *pvMDNS) Resolve(ctx context.Context, name string) ([]netip.Addr, error) {
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	_, alias, _ := strings.Cut(n, ".")
	m.mu.Lock()
	if !m.waiting[alias] {
		m.waiting[alias] = true
		if len(m.waiting) == m.want {
			close(m.gate)
		}
	}
	m.mu.Unlock()
	select {
	case <-m.gate:
	case <-ctx.Done():
		return nil, fmt.Errorf("resolve %s: %w", n, ctx.Err())
	}
	if !m.routed(n) {
		return nil, fmt.Errorf("resolve %s: %w", n, syslookup.ErrNotFound)
	}
	m.mu.Lock()
	m.reached++
	m.mu.Unlock()
	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	_, _ = m.plugin.ServeDNS(ctx, rec, new(dns.Msg).SetQuestion(dns.Fqdn(n), dns.TypeA))
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

// pvCNAME answers w<i>.prot.test with a CNAME to a<i>.cdn.test and an
// address of it.
func pvCNAME() plugin.Handler {
	return plugin.HandlerFunc(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
		q := r.Question[0].Name
		var i int
		if _, err := fmt.Sscanf(q, "w%d.prot.test.", &i); err != nil {
			return dns.RcodeServerFailure, err
		}
		alias := fmt.Sprintf("a%d.cdn.test.", i)
		m := new(dns.Msg).SetReply(r)
		m.Answer = []dns.RR{
			pvRR(fmt.Sprintf("%s 60 IN CNAME %s", q, alias)),
			pvRR(fmt.Sprintf("%s 60 IN A 198.18.%d.%d", alias, i/250, 1+i%250)),
		}
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

// pvListen opens the ipc server for the daemon.
func pvListen(t *testing.T, path string, d *daemon.Daemon) *ipc.Server {
	t.Helper()
	srv, err := ipc.Listen(ipc.ServerConfig{Path: path, Handler: d, Probes: d, AllowedUIDs: []uint32{pvUID()}})
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

func pvUID() uint32 { return uint32(os.Getuid()) } //nolint:gosec // a uid is never negative on unix

// pvStack starts the daemon and the ipc server until the test ends, and
// returns the plugin handler and the system resolver.
func pvStack(t *testing.T, want int) (*handler, *pvMDNS) {
	t.Helper()
	ctx := t.Context()
	cfg, err := policy.ParseBytes([]byte(pvDeadlockConfig))
	if err != nil {
		t.Fatal(err)
	}
	world := reconciletest.NewWorld()
	mdns := &pvMDNS{world: world, listen: cfg.DNS.Listen, waiting: map[string]bool{}, gate: make(chan struct{}), want: want}
	d := daemon.New(daemon.Config{
		Policy:   cfg,
		Snapshot: filepath.Join(t.TempDir(), "addrbook.json"),
		Platform: reconcile.Reconciler{
			Compiler: reconciletest.Compiler{}, Backend: world.Backend(), Resolver: world.Resolver(),
			Inventory: reconciletest.NewInventory(reconcile.Interface{Name: "en0", Class: policy.ClassHardware}),
		},
		Lookup: mdns,
	})
	go func() { _ = d.Run(ctx) }() // ends with ctx
	path := pvSocket(t)
	srv := pvListen(t, path, d)
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ctx) }()
	t.Cleanup(func() {
		_ = srv.Close()
		<-served
	})
	client := ipc.NewClient(path, pvUID())
	h := &handler{next: pvCNAME(), reporter: client, probes: client, timeout: ipc.DefaultTimeout}
	mdns.plugin = h
	for {
		st, err := d.Status(ctx)
		if err == nil && st.State == daemon.StateReady {
			return h, mdns
		}
		select {
		case <-ctx.Done():
			t.Fatalf("daemon not ready: %+v %v", st, err)
		case <-time.After(10 * time.Millisecond): // polls the daemon start; no other signal exists
		}
	}
}

func TestPVProbesPassWhileEveryReportSlotWaitsForAProbe(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	h, mdns := pvStack(t, pvReportSlots)

	type result struct {
		q     string
		rcode int
		err   error
		msg   *dns.Msg
	}
	results := make(chan result, pvReportSlots+1)
	start := time.Now()
	for i := range pvReportSlots + 1 { // one more than the slots: it waits for a slot
		go func() {
			q := fmt.Sprintf("w%d.prot.test.", i)
			rec := dnstest.NewRecorder(&test.ResponseWriter{})
			rcode, err := h.ServeDNS(ctx, rec, new(dns.Msg).SetQuestion(q, dns.TypeA))
			results <- result{q, rcode, err, rec.Msg}
		}()
	}

	for range pvReportSlots + 1 {
		r := <-results
		if r.err != nil || r.rcode != dns.RcodeSuccess || r.msg == nil || r.msg.Rcode != dns.RcodeSuccess {
			t.Errorf("%s: rcode %d, err %v, reply %v; want the upstream answer after an ack", r.q, r.rcode, r.err, r.msg)
		}
	}
	if el := time.Since(start); el >= ipc.DefaultTimeout {
		t.Errorf("the reports took %v: they waited for a timeout", el)
	}
	mdns.mu.Lock()
	defer mdns.mu.Unlock()
	if mdns.reached < pvReportSlots {
		t.Errorf("probes that reached the plugin = %d, want at least %d", mdns.reached, pvReportSlots)
	}
}
