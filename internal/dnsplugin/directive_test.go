package dnsplugin

import (
	"context"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"

	"github.com/Nagato-Yuzuru/ifbound/internal/ipc"
)

// timedReporter records each observation and the time left on its ctx.
type timedReporter struct {
	mu   sync.Mutex
	obs  []ipc.Observation
	left []time.Duration
}

func (r *timedReporter) Report(ctx context.Context, o ipc.Observation) (ipc.Ack, error) {
	dl, ok := ctx.Deadline()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.obs = append(r.obs, o)
	if ok {
		r.left = append(r.left, time.Until(dl))
	} else {
		r.left = append(r.left, -1)
	}
	return ipc.Ack{}, nil
}

type countingProber struct {
	mu    sync.Mutex
	names []string
}

func (p *countingProber) ReportProbe(_ context.Context, qname string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.names = append(p.names, qname)
	return nil
}

// fixedUpstream writes a fixed answer.
type fixedUpstream struct{ answer []dns.RR }

func (u fixedUpstream) ServeDNS(_ context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	m := new(dns.Msg).SetReply(r)
	m.Answer = u.answer
	if err := w.WriteMsg(m); err != nil {
		return dns.RcodeServerFailure, err
	}
	return dns.RcodeSuccess, nil
}

func (fixedUpstream) Name() string { return "upstream" }

func mustRR(t *testing.T, s string) dns.RR {
	t.Helper()
	r, err := dns.NewRR(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// directiveHandler builds the handler that the Corefile line sets up, with
// the reporter and prober replaced by recorders.
func directiveHandler(t *testing.T, line string, next fixedUpstream) (*handler, *timedReporter, *countingProber) {
	t.Helper()
	c := caddy.NewTestController("dns", line)
	if err := new(clients).setup(c); err != nil {
		t.Fatalf("setup(%q): %v", line, err)
	}
	chain := dnsserver.GetConfig(c).Plugin
	if len(chain) != 1 {
		t.Fatalf("plugins = %d, want 1", len(chain))
	}
	h, ok := chain[0](next).(*handler)
	if !ok {
		t.Fatalf("plugin is %T", chain[0](next))
	}
	rep, pr := &timedReporter{}, &countingProber{}
	h.reporter, h.probes = rep, pr
	return h, rep, pr
}

func serveQuery(t *testing.T, h *handler, qname string, qtype uint16) (*dns.Msg, int) {
	t.Helper()
	req := new(dns.Msg).SetQuestion(qname, qtype)
	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	rcode, err := h.ServeDNS(t.Context(), rec, req)
	if err != nil {
		t.Fatalf("ServeDNS(%s) = %d, %v", qname, rcode, err)
	}
	return rec.Msg, rcode
}

// Without a timeout argument, the plugin waits 2 s for the ack.
func TestPluginDefaultAckWaitIsTwoSeconds(t *testing.T) {
	next := fixedUpstream{answer: []dns.RR{mustRR(t, "example.com. 60 IN A 192.0.2.1")}}
	h, rep, _ := directiveHandler(t, "ifbound /run/ifbound.sock", next)
	if _, rcode := serveQuery(t, h, "example.com.", dns.TypeA); rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want success", rcode)
	}
	rep.mu.Lock()
	defer rep.mu.Unlock()
	if len(rep.left) != 1 {
		t.Fatalf("reports = %d, want 1", len(rep.left))
	}
	if d := rep.left[0]; d <= 1500*time.Millisecond || d > 2*time.Second {
		t.Errorf("ack wait = %v, want 2 s", d)
	}

	// An explicit argument still wins.
	h, rep, _ = directiveHandler(t, "ifbound /run/ifbound.sock 300ms", next)
	serveQuery(t, h, "example.com.", dns.TypeA)
	if d := rep.left[0]; d <= 200*time.Millisecond || d > 300*time.Millisecond {
		t.Errorf("ack wait with 300ms = %v", d)
	}
}

// A reply that only points to other names (CNAME, HTTPS TargetName)
// and has no address is reported without an address: only the ack tells
// if the plugin must flatten it. A reply with addresses is reported with
// the qname, the addresses and the TTL only.
func TestPluginReportsAddressesOnly(t *testing.T) {
	cnameOnly := fixedUpstream{answer: []dns.RR{
		mustRR(t, "www.example.com. 300 IN CNAME cdn.example.net."),
	}}
	h, rep, pr := directiveHandler(t, "ifbound /run/ifbound.sock", cnameOnly)
	m, rcode := serveQuery(t, h, "www.example.com.", dns.TypeA)
	if rcode != dns.RcodeSuccess || len(m.Answer) != 1 {
		t.Fatalf("CNAME-only reply: rcode %d, answer %v; want it passed on", rcode, m.Answer)
	}
	if len(rep.obs) != 1 || len(rep.obs[0].Addrs) != 0 || len(pr.names) != 0 {
		t.Errorf("CNAME-only reply gave reports %v and probes %v, want one report without an address", rep.obs, pr.names)
	}

	httpsOnly := fixedUpstream{answer: []dns.RR{
		mustRR(t, "www.example.com. 300 IN HTTPS 1 svc.example.org. alpn=h2"),
	}}
	h, rep, _ = directiveHandler(t, "ifbound /run/ifbound.sock", httpsOnly)
	serveQuery(t, h, "www.example.com.", dns.TypeHTTPS)
	if len(rep.obs) != 1 || len(rep.obs[0].Addrs) != 0 {
		t.Errorf("HTTPS reply without hints gave reports %v, want one without an address", rep.obs)
	}

	withAddrs := fixedUpstream{answer: []dns.RR{
		mustRR(t, "www.example.com. 300 IN CNAME cdn.example.net."),
		mustRR(t, "cdn.example.net. 60 IN A 192.0.2.7"),
	}}
	h, rep, _ = directiveHandler(t, "ifbound /run/ifbound.sock", withAddrs)
	serveQuery(t, h, "www.example.com.", dns.TypeA)
	if len(rep.obs) != 1 {
		t.Fatalf("reports = %d, want 1", len(rep.obs))
	}
	got := rep.obs[0]
	if got.QName != "www.example.com." || !slices.Equal(got.Addrs, []netip.Addr{netip.MustParseAddr("192.0.2.7")}) || got.TTL != 60*time.Second {
		t.Errorf("report = %+v, want www.example.com. [192.0.2.7] 60s", got)
	}
}
