package dnsplugin

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
)

// fromWire returns the query for qname and qtype as the server decodes it
// from the wire. A name that is not fully qualified cannot be packed, so it
// stays as given.
func fromWire(t *testing.T, qname string, qtype uint16) *dns.Msg {
	t.Helper()
	q := new(dns.Msg).SetQuestion(qname, qtype)
	q.RecursionDesired = true
	if !dns.IsFqdn(qname) {
		return q
	}
	wire, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	out := new(dns.Msg)
	if err := out.Unpack(wire); err != nil {
		t.Fatal(err)
	}
	return out
}

// requireLocalReply checks that m is the reply to req with rcode and no
// records, as a recursive resolver sends it.
func requireLocalReply(t *testing.T, req, m *dns.Msg, rcode int) {
	t.Helper()
	if m == nil {
		t.Fatal("client got no reply")
	}
	if m.Rcode != rcode || !m.Response || !m.RecursionAvailable || !m.RecursionDesired ||
		m.Authoritative || m.Id != req.Id {
		t.Errorf("header = %+v; want rcode %d, QR, RA, RD, no AA, id %d", m.MsgHdr, rcode, req.Id)
	}
	if len(m.Question) != 1 || m.Question[0] != req.Question[0] {
		t.Errorf("question = %v, want %v", m.Question, req.Question)
	}
	if len(m.Answer)+len(m.Ns)+len(m.Extra) != 0 {
		t.Errorf("client got records:\n%v", m)
	}
}

func TestServeDNSAnswersUpgradeSignalsLocally(t *testing.T) {
	tests := []struct {
		qname string
		qtype uint16
		want  int
	}{
		{"_dns.resolver.arpa.", dns.TypeSVCB, dns.RcodeSuccess},
		{"_dns.resolver.arpa.", dns.TypeHTTPS, dns.RcodeSuccess},
		{"_dns.resolver.arpa.", dns.TypeA, dns.RcodeSuccess},
		{"_dns.resolver.arpa.", dns.TypeAAAA, dns.RcodeSuccess},
		{"_dns.resolver.arpa.", dns.TypeANY, dns.RcodeSuccess},
		{"_DNS.Resolver.ARPA.", dns.TypeSVCB, dns.RcodeSuccess},
		{"_dns.resolver.arpa", dns.TypeSVCB, dns.RcodeSuccess},
		{"x._dns.resolver.arpa.", dns.TypeSVCB, dns.RcodeSuccess},
		{"resolver.arpa.", dns.TypeSOA, dns.RcodeSuccess},
		{"foo.resolver.arpa.", dns.TypeA, dns.RcodeSuccess},
		{"x_dns.resolver.arpa.", dns.TypeSVCB, dns.RcodeSuccess},
		{`x\._dns.resolver.arpa.`, dns.TypeSVCB, dns.RcodeSuccess},
		{"use-application-dns.net.", dns.TypeA, dns.RcodeNameError},
		{"use-application-dns.net.", dns.TypeAAAA, dns.RcodeNameError},
		{"use-application-dns.net.", dns.TypeHTTPS, dns.RcodeNameError},
		{"USE-Application-DNS.NET.", dns.TypeA, dns.RcodeNameError},
		{"use-application-dns.net", dns.TypeA, dns.RcodeNameError},
		{"a.b.use-application-dns.net.", dns.TypeA, dns.RcodeNameError},
	}
	for _, tt := range tests {
		t.Run(tt.qname+"/"+dns.TypeToString[tt.qtype], func(t *testing.T) {
			var rep recorder
			up := &upstream{answer: []dns.RR{rr("example.org. 300 IN A 192.0.2.1")}}
			h := &handler{key: testKey, next: up, reporter: &rep, timeout: time.Second}
			req := fromWire(t, tt.qname, tt.qtype)
			rec := dnstest.NewRecorder(&test.ResponseWriter{})

			rcode, err := h.ServeDNS(t.Context(), rec, req)
			if err != nil || rcode != tt.want {
				t.Fatalf("ServeDNS = %d, %v; want %d, nil", rcode, err, tt.want)
			}
			if up.sent != nil {
				t.Error("the next plugin got the query")
			}
			if n := rep.calls.Load(); n != 0 {
				t.Errorf("reports = %d, want 0", n)
			}
			requireLocalReply(t, req, rec.Msg, tt.want)
		})
	}
}

func TestServeDNSForwardsLookAlikesOfUpgradeSignals(t *testing.T) {
	for _, qname := range []string{
		"arpa.",
		`_dns\.resolver.arpa.`,
		"_dns.resolver.arpa.evil.",
		"resolver.arpa.evil.",
		"net.",
		"application-dns.net.",
		"notuse-application-dns.net.",
		`x\.use-application-dns.net.`,
		"use-application-dns.net.evil.",
	} {
		t.Run(qname, func(t *testing.T) {
			var rep recorder
			up := &upstream{answer: []dns.RR{rr("example.org. 300 IN A 192.0.2.1")}}
			h := &handler{key: testKey, next: up, reporter: &rep, timeout: time.Second}
			req := fromWire(t, qname, dns.TypeA)
			rec := dnstest.NewRecorder(&test.ResponseWriter{})

			rcode, err := h.ServeDNS(t.Context(), rec, req)
			if err != nil || rcode != dns.RcodeSuccess {
				t.Fatalf("ServeDNS = %d, %v; want NOERROR, nil", rcode, err)
			}
			if up.sent == nil {
				t.Fatal("the next plugin did not get the query")
			}
			if n := rep.calls.Load(); n != 1 {
				t.Errorf("reports = %d, want 1", n)
			}
			if rec.Msg == nil || len(rec.Msg.Answer) != 1 {
				t.Errorf("client got %v, want the upstream answer", rec.Msg)
			}
		})
	}
}

// failWriter refuses every reply.
type failWriter struct{ test.ResponseWriter }

var errFailWrite = errors.New("write failed")

func (*failWriter) WriteMsg(*dns.Msg) error { return errFailWrite }

// A local reply that cannot be written is SERVFAIL, so the server writes
// the error reply.
func TestServeDNSLocalReplyWriteError(t *testing.T) {
	for _, qname := range []string{"_dns.resolver.arpa.", "use-application-dns.net."} {
		t.Run(qname, func(t *testing.T) {
			var rep recorder
			up := &upstream{}
			h := &handler{key: testKey, next: up, reporter: &rep, timeout: time.Second}
			rcode, err := h.ServeDNS(t.Context(), &failWriter{}, fromWire(t, qname, dns.TypeA))
			if rcode != dns.RcodeServerFailure || !errors.Is(err, errFailWrite) {
				t.Errorf("ServeDNS = %d, %v; want SERVFAIL, %v", rcode, err, errFailWrite)
			}
			if up.sent != nil || rep.calls.Load() != 0 {
				t.Errorf("next got the query = %t, reports = %d; want neither", up.sent != nil, rep.calls.Load())
			}
		})
	}
}

// TestUpgradeSignalsThroughCoreDNS checks the local replies on the real
// server path: the server adds EDNS to them as to every other reply. No
// ifboundd listens, so a query that goes to the report gets SERVFAIL.
func TestUpgradeSignalsThroughCoreDNS(t *testing.T) {
	addr := startCoreDNS(t, rewriteCorefile, socketPath(t))
	tests := []struct {
		qname string
		qtype uint16
		want  int
	}{
		{"_dns.resolver.arpa.", dns.TypeSVCB, dns.RcodeSuccess},
		{"use-application-dns.net.", dns.TypeA, dns.RcodeNameError},
	}
	for _, tt := range tests {
		t.Run(tt.qname, func(t *testing.T) {
			q := new(dns.Msg).SetQuestion(tt.qname, tt.qtype)
			q.SetEdns0(1232, true)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			m, err := dns.ExchangeContext(ctx, q, addr)
			if err != nil {
				t.Fatal(err)
			}
			if m.Rcode != tt.want || len(m.Answer)+len(m.Ns) != 0 {
				t.Errorf("client got %v, want rcode %d without records", m, tt.want)
			}
			if opt := m.IsEdns0(); opt == nil || !opt.Do() {
				t.Errorf("reply OPT = %v, want EDNS with DO", opt)
			}
		})
	}
	if r := ask(t, addr, "app.corp.example."); r.Rcode != dns.RcodeServerFailure {
		t.Errorf("other query got %v, want SERVFAIL without ifboundd", r)
	}
}
