package dnsplugin

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"

	"github.com/Nagato-Yuzuru/ifbound/internal/ipc"
)

type reporterFunc func(ctx context.Context, o ipc.Observation) error

func (f reporterFunc) Report(ctx context.Context, o ipc.Observation) error { return f(ctx, o) }

// recorder is a reporter that acks and keeps every observation.
type recorder struct {
	calls atomic.Int32
	last  atomic.Pointer[ipc.Observation]
}

func (r *recorder) Report(_ context.Context, o ipc.Observation) error {
	r.calls.Add(1)
	r.last.Store(&o)
	return nil
}

// rr parses a record in zone file form. A test fixture that does not parse
// is a bug in the test.
func rr(s string) dns.RR {
	r, err := dns.NewRR(s)
	if err != nil {
		panic(err)
	}
	return r
}

// upstream is a fake next plugin. It writes one reply and returns rcode.
type upstream struct {
	rcode             int
	tc                bool
	answer, ns, extra []dns.RR
	sent              *dns.Msg
}

func (u *upstream) ServeDNS(_ context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	m := new(dns.Msg).SetRcode(r, u.rcode)
	m.Truncated = u.tc
	m.Answer, m.Ns, m.Extra = u.answer, u.ns, u.extra
	u.sent = m.Copy()
	if err := w.WriteMsg(m); err != nil {
		return dns.RcodeServerFailure, err
	}
	return u.rcode, nil
}

func (*upstream) Name() string { return "upstream" }

func serve(ctx context.Context, h *handler, qname string) (*dnstest.Recorder, int, error) {
	req := new(dns.Msg).SetQuestion(qname, dns.TypeA)
	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	rcode, err := h.ServeDNS(ctx, rec, req)
	return rec, rcode, err
}

func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}

func TestServeDNSReportsEveryAddressBeforeTheReply(t *testing.T) {
	tests := []struct {
		name  string
		qname string
		up    upstream
		want  ipc.Observation
	}{
		{
			name:  "A",
			qname: "example.org.",
			up:    upstream{answer: []dns.RR{rr("example.org. 300 IN A 192.0.2.1")}},
			want:  ipc.Observation{QName: "example.org.", Addrs: addrs("192.0.2.1"), TTL: 300 * time.Second},
		},
		{
			name:  "AAAA",
			qname: "example.org.",
			up:    upstream{answer: []dns.RR{rr("example.org. 300 IN AAAA 2001:db8::1")}},
			want:  ipc.Observation{QName: "example.org.", Addrs: addrs("2001:db8::1"), TTL: 300 * time.Second},
		},
		{
			name:  "HTTPS hints",
			qname: "example.org.",
			up: upstream{answer: []dns.RR{
				rr(`example.org. 300 IN HTTPS 1 . alpn=h2 ipv4hint=192.0.2.1,192.0.2.2 ipv6hint=2001:db8::1`),
			}},
			want: ipc.Observation{
				QName: "example.org.", Addrs: addrs("192.0.2.1", "192.0.2.2", "2001:db8::1"), TTL: 300 * time.Second,
			},
		},
		{
			name:  "SVCB hints",
			qname: "_dns.example.org.",
			up: upstream{answer: []dns.RR{
				rr(`_dns.example.org. 300 IN SVCB 1 dns.example.org. ipv4hint=192.0.2.3 ipv6hint=2001:db8::3`),
			}},
			want: ipc.Observation{
				QName: "_dns.example.org.", Addrs: addrs("192.0.2.3", "2001:db8::3"), TTL: 300 * time.Second,
				Aliases: []ipc.Alias{{Name: "dns.example.org.", TTL: 300 * time.Second}},
			},
		},
		{
			name:  "CNAME chain under the original qname with the smallest link TTL",
			qname: "www.example.org.",
			up: upstream{answer: []dns.RR{
				rr("www.example.org. 600 IN CNAME a.example.net."),
				rr("a.example.net. 120 IN CNAME b.example.com."),
				rr("b.example.com. 300 IN A 192.0.2.4"),
			}},
			want: ipc.Observation{
				QName: "www.example.org.", Addrs: addrs("192.0.2.4"), TTL: 120 * time.Second,
				Aliases: []ipc.Alias{{Name: "a.example.net.", TTL: 600 * time.Second}, {Name: "b.example.com.", TTL: 120 * time.Second}},
			},
		},
		{
			name:  "qname as presented, chain matched without case",
			qname: `WWW.Ex\.ample.org.`,
			up: upstream{answer: []dns.RR{
				rr(`www.ex\.ample.org. 30 IN CNAME b.example.com.`),
				rr("b.example.com. 300 IN A 192.0.2.4"),
			}},
			want: ipc.Observation{
				QName: `WWW.Ex\.ample.org.`, Addrs: addrs("192.0.2.4"), TTL: 30 * time.Second,
				Aliases: []ipc.Alias{{Name: "b.example.com.", TTL: 30 * time.Second}},
			},
		},
		{
			name:  "minimum TTL among address records",
			qname: "example.org.",
			up: upstream{answer: []dns.RR{
				rr("example.org. 300 IN A 192.0.2.1"),
				rr("example.org. 60 IN A 192.0.2.2"),
			}},
			want: ipc.Observation{QName: "example.org.", Addrs: addrs("192.0.2.1", "192.0.2.2"), TTL: 60 * time.Second},
		},
		{
			name:  "TTL zero",
			qname: "example.org.",
			up:    upstream{answer: []dns.RR{rr("example.org. 0 IN A 192.0.2.1")}},
			want:  ipc.Observation{QName: "example.org.", Addrs: addrs("192.0.2.1"), TTL: 0},
		},
		{
			name:  "address off the CNAME chain is reported under the qname",
			qname: "www.example.org.",
			up: upstream{answer: []dns.RR{
				rr("www.example.org. 300 IN CNAME a.example.net."),
				rr("a.example.net. 300 IN A 192.0.2.4"),
				rr("evil.example. 50 IN A 198.51.100.1"),
			}},
			want: ipc.Observation{
				QName: "www.example.org.", Addrs: addrs("192.0.2.4", "198.51.100.1"), TTL: 50 * time.Second,
				Aliases: []ipc.Alias{{Name: "a.example.net.", TTL: 300 * time.Second}},
			},
		},
		{
			name:  "CNAME loop ends",
			qname: "a.example.",
			up: upstream{answer: []dns.RR{
				rr("a.example. 300 IN CNAME b.example."),
				rr("b.example. 200 IN CNAME a.example."),
				rr("c.example. 300 IN A 192.0.2.5"),
			}},
			want: ipc.Observation{
				QName: "a.example.", Addrs: addrs("192.0.2.5"), TTL: 200 * time.Second,
				Aliases: []ipc.Alias{{Name: "b.example.", TTL: 300 * time.Second}},
			},
		},
		{
			name:  "additional and authority sections",
			qname: "example.org.",
			up: upstream{
				answer: []dns.RR{rr(`example.org. 300 IN HTTPS 1 svc.example.org. alpn=h2`)},
				ns:     []dns.RR{rr("ns.example.org. 300 IN AAAA 2001:db8::53")},
				extra:  []dns.RR{rr("svc.example.org. 90 IN A 192.0.2.6")},
			},
			want: ipc.Observation{
				QName: "example.org.", Addrs: addrs("192.0.2.6", "2001:db8::53"), TTL: 90 * time.Second,
				Aliases: []ipc.Alias{{Name: "svc.example.org.", TTL: 300 * time.Second}},
			},
		},
		{
			name:  "truncated reply reports what it carries",
			qname: "example.org.",
			up:    upstream{tc: true, answer: []dns.RR{rr("example.org. 300 IN A 192.0.2.1")}},
			want:  ipc.Observation{QName: "example.org.", Addrs: addrs("192.0.2.1"), TTL: 300 * time.Second},
		},
		{
			name:  "A record in generic form is read as the client reads it",
			qname: "example.org.",
			up: upstream{answer: []dns.RR{&dns.RFC3597{
				Hdr:   dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				Rdata: "c0000201",
			}}},
			want: ipc.Observation{QName: "example.org.", Addrs: addrs("192.0.2.1"), TTL: 300 * time.Second},
		},
		{
			name:  "hint in generic form is read as the client reads it",
			qname: "example.org.",
			up: upstream{answer: []dns.RR{&dns.SVCB{
				Hdr:      dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeSVCB, Class: dns.ClassINET, Ttl: 300},
				Priority: 1, Target: ".",
				Value: []dns.SVCBKeyValue{&dns.SVCBLocal{KeyCode: dns.SVCB_IPV4HINT, Data: []byte{192, 0, 2, 8}}},
			}}},
			want: ipc.Observation{QName: "example.org.", Addrs: addrs("192.0.2.8"), TTL: 300 * time.Second},
		},
		{
			// The TXT value "abc" packs as rdata 03 61 62 63, which a client
			// decodes as A 3.97.98.99.
			name:  "TXT value with type A is read as the client reads it",
			qname: "example.org.",
			up: upstream{answer: []dns.RR{&dns.TXT{
				Hdr: dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				Txt: []string{"abc"},
			}}},
			want: ipc.Observation{QName: "example.org.", Addrs: addrs("3.97.98.99"), TTL: 300 * time.Second},
		},
		{
			// miekg/dns packs only the IPv4 form of an A value; a client
			// decodes 0.0.0.0 from this one.
			name:  "A value with an IPv6 address is read as the client reads it",
			qname: "example.org.",
			up: upstream{answer: []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("2001:db8::1"),
			}}},
			want: ipc.Observation{QName: "example.org.", Addrs: addrs("0.0.0.0"), TTL: 300 * time.Second},
		},
		{
			name:  "IPv4-mapped AAAA is reported in IPv4 form",
			qname: "example.org.",
			up:    upstream{answer: []dns.RR{rr("example.org. 300 IN AAAA ::ffff:192.0.2.1")}},
			want:  ipc.Observation{QName: "example.org.", Addrs: addrs("192.0.2.1"), TTL: 300 * time.Second},
		},
		{
			name:  "duplicate addresses collapse",
			qname: "example.org.",
			up: upstream{answer: []dns.RR{
				rr("example.org. 300 IN A 192.0.2.1"),
				rr(`example.org. 300 IN HTTPS 1 . ipv4hint=192.0.2.1`),
			}},
			want: ipc.Observation{QName: "example.org.", Addrs: addrs("192.0.2.1"), TTL: 300 * time.Second},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rep recorder
			h := &handler{next: &tt.up, reporter: &rep, timeout: time.Second}
			rec, rcode, err := serve(t.Context(), h, tt.qname)
			if err != nil || rcode != dns.RcodeSuccess {
				t.Fatalf("ServeDNS = %d, %v; want success", rcode, err)
			}
			if n := rep.calls.Load(); n != 1 {
				t.Fatalf("reports = %d, want 1", n)
			}
			got := *rep.last.Load()
			if got.QName != tt.want.QName || got.TTL != tt.want.TTL || !slices.Equal(got.Addrs, tt.want.Addrs) ||
				!slices.Equal(got.Aliases, tt.want.Aliases) {
				t.Errorf("observation = %+v, want %+v", got, tt.want)
			}
			if want := onWire(t, tt.up.sent); rec.Msg == nil || rec.Msg.String() != want.String() {
				t.Errorf("client got\n%v\nwant\n%v", rec.Msg, want)
			}
			requireReported(t, rec.Msg, got.Addrs)
			requireAliasesReported(t, tt.qname, rec.Msg, got.Aliases)
		})
	}
}

func TestServeDNSReportsAliases(t *testing.T) {
	type alias = ipc.Alias
	tests := []struct {
		name  string
		qname string
		up    upstream
		want  []alias
		ttl   time.Duration // the address TTL
	}{
		{
			name:  "CNAME chain of length 1",
			qname: "www.example.org.",
			up: upstream{answer: []dns.RR{
				rr("www.example.org. 600 IN CNAME a.example.net."),
				rr("a.example.net. 300 IN A 192.0.2.1"),
			}},
			want: []alias{{Name: "a.example.net.", TTL: 600 * time.Second}},
			ttl:  300 * time.Second,
		},
		{
			name:  "CNAME chain of length 3, each alias with the TTL of its link",
			qname: "www.example.org.",
			up: upstream{answer: []dns.RR{
				rr("b.example.net. 60 IN CNAME c.example.com."),
				rr("www.example.org. 600 IN CNAME a.example.net."),
				rr("a.example.net. 120 IN CNAME b.example.net."),
				rr("c.example.com. 300 IN A 192.0.2.1"),
			}},
			want: []alias{
				{Name: "a.example.net.", TTL: 600 * time.Second},
				{Name: "b.example.net.", TTL: 120 * time.Second},
				{Name: "c.example.com.", TTL: 60 * time.Second},
			},
			ttl: 60 * time.Second,
		},
		{
			name:  "CNAME TTLs that do not fall along the chain",
			qname: "www.example.org.",
			up: upstream{answer: []dns.RR{
				rr("www.example.org. 10 IN CNAME a.example.net."),
				rr("a.example.net. 600 IN CNAME b.example.net."),
				rr("b.example.net. 300 IN A 192.0.2.1"),
			}},
			want: []alias{{Name: "a.example.net.", TTL: 10 * time.Second}, {Name: "b.example.net.", TTL: 600 * time.Second}},
			ttl:  10 * time.Second,
		},
		{
			name:  "branching CNAMEs: every target the client can follow",
			qname: "www.example.org.",
			up: upstream{answer: []dns.RR{
				rr("www.example.org. 300 IN CNAME a.example.net."),
				rr("WWW.example.org. 30 IN CNAME evil.example."),
				rr("a.example.net. 60 IN CNAME b.example.net."),
				rr("evil.example. 90 IN CNAME B.example.net."),
				rr("b.example.net. 300 IN A 192.0.2.1"),
			}},
			want: []alias{
				{Name: "a.example.net.", TTL: 300 * time.Second},
				{Name: "evil.example.", TTL: 30 * time.Second},
				{Name: "b.example.net.", TTL: 90 * time.Second},
			},
			ttl: 30 * time.Second,
		},
		{
			name:  "CNAME target root is no alias",
			qname: "www.example.org.",
			up: upstream{answer: []dns.RR{
				rr("www.example.org. 300 IN CNAME a.example.net."),
				rr("a.example.net. 300 IN CNAME ."),
			}},
			want: []alias{{Name: "a.example.net.", TTL: 300 * time.Second}},
		},
		{
			name:  "CNAME loop stops; a CNAME off the chain is no alias",
			qname: "a.example.",
			up: upstream{answer: []dns.RR{
				rr("a.example. 300 IN CNAME b.example."),
				rr("b.example. 200 IN CNAME c.example."),
				rr("c.example. 100 IN CNAME B.example."),
				rr("x.example. 100 IN CNAME y.example."),
			}},
			want: []alias{{Name: "b.example.", TTL: 300 * time.Second}, {Name: "c.example.", TTL: 200 * time.Second}},
		},
		{
			name:  "CNAME loop back to the qname",
			qname: "a.example.",
			up: upstream{answer: []dns.RR{
				rr("a.example. 300 IN CNAME b.example."),
				rr("b.example. 200 IN CNAME A.example."),
			}},
			want: []alias{{Name: "b.example.", TTL: 300 * time.Second}},
		},
		{
			name:  "only a CNAME, no address",
			qname: "example.org.",
			up: upstream{
				answer: []dns.RR{rr("example.org. 300 IN CNAME a.example.net.")},
				ns:     []dns.RR{rr("example.net. 300 IN SOA ns.example.net. host.example.net. 1 7200 3600 1209600 300")},
			},
			want: []alias{{Name: "a.example.net.", TTL: 300 * time.Second}},
		},
		{
			name:  "HTTPS ServiceMode target in the answer",
			qname: "example.org.",
			up:    upstream{answer: []dns.RR{rr("example.org. 120 IN HTTPS 1 svc.example.net. alpn=h2 ipv4hint=192.0.2.1")}},
			want:  []alias{{Name: "svc.example.net.", TTL: 120 * time.Second}},
			ttl:   120 * time.Second,
		},
		{
			name:  "HTTPS AliasMode target in the answer, no address",
			qname: "example.org.",
			up:    upstream{answer: []dns.RR{rr("example.org. 120 IN HTTPS 0 pool.example.net.")}},
			want:  []alias{{Name: "pool.example.net.", TTL: 120 * time.Second}},
		},
		{
			name:  "HTTPS targets in the additional section",
			qname: "www.example.org.",
			up: upstream{
				answer: []dns.RR{rr("www.example.org. 300 IN A 192.0.2.1")},
				extra: []dns.RR{
					rr("www.example.org. 90 IN HTTPS 1 svc.example.net."),
					rr("other.example. 45 IN HTTPS 0 pool.example.net."),
				},
			},
			want: []alias{{Name: "svc.example.net.", TTL: 90 * time.Second}, {Name: "pool.example.net.", TTL: 45 * time.Second}},
			ttl:  300 * time.Second,
		},
		{
			name:  "HTTPS target in the authority section",
			qname: "example.org.",
			up: upstream{
				answer: []dns.RR{rr("example.org. 300 IN A 192.0.2.1")},
				ns:     []dns.RR{rr("other.example. 75 IN HTTPS 1 svc.example.net.")},
			},
			want: []alias{{Name: "svc.example.net.", TTL: 75 * time.Second}},
			ttl:  300 * time.Second,
		},
		{
			name:  "SVCB target",
			qname: "_dns.example.org.",
			up:    upstream{answer: []dns.RR{rr("_dns.example.org. 60 IN SVCB 0 dns.example.net.")}},
			want:  []alias{{Name: "dns.example.net.", TTL: 60 * time.Second}},
		},
		{
			name:  "target dot and target equal to the owner are no aliases",
			qname: "example.org.",
			up: upstream{answer: []dns.RR{
				rr("example.org. 300 IN HTTPS 1 . ipv4hint=192.0.2.1"),
				rr("example.org. 300 IN HTTPS 2 EXAMPLE.org. ipv4hint=192.0.2.2"),
				rr("_dns.example.org. 300 IN SVCB 1 _dns.example.org. ipv4hint=192.0.2.3"),
				rr("example.org. 300 IN HTTPS 0 ."),
			}},
			ttl: 300 * time.Second,
		},
		{
			name:  "duplicate names collapse to the first form with the largest TTL",
			qname: "www.example.org.",
			up: upstream{
				answer: []dns.RR{
					rr("www.example.org. 30 IN CNAME cdn.example.net."),
					rr("cdn.example.net. 60 IN HTTPS 1 svc.example.net."),
					rr("cdn.example.net. 300 IN HTTPS 2 SVC.example.net."),
				},
				extra: []dns.RR{rr("x.example. 600 IN HTTPS 1 CDN.example.net.")},
			},
			want: []alias{{Name: "cdn.example.net.", TTL: 600 * time.Second}, {Name: "svc.example.net.", TTL: 300 * time.Second}},
		},
		{
			name:  "the walk goes on through the root",
			qname: "q.example.",
			up: upstream{answer: []dns.RR{
				rr("q.example. 30 IN CNAME ."),
				rr(". 40 IN CNAME z.example."),
			}},
			want: []alias{{Name: "z.example.", TTL: 40 * time.Second}},
		},
		{
			name:  "root query: the root is no alias, its CNAME target is",
			qname: ".",
			up:    upstream{answer: []dns.RR{rr(". 60 IN CNAME a.example."), rr("a.example. 70 IN CNAME .")}},
			want:  []alias{{Name: "a.example.", TTL: 60 * time.Second}},
		},
		{
			name:  "a CNAME and an HTTPS record to one name: the largest TTL",
			qname: "q.example.",
			up: upstream{answer: []dns.RR{
				rr("q.example. 15 IN CNAME w.example."),
				rr("w.example. 8 IN HTTPS 1 svc.example."),
				rr("q.example. 99 IN HTTPS 1 W.example."),
			}},
			want: []alias{{Name: "w.example.", TTL: 99 * time.Second}, {Name: "svc.example.", TTL: 8 * time.Second}},
		},
		{
			// miekg/dns presents the octet 0x20 as "\ ".
			name:  "escaped octets keep the presentation form that the client decodes",
			qname: `q\.x.example.`,
			up:    upstream{answer: []dns.RR{rr(`Q\.X.example. 60 IN CNAME a\032b.\195\175.example.`)}},
			want:  []alias{{Name: `a\ b.\195\175.example.`, TTL: 60 * time.Second}},
		},
		{
			name:  "names in the presentation form that the client decodes",
			qname: "www.example.org.",
			up: upstream{answer: []dns.RR{
				rr(`www.example.org. 30 IN CNAME Cdn\.x.Example.NET.`),
				rr(`Cdn\.x.Example.NET. 30 IN HTTPS 1 \195\175.example.net.`),
			}},
			want: []alias{{Name: `Cdn\.x.Example.NET.`, TTL: 30 * time.Second}, {Name: `\195\175.example.net.`, TTL: 30 * time.Second}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rep recorder
			h := &handler{next: &tt.up, reporter: &rep, timeout: time.Second}
			rec, rcode, err := serve(t.Context(), h, tt.qname)
			if err != nil || rcode != dns.RcodeSuccess {
				t.Fatalf("ServeDNS = %d, %v; want success", rcode, err)
			}
			if n := rep.calls.Load(); n != 1 {
				t.Fatalf("reports = %d, want 1", n)
			}
			got := *rep.last.Load()
			if got.QName != tt.qname || got.TTL != tt.ttl || !slices.Equal(got.Aliases, tt.want) {
				t.Errorf("observation = %+v, want aliases %+v and TTL %v", got, tt.want, tt.ttl)
			}
			if want := onWire(t, tt.up.sent); rec.Msg == nil || rec.Msg.String() != want.String() {
				t.Errorf("client got\n%v\nwant\n%v", rec.Msg, want)
			}
			requireReported(t, rec.Msg, got.Addrs)
			requireAliasesReported(t, tt.qname, rec.Msg, got.Aliases)
		})
	}
}

// onWire returns m as a client decodes it.
func onWire(t *testing.T, m *dns.Msg) *dns.Msg {
	t.Helper()
	buf, err := m.Pack()
	if err != nil {
		t.Fatalf("packing %v: %v", m, err)
	}
	out := new(dns.Msg)
	if err := out.Unpack(buf); err != nil {
		t.Fatalf("unpacking: %v", err)
	}
	return out
}

// requireReported fails the test when the client can decode an address
// from sent that is not in reported. It reads the records independently of
// the code under test.
func requireReported(t *testing.T, sent *dns.Msg, reported []netip.Addr) {
	t.Helper()
	var ips []net.IP
	m := onWire(t, sent)
	for _, section := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, r := range section {
			switch r := r.(type) {
			case *dns.A:
				ips = append(ips, r.A)
			case *dns.AAAA:
				ips = append(ips, r.AAAA)
			case *dns.SVCB:
				ips = append(ips, hints(r.Value)...)
			case *dns.HTTPS:
				ips = append(ips, hints(r.Value)...)
			}
		}
	}
	for _, ip := range ips {
		a, _ := netip.AddrFromSlice(ip)
		if !slices.Contains(reported, a.Unmap()) {
			t.Errorf("client can decode %v, but the report has only %v", ip, reported)
		}
	}
}

func hints(kvs []dns.SVCBKeyValue) []net.IP {
	var out []net.IP
	for _, kv := range kvs {
		switch kv := kv.(type) {
		case *dns.SVCBIPv4Hint:
			out = append(out, kv.Hint...)
		case *dns.SVCBIPv6Hint:
			out = append(out, kv.Hint...)
		}
	}
	return out
}

func TestServeDNSPassesThroughWithoutAddress(t *testing.T) {
	soa := rr("example.org. 300 IN SOA ns.example.org. host.example.org. 1 7200 3600 1209600 300")
	tests := []struct {
		name string
		up   upstream
	}{
		{name: "NXDOMAIN", up: upstream{rcode: dns.RcodeNameError, ns: []dns.RR{soa}}},
		{name: "NODATA", up: upstream{ns: []dns.RR{soa}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rep recorder
			h := &handler{next: &tt.up, reporter: &rep, timeout: time.Second}
			rec, rcode, err := serve(t.Context(), h, "example.org.")
			if err != nil || rcode != tt.up.rcode {
				t.Fatalf("ServeDNS = %d, %v; want %d, nil", rcode, err, tt.up.rcode)
			}
			if n := rep.calls.Load(); n != 0 {
				t.Errorf("reports = %d, want 0", n)
			}
			if rec.Msg == nil || rec.Msg.String() != tt.up.sent.String() {
				t.Errorf("client got\n%v\nwant\n%v", rec.Msg, tt.up.sent)
			}
		})
	}
}

func TestServeDNSPassesThroughUpstreamError(t *testing.T) {
	errUpstream := errors.New("upstream timeout")
	next := plugin.HandlerFunc(func(context.Context, dns.ResponseWriter, *dns.Msg) (int, error) {
		return dns.RcodeServerFailure, errUpstream
	})
	var rep recorder
	h := &handler{next: next, reporter: &rep, timeout: time.Second}
	rec, rcode, err := serve(t.Context(), h, "example.org.")
	if rcode != dns.RcodeServerFailure || !errors.Is(err, errUpstream) {
		t.Errorf("ServeDNS = %d, %v; want SERVFAIL, %v", rcode, err, errUpstream)
	}
	if rep.calls.Load() != 0 || rec.Msg != nil {
		t.Errorf("reports = %d, client got %v; want none", rep.calls.Load(), rec.Msg)
	}
}

// writeA writes one A reply, then calls more with the writer.
func writeA(more func(w dns.ResponseWriter, m *dns.Msg) (int, error)) plugin.HandlerFunc {
	return func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
		m := new(dns.Msg).SetReply(r)
		m.Answer = []dns.RR{rr("example.org. 300 IN A 192.0.2.1")}
		if err := w.WriteMsg(m); err != nil {
			return dns.RcodeServerFailure, err
		}
		return more(w, m)
	}
}

func done(dns.ResponseWriter, *dns.Msg) (int, error) { return dns.RcodeSuccess, nil }

// manyHTTPS returns n HTTPS records for example.org., each with its own
// target.
func manyHTTPS(n int) []dns.RR {
	out := make([]dns.RR, n)
	for i := range out {
		out[i] = rr(fmt.Sprintf("example.org. 300 IN HTTPS %d t%d.example.net.", i+1, i))
	}
	return out
}

// answerWith returns a next plugin that writes rrs in the answer section.
func answerWith(rrs ...dns.RR) plugin.Handler { return &upstream{answer: rrs} }

func TestServeDNSFailsClosed(t *testing.T) {
	ack := reporterFunc(func(context.Context, ipc.Observation) error { return nil })
	tests := []struct {
		name     string
		next     plugin.Handler
		reporter reporter
		cancel   bool // cancel the request context before ServeDNS
		reported bool // the reply reaches the reporter
		want     error
	}{
		{
			name:     "reporter error",
			next:     writeA(done),
			reporter: reporterFunc(func(context.Context, ipc.Observation) error { return ipc.ErrUnavailable }),
			reported: true,
			want:     ipc.ErrUnavailable,
		},
		{
			name: "reporter does not ack before the timeout",
			next: writeA(done),
			reporter: reporterFunc(func(ctx context.Context, _ ipc.Observation) error {
				<-ctx.Done()
				return ctx.Err()
			}),
			reported: true,
			want:     context.DeadlineExceeded,
		},
		{
			name: "ack after the timeout",
			next: writeA(done),
			reporter: reporterFunc(func(ctx context.Context, _ ipc.Observation) error {
				<-ctx.Done()
				return nil
			}),
			reported: true,
			want:     errLateAck,
		},
		{
			name: "request context ends",
			next: writeA(done),
			reporter: reporterFunc(func(ctx context.Context, _ ipc.Observation) error {
				return ctx.Err()
			}),
			cancel:   true,
			reported: true,
			want:     context.Canceled,
		},
		{
			name:     "report of an alias without address rejected",
			next:     answerWith(rr("example.org. 300 IN CNAME a.example.net.")),
			reporter: reporterFunc(func(context.Context, ipc.Observation) error { return ipc.ErrRejected }),
			reported: true,
			want:     ipc.ErrRejected,
		},
		{
			name:     "more aliases than the report can carry",
			next:     answerWith(manyHTTPS(ipc.MaxAliases + 1)...),
			reporter: ack,
			want:     errTooManyAliases,
		},
		{
			name: "malformed ipv4hint",
			next: answerWith(&dns.HTTPS{SVCB: dns.SVCB{
				Hdr:      dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 300},
				Priority: 1, Target: ".",
				Value: []dns.SVCBKeyValue{&dns.SVCBIPv4Hint{Hint: []net.IP{{192, 0, 2}}}},
			}}),
			reporter: ack,
			want:     errUnreadable,
		},
		{
			name: "A record without address",
			next: answerWith(&dns.A{
				Hdr: dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			}),
			reporter: ack,
			want:     errBadAddr,
		},
		{
			name: "next writes twice",
			next: writeA(func(w dns.ResponseWriter, m *dns.Msg) (int, error) {
				_ = w.WriteMsg(m) // the error is what the test checks through ServeDNS
				return dns.RcodeSuccess, nil
			}),
			reporter: ack,
			want:     errTwoReplies,
		},
		{
			name: "next claims a reply but writes none",
			next: plugin.HandlerFunc(func(context.Context, dns.ResponseWriter, *dns.Msg) (int, error) {
				return dns.RcodeSuccess, nil
			}),
			reporter: ack,
			want:     errNoReply,
		},
		{
			name: "next writes raw bytes",
			next: plugin.HandlerFunc(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
				m := new(dns.Msg).SetReply(r)
				m.Answer = []dns.RR{rr("example.org. 300 IN A 192.0.2.1")}
				buf, err := m.Pack()
				if err != nil {
					return dns.RcodeServerFailure, err
				}
				_, _ = w.Write(buf) // the error is what the test checks through ServeDNS
				return dns.RcodeSuccess, nil
			}),
			reporter: ack,
			want:     errRawWrite,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls atomic.Int32
			rep := reporterFunc(func(ctx context.Context, o ipc.Observation) error {
				calls.Add(1)
				return tt.reporter.Report(ctx, o)
			})
			h := &handler{next: tt.next, reporter: rep, timeout: 20 * time.Millisecond}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tt.cancel {
				cancel()
			}
			rec, rcode, err := serve(ctx, h, "example.org.")
			if rcode != dns.RcodeServerFailure || !errors.Is(err, tt.want) {
				t.Errorf("ServeDNS = %d, %v; want SERVFAIL, %v", rcode, err, tt.want)
			}
			if err != nil && !strings.HasPrefix(err.Error(), "plugin/ifbound: ") {
				t.Errorf("error %q lacks the plugin prefix", err)
			}
			if rec.Msg != nil {
				t.Errorf("client got a reply:\n%v", rec.Msg)
			}
			if got := calls.Load() > 0; got != tt.reported {
				t.Errorf("reporter called = %v, want %v", got, tt.reported)
			}
		})
	}
}

func TestServeDNSDropsWriteAfterFailedReport(t *testing.T) {
	failed := make(chan struct{})
	late := make(chan error, 1)
	next := writeA(func(w dns.ResponseWriter, m *dns.Msg) (int, error) {
		go func() {
			<-failed
			late <- w.WriteMsg(m)
		}()
		return dns.RcodeSuccess, nil
	})
	rep := reporterFunc(func(context.Context, ipc.Observation) error {
		close(failed)
		return ipc.ErrRejected
	})
	h := &handler{next: next, reporter: rep, timeout: time.Second}
	rec, rcode, _ := serve(t.Context(), h, "example.org.")
	if err := <-late; !errors.Is(err, errLateWrite) {
		t.Errorf("late write error = %v, want %v", err, errLateWrite)
	}
	if rcode != dns.RcodeServerFailure || rec.Msg != nil {
		t.Errorf("ServeDNS = %d, client got %v; want SERVFAIL and no reply", rcode, rec.Msg)
	}
}

func TestReportDeadline(t *testing.T) {
	tests := []struct {
		name       string
		requestTTL time.Duration // 0: the request context has no deadline
		want       time.Duration
	}{
		{name: "directive timeout", want: 2 * time.Second},
		{name: "earlier request deadline", requestTTL: 300 * time.Millisecond, want: 300 * time.Millisecond},
		{name: "later request deadline", requestTTL: 5 * time.Second, want: 2 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var got time.Time
				rep := reporterFunc(func(ctx context.Context, _ ipc.Observation) error {
					got, _ = ctx.Deadline()
					return nil
				})
				h := &handler{next: writeA(done), reporter: rep, timeout: 2 * time.Second}
				ctx := t.Context()
				if tt.requestTTL > 0 {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, tt.requestTTL)
					defer cancel()
				}
				start := time.Now()
				if _, rcode, err := serve(ctx, h, "example.org."); rcode != dns.RcodeSuccess || err != nil {
					t.Fatalf("ServeDNS = %d, %v", rcode, err)
				}
				if d := got.Sub(start); d != tt.want {
					t.Errorf("report deadline = start + %s, want start + %s", d, tt.want)
				}
			})
		})
	}
}

func TestServeDNSSendsTheSnapshotItReported(t *testing.T) {
	tests := []struct {
		name string
		when string // when next changes the message that it wrote
	}{
		{name: "change before next returns", when: "before return"},
		{name: "change while the report is in flight", when: "during report"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inReport, changed := make(chan struct{}), make(chan struct{})
			change := func(m *dns.Msg) {
				m.Answer[0] = rr("example.org. 300 IN A 203.0.113.66")
				close(changed)
			}
			next := writeA(func(_ dns.ResponseWriter, m *dns.Msg) (int, error) {
				if tt.when == "before return" {
					change(m)
					return dns.RcodeSuccess, nil
				}
				go func() {
					<-inReport
					change(m)
				}()
				return dns.RcodeSuccess, nil
			})
			var reported []netip.Addr
			rep := reporterFunc(func(_ context.Context, o ipc.Observation) error {
				reported = o.Addrs
				close(inReport)
				<-changed
				return nil
			})
			h := &handler{next: next, reporter: rep, timeout: time.Second}
			rec, rcode, err := serve(t.Context(), h, "example.org.")
			if err != nil || rcode != dns.RcodeSuccess {
				t.Fatalf("ServeDNS = %d, %v; want success", rcode, err)
			}
			if !slices.Equal(reported, addrs("192.0.2.1")) {
				t.Errorf("reported %v, want [192.0.2.1]", reported)
			}
			requireReported(t, rec.Msg, reported)
		})
	}
}

// countingWriter counts the replies that reach the client.
type countingWriter struct {
	test.ResponseWriter
	msgs []*dns.Msg
}

func (c *countingWriter) WriteMsg(m *dns.Msg) error {
	c.msgs = append(c.msgs, m)
	return nil
}

// A next plugin may write a reply and still return a "not written" rcode
// (the nomad plugin does this with SERVFAIL). The handler sends that reply
// once and returns an rcode that stops the server from writing a second one.
func TestServeDNSWrittenReplyWithServfailRcodeGoesOutOnce(t *testing.T) {
	errNext := errors.New("lookup failed")
	tests := []struct {
		name   string
		answer []dns.RR
		rcode  int // the rcode of the written message
	}{
		{name: "SERVFAIL message", rcode: dns.RcodeServerFailure},
		{name: "answer with an address", answer: []dns.RR{rr("example.org. 300 IN A 192.0.2.1")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			next := plugin.HandlerFunc(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
				m := new(dns.Msg).SetRcode(r, tt.rcode)
				m.Answer = tt.answer
				if err := w.WriteMsg(m); err != nil {
					return dns.RcodeServerFailure, err
				}
				return dns.RcodeServerFailure, errNext
			})
			var rep recorder
			h := &handler{next: next, reporter: &rep, timeout: time.Second}
			cw := &countingWriter{}
			rcode, err := h.ServeDNS(t.Context(), cw, new(dns.Msg).SetQuestion("example.org.", dns.TypeA))
			if !plugin.ClientWrite(rcode) || !errors.Is(err, errNext) {
				t.Errorf("ServeDNS = %d, %v; want a written rcode and %v", rcode, err, errNext)
			}
			if len(cw.msgs) != 1 || cw.msgs[0].Rcode != tt.rcode {
				t.Fatalf("client got %d replies, want one with rcode %d", len(cw.msgs), tt.rcode)
			}
			if wantReports := int32(len(tt.answer)); rep.calls.Load() != wantReports {
				t.Errorf("reports = %d, want %d", rep.calls.Load(), wantReports)
			}
		})
	}
}

// The report names the question that the client asked, not the question in
// the reply that the next plugin wrote.
func TestServeDNSReportsTheRequestQName(t *testing.T) {
	next := plugin.HandlerFunc(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
		m := new(dns.Msg).SetReply(r)
		m.Question[0].Name = "other.example."
		m.Answer = []dns.RR{rr("other.example. 300 IN A 192.0.2.1")}
		return dns.RcodeSuccess, w.WriteMsg(m)
	})
	var rep recorder
	h := &handler{next: next, reporter: &rep, timeout: time.Second}
	if _, rcode, err := serve(t.Context(), h, "example.org."); rcode != dns.RcodeSuccess || err != nil {
		t.Fatalf("ServeDNS = %d, %v", rcode, err)
	}
	if o := rep.last.Load(); o == nil || o.QName != "example.org." {
		t.Errorf("report = %+v, want qname example.org.", o)
	}
}
