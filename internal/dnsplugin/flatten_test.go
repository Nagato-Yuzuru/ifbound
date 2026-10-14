package dnsplugin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"

	"github.com/Nagato-Yuzuru/ifbound/internal/ipc"
)

var errNotInZone = errors.New("question not in the fake zone")

// zone is a fake next plugin that answers each question from its own
// table, as a recursive resolver does. It records each question. A
// question that is not in the table gets no reply and SERVFAIL, as from a
// failed upstream.
type zone struct {
	replies map[string]zoneReply

	mu    sync.Mutex
	asked []string
	sent  map[string][]byte // the first reply to each question, packed
}

type zoneReply struct {
	rcode             int
	ad, tc            bool
	answer, ns, extra []string
}

func zkey(name string, qtype uint16) string {
	return dns.CanonicalName(name) + " " + dns.TypeToString[qtype]
}

func (z *zone) ServeDNS(_ context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	q := r.Question[0]
	key := zkey(q.Name, q.Qtype)
	z.mu.Lock()
	z.asked = append(z.asked, key)
	z.mu.Unlock()
	zr, ok := z.replies[key]
	if !ok {
		return dns.RcodeServerFailure, errNotInZone
	}
	m := new(dns.Msg).SetRcode(r, zr.rcode)
	m.RecursionAvailable, m.AuthenticatedData, m.Truncated = true, zr.ad, zr.tc
	for _, s := range zr.answer {
		m.Answer = append(m.Answer, rr(s))
	}
	for _, s := range zr.ns {
		m.Ns = append(m.Ns, rr(s))
	}
	for _, s := range zr.extra {
		m.Extra = append(m.Extra, rr(s))
	}
	if o := r.IsEdns0(); o != nil {
		m.SetEdns0(o.UDPSize(), o.Do())
	}
	if wire, err := m.Pack(); err == nil {
		z.mu.Lock()
		if z.sent == nil {
			z.sent = map[string][]byte{}
		}
		if _, ok := z.sent[key]; !ok {
			z.sent[key] = wire
		}
		z.mu.Unlock()
	}
	return zr.rcode, w.WriteMsg(m)
}

func (*zone) Name() string { return "zone" }

func (z *zone) questions() []string {
	z.mu.Lock()
	defer z.mu.Unlock()
	return slices.Clone(z.asked)
}

// zoneResult is what one query through the handler gave.
type zoneResult struct {
	reply *dns.Msg
	rcode int
	err   error
	rep   *recorder
}

func query(t *testing.T, h *handler, qname string, qtype uint16) zoneResult {
	t.Helper()
	req := new(dns.Msg).SetQuestion(qname, qtype)
	req.SetEdns0(4096, false)
	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	rcode, err := h.ServeDNS(t.Context(), rec, req)
	return zoneResult{reply: rec.Msg, rcode: rcode, err: err}
}

func askZone(t *testing.T, z *zone, protected bool, qname string, qtype uint16) zoneResult {
	t.Helper()
	rep := &recorder{protected: protected}
	h := &handler{key: testKey, next: z, reporter: rep, timeout: time.Second}
	res := query(t, h, qname, qtype)
	res.rep = rep
	return res
}

// records parses zone file lines, for a comparison by String.
func records(ss ...string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = rr(s).String()
	}
	return out
}

func strs(rrs []dns.RR) []string {
	out := make([]string, len(rrs))
	for i, r := range rrs {
		out[i] = r.String()
	}
	return out
}

const soaNet = "cdn.net. 900 IN SOA ns.cdn.net. host.cdn.net. 1 7200 3600 1209600 600"

// flattenCase is a protected query and the reply that the client must
// get.
type flattenCase struct {
	name      string
	qname     string
	qtype     uint16
	zone      map[string]zoneReply
	rcode     int
	answer    []string // zone file lines; nil when check is set
	check     func(t *testing.T, m *dns.Msg)
	ns        []string
	addrs     []string
	wantAsked []string // the questions after the first, when the chain needs completion
}

func TestFlattenProtectedReply(t *testing.T) {
	long := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 40) + ".example.com."
	tests := []flattenCase{
		{
			name:  "chain over several zones gets the qname and the smallest TTL",
			qname: "www.example.com.", qtype: dns.TypeA,
			zone: map[string]zoneReply{zkey("www.example.com.", dns.TypeA): {
				answer: []string{
					"www.example.com. 300 IN CNAME a.cdn.net.",
					"a.cdn.net. 60 IN CNAME b.edge.org.",
					"b.edge.org. 120 IN A 192.0.2.1",
					"b.edge.org. 600 IN A 192.0.2.2",
				},
				ns:    []string{"edge.org. 300 IN NS ns.edge.org."},
				extra: []string{"ns.edge.org. 300 IN A 198.51.100.53"},
			}},
			answer: []string{"www.example.com. 60 IN A 192.0.2.1", "www.example.com. 60 IN A 192.0.2.2"},
			addrs:  []string{"192.0.2.1", "192.0.2.2", "198.51.100.53"},
		},
		{
			name:  "the final TTL is the smallest when it is below the links",
			qname: "www.example.com.", qtype: dns.TypeAAAA,
			zone: map[string]zoneReply{zkey("www.example.com.", dns.TypeAAAA): {answer: []string{
				"www.example.com. 300 IN CNAME a.cdn.net.",
				"a.cdn.net. 20 IN AAAA 2001:db8::1",
			}}},
			answer: []string{"www.example.com. 20 IN AAAA 2001:db8::1"},
			addrs:  []string{"2001:db8::1"},
		},
		{
			name:  "chain that ends in NODATA keeps the SOA with a capped TTL",
			qname: "www.example.com.", qtype: dns.TypeAAAA,
			zone: map[string]zoneReply{zkey("www.example.com.", dns.TypeAAAA): {
				answer: []string{"www.example.com. 300 IN CNAME a.cdn.net."},
				ns:     []string{soaNet},
			}},
			ns: []string{"cdn.net. 300 IN SOA ns.cdn.net. host.cdn.net. 1 7200 3600 1209600 300"},
		},
		{
			name:  "chain that ends in NXDOMAIN keeps the rcode and the SOA",
			qname: "www.example.com.", qtype: dns.TypeA,
			zone: map[string]zoneReply{zkey("www.example.com.", dns.TypeA): {
				rcode:  dns.RcodeNameError,
				answer: []string{"www.example.com. 3600 IN CNAME a.cdn.net."},
				ns:     []string{soaNet},
			}},
			rcode: dns.RcodeNameError,
			ns:    []string{soaNet},
		},
		{
			name:  "DNAME and its synthesized CNAME go away",
			qname: "www.example.com.", qtype: dns.TypeA,
			zone: map[string]zoneReply{zkey("www.example.com.", dns.TypeA): {answer: []string{
				"example.com. 600 IN DNAME example.net.",
				"www.example.com. 600 IN CNAME www.example.net.",
				"www.example.net. 300 IN A 192.0.2.3",
			}}},
			answer: []string{"www.example.com. 300 IN A 192.0.2.3"},
			addrs:  []string{"192.0.2.3"},
		},
		{
			name:  "HTTPS with TargetName . at the end of a chain moves to the qname",
			qname: "www.example.com.", qtype: dns.TypeHTTPS,
			zone: map[string]zoneReply{zkey("www.example.com.", dns.TypeHTTPS): {answer: []string{
				"www.example.com. 300 IN CNAME a.cdn.net.",
				`a.cdn.net. 60 IN HTTPS 1 . alpn="h3,h2" ipv4hint=192.0.2.4 ech=AEX+DQBBpQAgACB/RU5hAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA=`,
			}}},
			answer: []string{`www.example.com. 60 IN HTTPS 1 . alpn="h3,h2" ipv4hint=192.0.2.4 ech=AEX+DQBBpQAgACB/RU5hAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA=`},
			addrs:  []string{"192.0.2.4"},
		},
		{
			name:  "TargetName equal to the old owner becomes .",
			qname: "www.example.com.", qtype: dns.TypeHTTPS,
			zone: map[string]zoneReply{zkey("www.example.com.", dns.TypeHTTPS): {answer: []string{
				"www.example.com. 300 IN CNAME a.cdn.net.",
				"a.cdn.net. 60 IN HTTPS 1 A.cdn.NET. alpn=h2",
			}}},
			answer: []string{"www.example.com. 60 IN HTTPS 1 . alpn=h2"},
		},
		{
			name:  "TargetName equal to the qname stays",
			qname: "www.example.com.", qtype: dns.TypeHTTPS,
			zone: map[string]zoneReply{zkey("www.example.com.", dns.TypeHTTPS): {answer: []string{
				"www.example.com. 300 IN HTTPS 1 www.example.com. alpn=h2",
			}}},
			answer: []string{"www.example.com. 300 IN HTTPS 1 www.example.com. alpn=h2"},
		},
		{
			name:  "ServiceMode outside target becomes a synthetic name with all parameters and a TTL of at most 300",
			qname: "www.example.com.", qtype: dns.TypeHTTPS,
			zone: map[string]zoneReply{zkey("www.example.com.", dns.TypeHTTPS): {answer: []string{
				"www.example.com. 3600 IN HTTPS 1 svc.cdn.net. alpn=h2 port=8443 ipv6hint=2001:db8::5",
				"www.example.com. 3600 IN HTTPS 2 . alpn=h2",
			}}},
			check: func(t *testing.T, m *dns.Msg) {
				t.Helper()
				requireSynthetic(t, m, "www.example.com.", "svc.cdn.net.", 1, "alpn=h2 port=8443 ipv6hint=2001:db8::5")
				if len(m.Answer) != 2 || m.Answer[0].Header().Ttl != maxSynthTTL || m.Answer[1].Header().Ttl != 3600 {
					t.Errorf("answer %v, want TTL 300 for the synthetic name and 3600 for the other record", m.Answer)
				}
			},
			addrs: []string{"2001:db8::5"},
		},
		{
			name:  "AliasMode outside target at the end of a chain becomes a synthetic name",
			qname: "www.example.com.", qtype: dns.TypeHTTPS,
			zone: map[string]zoneReply{zkey("www.example.com.", dns.TypeHTTPS): {answer: []string{
				"www.example.com. 300 IN CNAME a.cdn.net.",
				"a.cdn.net. 60 IN HTTPS 0 pool.cdn.org.",
			}}},
			check: func(t *testing.T, m *dns.Msg) {
				t.Helper()
				requireSynthetic(t, m, "www.example.com.", "pool.cdn.org.", 0, "")
				if m.Answer[0].Header().Ttl != 60 {
					t.Errorf("TTL = %d, want 60", m.Answer[0].Header().Ttl)
				}
			},
		},
		{
			// The TargetName of SVCB can be the TLS identity of the
			// service (RFC 9461), so it cannot become a synthetic name.
			name:  "SVCB with another target goes away, also below the qname",
			qname: "_dns.example.com.", qtype: dns.TypeSVCB,
			zone: map[string]zoneReply{zkey("_dns.example.com.", dns.TypeSVCB): {answer: []string{
				"_dns.example.com. 300 IN SVCB 1 dns.example.com. alpn=dot",
				"_dns.example.com. 300 IN SVCB 2 . alpn=dot",
				"_dns.example.com. 300 IN SVCB 3 _dns.example.com. alpn=doq",
			}}},
			answer: []string{
				"_dns.example.com. 300 IN SVCB 2 . alpn=dot",
				"_dns.example.com. 300 IN SVCB 3 _dns.example.com. alpn=doq",
			},
		},
		{
			name:  "SVCB with the old owner as target goes away after a chain",
			qname: "_dns.example.com.", qtype: dns.TypeSVCB,
			zone: map[string]zoneReply{zkey("_dns.example.com.", dns.TypeSVCB): {answer: []string{
				"_dns.example.com. 300 IN CNAME _dns.cdn.net.",
				"_dns.cdn.net. 300 IN SVCB 1 _dns.cdn.net. alpn=dot",
				"_dns.cdn.net. 300 IN SVCB 2 . alpn=dot",
			}}},
			answer: []string{"_dns.example.com. 300 IN SVCB 2 . alpn=dot"},
		},
		{
			name:  "records of other types and names go away",
			qname: "www.example.com.", qtype: dns.TypeA,
			zone: map[string]zoneReply{zkey("www.example.com.", dns.TypeA): {answer: []string{
				"www.example.com. 300 IN CNAME a.cdn.net.",
				"a.cdn.net. 60 IN A 192.0.2.6",
				"a.cdn.net. 60 IN AAAA 2001:db8::6",
				"a.cdn.net. 60 IN HTTPS 1 . alpn=h2",
				"other.org. 60 IN A 203.0.113.9",
			}}},
			answer: []string{"www.example.com. 60 IN A 192.0.2.6"},
			addrs:  []string{"192.0.2.6", "203.0.113.9", "2001:db8::6"},
		},
		{
			name:  "synthetic name over 255 octets drops its record, the rest stays",
			qname: long, qtype: dns.TypeHTTPS,
			zone: map[string]zoneReply{zkey(long, dns.TypeHTTPS): {answer: []string{
				long + " 300 IN HTTPS 1 " + strings.Repeat("t", 40) + ".cdn.net. alpn=h2",
				long + " 300 IN HTTPS 2 . alpn=h2",
			}}},
			answer: []string{long + " 300 IN HTTPS 2 . alpn=h2"},
		},
		{
			name:  "incomplete chain is completed upstream",
			qname: "www.example.com.", qtype: dns.TypeA,
			zone: map[string]zoneReply{
				zkey("www.example.com.", dns.TypeA): {answer: []string{"www.example.com. 300 IN CNAME a.cdn.net."}},
				zkey("a.cdn.net.", dns.TypeA): {answer: []string{
					"a.cdn.net. 200 IN CNAME b.edge.org.",
				}},
				zkey("b.edge.org.", dns.TypeA): {answer: []string{"b.edge.org. 100 IN A 192.0.2.7"}},
			},
			answer:    []string{"www.example.com. 100 IN A 192.0.2.7"},
			addrs:     []string{"192.0.2.7"},
			wantAsked: []string{zkey("a.cdn.net.", dns.TypeA), zkey("b.edge.org.", dns.TypeA)},
		},
		{
			name:  "completion that ends in NXDOMAIN gives NXDOMAIN",
			qname: "www.example.com.", qtype: dns.TypeA,
			zone: map[string]zoneReply{
				zkey("www.example.com.", dns.TypeA): {answer: []string{"www.example.com. 300 IN CNAME a.cdn.net."}},
				zkey("a.cdn.net.", dns.TypeA):       {rcode: dns.RcodeNameError, ns: []string{soaNet}},
			},
			rcode:     dns.RcodeNameError,
			ns:        []string{"cdn.net. 300 IN SOA ns.cdn.net. host.cdn.net. 1 7200 3600 1209600 300"},
			wantAsked: []string{zkey("a.cdn.net.", dns.TypeA)},
		},
		{
			name:  "completion with an empty reply is NODATA without a SOA",
			qname: "www.example.com.", qtype: dns.TypeA,
			zone: map[string]zoneReply{
				zkey("www.example.com.", dns.TypeA): {answer: []string{"www.example.com. 300 IN CNAME a.cdn.net."}},
				zkey("a.cdn.net.", dns.TypeA):       {},
			},
			wantAsked: []string{zkey("a.cdn.net.", dns.TypeA)},
		},
		{
			name:  "truncated reply to the rest of the chain gives TC to the client",
			qname: "www.example.com.", qtype: dns.TypeA,
			zone: map[string]zoneReply{
				zkey("www.example.com.", dns.TypeA): {answer: []string{"www.example.com. 300 IN CNAME a.cdn.net."}},
				zkey("a.cdn.net.", dns.TypeA):       {tc: true, answer: []string{"a.cdn.net. 60 IN A 192.0.2.30"}},
			},
			check: func(t *testing.T, m *dns.Msg) {
				t.Helper()
				if !m.Truncated || len(m.Answer) != 0 {
					t.Errorf("reply %v, want TC and no answer", m)
				}
			},
			wantAsked: []string{zkey("a.cdn.net.", dns.TypeA)},
		},
		{
			name:  "truncated upstream reply is not completed",
			qname: "www.example.com.", qtype: dns.TypeA,
			zone: map[string]zoneReply{
				zkey("www.example.com.", dns.TypeA): {tc: true, answer: []string{"www.example.com. 300 IN CNAME a.cdn.net."}},
				zkey("a.cdn.net.", dns.TypeA):       {answer: []string{"a.cdn.net. 60 IN A 192.0.2.31"}},
			},
			check: func(t *testing.T, m *dns.Msg) {
				t.Helper()
				if !m.Truncated || len(m.Answer) != 0 {
					t.Errorf("reply %v, want TC and no answer", m)
				}
			},
		},
		{
			name:  "AD goes when the reply changes",
			qname: "www.example.com.", qtype: dns.TypeA,
			zone: map[string]zoneReply{zkey("www.example.com.", dns.TypeA): {ad: true, answer: []string{
				"www.example.com. 300 IN CNAME a.cdn.net.",
				"a.cdn.net. 60 IN A 192.0.2.32",
			}}},
			answer: []string{"www.example.com. 60 IN A 192.0.2.32"},
			check: func(t *testing.T, m *dns.Msg) {
				t.Helper()
				if m.AuthenticatedData {
					t.Error("AD is set on a changed reply")
				}
			},
			addrs: []string{"192.0.2.32"},
		},
		{
			name:  "AD stays when the reply does not change",
			qname: "www.example.com.", qtype: dns.TypeA,
			zone: map[string]zoneReply{zkey("www.example.com.", dns.TypeA): {ad: true, answer: []string{
				"www.example.com. 60 IN A 192.0.2.33",
			}}},
			answer: []string{"www.example.com. 60 IN A 192.0.2.33"},
			check: func(t *testing.T, m *dns.Msg) {
				t.Helper()
				if !m.AuthenticatedData {
					t.Error("AD is clear on an unchanged reply")
				}
			},
			addrs: []string{"192.0.2.33"},
		},
		{
			name:  "chain of the limit length",
			qname: "c0.example.com.", qtype: dns.TypeA,
			zone:   map[string]zoneReply{zkey("c0.example.com.", dns.TypeA): {answer: chainOf(maxChainLinks)}},
			answer: []string{"c0.example.com. 60 IN A 192.0.2.8"},
			addrs:  []string{"192.0.2.8"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, tt.run)
	}
}

// run checks the protected reply, the report, and the questions that went
// upstream. Then it checks that the same upstream without protection gives
// the client the first upstream reply byte for byte.
func (tt flattenCase) run(t *testing.T) {
	z := &zone{replies: tt.zone}
	res := askZone(t, z, true, tt.qname, tt.qtype)
	if res.err != nil || res.reply == nil {
		t.Fatalf("ServeDNS = %d, %v; want a reply", res.rcode, res.err)
	}
	m := res.reply
	if m.Rcode != tt.rcode || res.rcode != tt.rcode || m.Id == 0 || len(m.Question) != 1 || m.Question[0].Name != tt.qname {
		t.Errorf("header %v, question %v, ServeDNS rcode %d; want rcode %d and the client question", m.MsgHdr, m.Question, res.rcode, tt.rcode)
	}
	if tt.check != nil {
		tt.check(t, m)
	}
	if got, want := strs(m.Answer), records(tt.answer...); (tt.answer != nil || tt.check == nil) && !slices.Equal(got, want) {
		t.Errorf("answer:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if got, want := strs(m.Ns), records(tt.ns...); !slices.Equal(got, want) {
		t.Errorf("authority:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if len(m.Extra) != 1 || m.Extra[0].Header().Rrtype != dns.TypeOPT {
		t.Errorf("additional = %v, want the OPT record only", m.Extra)
	}
	requireNoAlias(t, tt.qname, m)
	tt.checkReport(t, res)
	if got := z.questions()[1:]; !slices.Equal(got, tt.wantAsked) {
		t.Errorf("plugin asked %v, want %v", got, tt.wantAsked)
	}

	z = &zone{replies: tt.zone}
	res = askZone(t, z, false, tt.qname, tt.qtype)
	got, err := res.reply.Pack()
	if err != nil || !bytes.Equal(got, z.sent[zkey(tt.qname, tt.qtype)]) {
		t.Errorf("unprotected reply changed (%v):\n%v", err, res.reply)
	}
}

// checkReport checks the report of res. A reply that flattening does not
// change and that has no address needs no report.
func (tt flattenCase) checkReport(t *testing.T, res zoneResult) {
	t.Helper()
	o := res.rep.last.Load()
	switch {
	case o == nil && len(tt.addrs) > 0:
		t.Fatal("no report")
	case o == nil:
		return
	}
	if got := addrStrings(o.Addrs); !slices.Equal(got, tt.addrs) || o.QName != tt.qname {
		t.Errorf("report = %s %v, want %s %v", o.QName, got, tt.qname, tt.addrs)
	}
	requireReported(t, res.reply, o.Addrs)
}

// chainOf returns a chain of n CNAME links from c0.example.com and an A
// record at its end.
func chainOf(n int) []string {
	var out []string
	for i := range n {
		out = append(out, fmt.Sprintf("c%d.example.com. 300 IN CNAME c%d.example.com.", i, i+1))
	}
	return append(out, fmt.Sprintf("c%d.example.com. 60 IN A 192.0.2.8", n))
}

// requireSynthetic checks that the first answer record of m is an HTTPS
// record at qname with priority prio, the parameters params, and a
// TargetName that is the synthetic name of target below qname.
func requireSynthetic(t *testing.T, m *dns.Msg, qname, target string, prio uint16, params string) {
	t.Helper()
	if len(m.Answer) == 0 {
		t.Fatalf("answer = %v, want a record", m.Answer)
	}
	var s *dns.SVCB
	switch v := m.Answer[0].(type) {
	case *dns.HTTPS:
		s = &v.SVCB
	case *dns.SVCB:
		s = v
	default:
		t.Fatalf("answer %v is not HTTPS or SVCB", v)
	}
	if s.Hdr.Name != qname || s.Priority != prio {
		t.Errorf("record %v, want owner %s and priority %d", s, qname, prio)
	}
	var kvs []string
	for _, kv := range s.Value {
		kvs = append(kvs, kv.Key().String()+"="+kv.String())
	}
	if got := strings.Join(kvs, " "); got != params {
		t.Errorf("parameters %q, want %q", got, params)
	}
	labels := dns.SplitDomainName(s.Target)
	tl := len(dns.SplitDomainName(target))
	if len(labels) != tl+2+len(dns.SplitDomainName(qname)) || dns.Fqdn(strings.Join(labels[:tl], ".")) != target ||
		labels[tl] != synthLabel || len(labels[tl+1]) != 26 || !strings.HasSuffix(s.Target, "."+qname) {
		t.Errorf("TargetName = %s, want %s._ifb.<tag>.%s", s.Target, target, qname)
	}
	syn, ok, err := testKey.parse(s.Target)
	if err != nil || !ok || syn.target != target || syn.origin != qname {
		t.Errorf("parse(%s) = %+v, %v, %v; want target %s, origin %s", s.Target, syn, ok, err, target, qname)
	}
}

// requireNoAlias checks the flattening rule independently of flatten: no
// name outside qname (see namesOutside), no CNAME or DNAME record, an
// authority section with only SOA records and only in a negative answer,
// and each HTTPS TargetName is ".", qname, or a valid synthetic name below
// qname. An SVCB TargetName is "." or qname.
func requireNoAlias(t testing.TB, qname string, m *dns.Msg) {
	t.Helper()
	if esc := namesOutside(qname, m); len(esc) > 0 {
		t.Errorf("reply to %s names %v", qname, esc)
	}
	for _, r := range append(slices.Clone(m.Answer), m.Extra...) {
		switch v := r.(type) {
		case *dns.CNAME, *dns.DNAME:
			t.Errorf("alias record %v", r)
		case *dns.SVCB:
			if v.Target != "." && !strings.EqualFold(v.Target, qname) {
				t.Errorf("SVCB record %v has a target other than . and %s", v, qname)
			}
		case *dns.HTTPS:
			if v.Target == "." || strings.EqualFold(v.Target, qname) {
				continue
			}
			syn, ok, err := testKey.parse(v.Target)
			if err != nil || !ok || !strings.EqualFold(syn.origin, qname) {
				t.Errorf("TargetName %s is not a synthetic name below %s (%v)", v.Target, qname, err)
			}
		}
	}
	for _, r := range m.Ns {
		if r.Header().Rrtype != dns.TypeSOA || len(m.Answer) > 0 {
			t.Errorf("authority record %v in a reply with %d answers", r, len(m.Answer))
		}
	}
}

func addrStrings(as []netip.Addr) []string {
	out := make([]string, len(as))
	for i, a := range as {
		out[i] = a.String()
	}
	return out
}

// slowZone is a zone whose reply to slow takes delay, and ignores the
// context, as forward does while it waits for a UDP reply.
type slowZone struct {
	*zone
	slow  string
	delay time.Duration
}

func (z slowZone) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	if zkey(r.Question[0].Name, r.Question[0].Qtype) == z.slow {
		time.Sleep(z.delay) // the fake upstream waits; synctest makes it instant
	}
	return z.zone.ServeDNS(ctx, w, r)
}

// An upstream reply after one lost packet (2 s with forward) still
// reaches the client: for the target of a synthetic name, and for the
// rest of a chain.
func TestSlowUpstreamAfterALostPacketIsNotAFailure(t *testing.T) {
	const delay = 2100 * time.Millisecond
	syn, _ := testKey.synthName("svc.cdn.net.", "www.example.com.")
	tests := []struct {
		name, qname, slow string
	}{
		{name: "target of a synthetic name", qname: syn, slow: zkey("svc.cdn.net.", dns.TypeA)},
		{name: "rest of a chain", qname: "chain.example.com.", slow: zkey("a.cdn.net.", dns.TypeA)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				replies := syntheticZone()
				replies[zkey("chain.example.com.", dns.TypeA)] = zoneReply{answer: []string{"chain.example.com. 300 IN CNAME a.cdn.net."}}
				replies[zkey("a.cdn.net.", dns.TypeA)] = zoneReply{answer: []string{"a.cdn.net. 60 IN A 192.0.2.40"}}
				z := slowZone{zone: &zone{replies: replies}, slow: tt.slow, delay: delay}
				h := &handler{key: testKey, next: z, reporter: &recorder{protected: true}, timeout: 2 * time.Second}
				res := query(t, h, tt.qname, dns.TypeA)
				if res.err != nil || res.reply == nil || len(res.reply.Answer) != 1 {
					t.Errorf("ServeDNS = %d, %v, reply %v; want the answer", res.rcode, res.err, res.reply)
				}
			})
		})
	}
}

// While ifboundd is down, a reply without an address and without a name
// that a client follows still goes out unchanged. A reply with an alias
// gets SERVFAIL.
func TestReplyWithoutAddressOrAliasNeedsNoAck(t *testing.T) {
	soa := "example.com. 300 IN SOA ns.example.com. host.example.com. 1 7200 3600 1209600 300"
	nsec := "www.example.com. 300 IN NSEC zz.example.com. A RRSIG NSEC"
	sig := "www.example.com. 300 IN RRSIG NSEC 13 3 300 20300317174640 20231114221320 12345 example.com. AAAA"
	tests := []struct {
		name  string
		reply zoneReply
		want  int
	}{
		{name: "NXDOMAIN with NSEC and RRSIG", reply: zoneReply{rcode: dns.RcodeNameError, ns: []string{soa, nsec, sig}}, want: dns.RcodeNameError},
		{name: "NODATA with NS", reply: zoneReply{ns: []string{soa, "example.com. 300 IN NS ns.other.net."}}, want: dns.RcodeSuccess},
		{name: "HTTPS without hints and with the owner as target", reply: zoneReply{answer: []string{"www.example.com. 300 IN HTTPS 1 www.example.com. alpn=h2"}}, want: dns.RcodeSuccess},
		{name: "CNAME", reply: zoneReply{answer: []string{"www.example.com. 300 IN CNAME a.cdn.net."}, ns: []string{soa}}, want: dns.RcodeServerFailure},
		{name: "HTTPS with an outside target", reply: zoneReply{answer: []string{"www.example.com. 300 IN HTTPS 1 svc.cdn.net."}}, want: dns.RcodeServerFailure},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			z := &zone{replies: map[string]zoneReply{zkey("www.example.com.", dns.TypeHTTPS): tt.reply}}
			down := reporterFunc(func(context.Context, ipc.Observation) error { return ipc.ErrUnavailable })
			h := &handler{key: testKey, next: z, reporter: down, timeout: time.Second}
			res := query(t, h, "www.example.com.", dns.TypeHTTPS)
			if res.rcode != tt.want {
				t.Fatalf("ServeDNS = %d, %v; want rcode %d", res.rcode, res.err, tt.want)
			}
			if tt.want == dns.RcodeServerFailure {
				return
			}
			if got, err := res.reply.Pack(); err != nil || !bytes.Equal(got, z.sent[zkey("www.example.com.", dns.TypeHTTPS)]) {
				t.Errorf("reply changed (%v):\n%v", err, res.reply)
			}
		})
	}
}

// The first report has the addresses of the upstream reply. The addresses
// that the rest of the chain adds go in a second report under the same
// name, before the reply.
func TestAddressesOfTheRestOfTheChainGetASecondReport(t *testing.T) {
	z := &zone{replies: map[string]zoneReply{
		zkey("www.example.com.", dns.TypeA): {answer: []string{
			"www.example.com. 300 IN CNAME a.cdn.net.",
			"other.cdn.net. 300 IN A 192.0.2.50",
		}},
		zkey("a.cdn.net.", dns.TypeA): {answer: []string{"a.cdn.net. 60 IN A 192.0.2.51", "a.cdn.net. 60 IN A 192.0.2.50"}},
	}}
	var seen []ipc.Observation
	rep := ackFunc(func(_ context.Context, o ipc.Observation) (ipc.Ack, error) {
		seen = append(seen, o)
		return ipc.Ack{Protected: true}, nil
	})
	h := &handler{key: testKey, next: z, reporter: rep, timeout: time.Second}
	res := query(t, h, "www.example.com.", dns.TypeA)
	if res.err != nil || len(res.reply.Answer) != 2 {
		t.Fatalf("ServeDNS = %d, %v, reply %v", res.rcode, res.err, res.reply)
	}
	if len(seen) != 2 || seen[0].QName != "www.example.com." || seen[1].QName != "www.example.com." ||
		!slices.Equal(addrStrings(seen[0].Addrs), []string{"192.0.2.50"}) ||
		!slices.Equal(addrStrings(seen[1].Addrs), []string{"192.0.2.51"}) {
		t.Errorf("reports = %+v; want 192.0.2.50, then 192.0.2.51, both under www.example.com.", seen)
	}
}

// walk refuses the chains that a client can follow in a way that the
// plugin does not see.
func TestWalkRefusesLoopsForksAndLongChains(t *testing.T) {
	tests := map[string]struct {
		answer []dns.RR
		want   error
	}{
		"loop":                 {answerOf([]string{"a.example. 1 IN CNAME b.example.", "B.example. 1 IN CNAME A.example."}), errCNAMELoop},
		"fork":                 {answerOf([]string{"a.example. 1 IN CNAME b.example.", "a.example. 1 IN CNAME c.example."}), errCNAMEFork},
		"same link twice":      {answerOf([]string{"a.example. 1 IN CNAME b.example.", "A.example. 2 IN CNAME B.example."}), nil},
		"chain of the limit":   {answerOf(chainOf(maxChainLinks)), nil},
		"chain over the limit": {answerOf(chainOf(maxChainLinks + 1)), errChainTooLong},
	}
	for name, tt := range tests {
		start := "a.example."
		if len(tt.answer) > 2 {
			start = "c0.example.com."
		}
		if _, err := walk(start, dns.TypeA, tt.answer); !errors.Is(err, tt.want) {
			t.Errorf("%s: walk = %v, want %v", name, err, tt.want)
		}
	}
}

func answerOf(ss []string) []dns.RR {
	out := make([]dns.RR, len(ss))
	for i, s := range ss {
		out[i] = rr(s)
	}
	return out
}

// An HTTPS or SVCB record with empty rdata has no target that a client can
// read. flatten drops it.
func TestFlattenDropsAServiceRecordWithoutTarget(t *testing.T) {
	m := new(dns.Msg).SetQuestion("www.example.com.", dns.TypeHTTPS)
	m.Answer = []dns.RR{
		&dns.HTTPS{SVCB: dns.SVCB{Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 60}}},
		rr("www.example.com. 60 IN HTTPS 1 . alpn=h2"),
	}
	out, err := flatten(testKey, "www.example.com.", "www.example.com.", dns.TypeHTTPS, m)
	if err != nil || len(out.Answer) != 1 || !strings.HasSuffix(out.Answer[0].String(), "HTTPS\t1 . alpn=\"h2\"") {
		t.Errorf("flatten = %v, %v; want the record with target . only", out, err)
	}
}
