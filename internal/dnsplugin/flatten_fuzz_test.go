package dnsplugin

import (
	"context"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"

	"github.com/Nagato-Yuzuru/ifbound/internal/ipc"
)

// fuzzSeed packs a reply to qname and qtype with the given answer and
// authority records.
func fuzzSeed(f *testing.F, qname string, qtype uint16, rcode int, answer, ns []string) {
	f.Helper()
	m := new(dns.Msg).SetQuestion(qname, qtype)
	m.Response, m.Rcode = true, rcode
	for _, s := range answer {
		m.Answer = append(m.Answer, rr(s))
	}
	for _, s := range ns {
		m.Ns = append(m.Ns, rr(s))
	}
	m.SetEdns0(1232, false)
	wire, err := m.Pack()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(wire, false)
	f.Add(wire, true)
}

// FuzzFlatten checks the rules of a flattened reply for any upstream reply
// (see flatten), through the handler, with an ack that says protected,
// for the name itself and for a synthetic name whose target it is. The
// checks do not use the code under test:
//
//   - no owner or TargetName outside the client qname remains, except the
//     SOA owner of a negative answer and the known gap; a synthetic name
//     below the qname is allowed (see requireNoAlias);
//   - when the reply goes out, the reports so far hold every address that
//     the client can decode, and the upstream reply had it;
//   - a reply without a report has no address and no name that a client
//     follows;
//   - no TTL grows.
func FuzzFlatten(f *testing.F) {
	fuzzSeeds(f)
	f.Fuzz(checkFlattened)
}

// checkFlattened is the body of FuzzFlatten.
func checkFlattened(t *testing.T, wire []byte, synthetic bool) {
	in := new(dns.Msg)
	if in.Unpack(wire) != nil || len(in.Question) != 1 {
		return
	}
	q := in.Question[0]
	qname := q.Name
	if synthetic {
		name, ok := testKey.synthName(q.Name, "www.example.com.")
		if !ok {
			return
		}
		qname = name
	}
	out, reports := serveFuzzed(t, in, qname, q.Qtype)
	if out == nil {
		return // SERVFAIL: the plugin failed closed
	}
	if reports == 0 && !synthetic {
		// Without a report, the reply must need none.
		for _, p := range passThroughViolations(t, out) {
			t.Error(p)
		}
		return
	}
	requireNoAlias(t, qname, out)
	if out.Rcode != in.Rcode {
		t.Errorf("rcode %d, want %d", out.Rcode, in.Rcode)
	}
	// Pack and unpack the input too: packing puts some values in a
	// canonical order, such as the keys of "mandatory".
	inWire, err := in.Pack()
	again := new(dns.Msg)
	if err != nil || again.Unpack(inWire) != nil {
		return
	}
	requireNoLongerTTL(t, again, out)
}

func fuzzSeeds(f *testing.F) {
	fuzzSeed(f, "www.example.com.", dns.TypeA, dns.RcodeSuccess, []string{
		"www.example.com. 300 IN CNAME a.cdn.net.",
		"a.cdn.net. 60 IN CNAME b.edge.org.",
		"b.edge.org. 120 IN A 192.0.2.1",
		"other.org. 60 IN AAAA 2001:db8::1",
	}, nil)
	fuzzSeed(f, "www.example.com.", dns.TypeHTTPS, dns.RcodeSuccess, []string{
		"www.example.com. 300 IN CNAME a.cdn.net.",
		"a.cdn.net. 60 IN HTTPS 1 . alpn=h2 ipv4hint=192.0.2.4",
		"a.cdn.net. 60 IN HTTPS 2 svc.cdn.net. alpn=h3 ipv6hint=2001:db8::4",
		"a.cdn.net. 60 IN HTTPS 3 a.cdn.net. port=8443",
	}, nil)
	fuzzSeed(f, "www.example.com.", dns.TypeHTTPS, dns.RcodeSuccess, []string{
		"www.example.com. 300 IN HTTPS 0 pool.cdn.org.",
	}, nil)
	fuzzSeed(f, "www.example.com.", dns.TypeA, dns.RcodeNameError, []string{
		"example.com. 600 IN DNAME example.net.",
		"www.example.com. 600 IN CNAME www.example.net.",
	}, []string{soaNet, "net. 300 IN NS a.gtld-servers.net."})
	fuzzSeed(f, "_dns.example.com.", dns.TypeSVCB, dns.RcodeSuccess, []string{
		"_dns.example.com. 300 IN SVCB 1 dns.example.com. alpn=dot",
	}, nil)
	fuzzSeed(f, "_imap._tcp.example.com.", dns.TypeSRV, dns.RcodeSuccess, []string{
		"_imap._tcp.example.com. 300 IN CNAME _imap._tcp.cdn.net.",
		"_imap._tcp.cdn.net. 300 IN SRV 0 1 993 mail.cdn.net.",
	}, nil)
	fuzzSeed(f, "a.example.", dns.TypeA, dns.RcodeSuccess, []string{
		"a.example. 300 IN CNAME b.example.",
		"b.example. 300 IN CNAME a.example.",
	}, nil)
}

// fuzzUpstream answers every question with the records of one reply.
type fuzzUpstream struct{ m *dns.Msg }

func (u fuzzUpstream) ServeDNS(_ context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	m := u.m.Copy()
	m.Id, m.Response, m.Question = r.Id, true, slices.Clone(r.Question)
	return dns.RcodeSuccess, w.WriteMsg(m)
}

func (fuzzUpstream) Name() string { return "fuzzupstream" }

// checkedWriter fails the test when a reply has an address that is not in
// the reports so far, or that the upstream reply did not have.
type checkedWriter struct {
	test.ResponseWriter
	t        *testing.T
	reported map[netip.Addr]bool
	had      map[netip.Addr]bool
	reply    *dns.Msg
}

func (w *checkedWriter) WriteMsg(m *dns.Msg) error {
	wire, err := m.Pack()
	dec := new(dns.Msg)
	if err != nil || dec.Unpack(wire) != nil {
		// A record that unpacks loosely, such as a short SOA, can pack
		// to bytes that do not unpack. No client reads such a reply.
		return nil
	}
	got, ok := readableAddrSet(dec)
	if !ok {
		w.t.Errorf("reply has an address record that no client can read, and no report can hold:\n%v", m)
	}
	for a := range got {
		if !w.reported[a] || !w.had[a] {
			w.t.Errorf("address %v of the reply: reported before %v, in the upstream reply %v", a, w.reported[a], w.had[a])
		}
	}
	w.reply = dec
	return nil
}

// serveFuzzed asks the handler qname and qtype, with in as the reply to
// every upstream query and an ack that says protected. It returns the
// reply as the client decodes it, or nil, and the number of reports.
func serveFuzzed(t *testing.T, in *dns.Msg, qname string, qtype uint16) (*dns.Msg, int) {
	t.Helper()
	wire, err := in.Pack()
	client := new(dns.Msg)
	if err != nil || client.Unpack(wire) != nil {
		return nil, 0 // the handler cannot read the reply of the next plugin: SERVFAIL
	}
	reports := 0
	had, _ := readableAddrSet(client)
	w := &checkedWriter{t: t, reported: map[netip.Addr]bool{}, had: had}
	rep := ackFunc(func(_ context.Context, o ipc.Observation) (ipc.Ack, error) {
		reports++
		for _, a := range o.Addrs {
			w.reported[a.Unmap()] = true
		}
		return ipc.Ack{Protected: true}, nil
	})
	h := &handler{key: testKey, next: fuzzUpstream{in}, reporter: rep, timeout: time.Second}
	_, _ = h.ServeDNS(t.Context(), w, new(dns.Msg).SetQuestion(qname, qtype)) //nolint:errcheck // the caller reads the reply the writer got, and a SERVFAIL writes nothing
	return w.reply, reports
}

// readableAddrSet is the set of readableAddrs. It is false when m has an
// address record with a value that is not an address.
func readableAddrSet(m *dns.Msg) (map[netip.Addr]bool, bool) {
	set := map[netip.Addr]bool{}
	for _, a := range readableAddrs(m) {
		set[a] = true
	}
	for _, sec := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, r := range sec {
			switch v := r.(type) {
			case *dns.A:
				if len(v.A) == 0 {
					return set, false
				}
			case *dns.AAAA:
				if len(v.AAAA) == 0 {
					return set, false
				}
			}
		}
	}
	return set, true
}

// normalRR is r without the parts that flatten changes: the owner, the
// TTL, the TargetName, and the negative TTL of a SOA.
func normalRR(r dns.RR) string {
	c := dns.Copy(r)
	c.Header().Name, c.Header().Ttl = ".", 0
	switch v := c.(type) {
	case *dns.SVCB:
		v.Target = "."
	case *dns.HTTPS:
		v.Target = "."
	case *dns.SOA:
		v.Minttl = 0
	}
	return c.String()
}

// requireNoLongerTTL checks that each record of out comes from a record of
// in with the same data and a TTL that is not smaller.
func requireNoLongerTTL(t *testing.T, in, out *dns.Msg) {
	t.Helper()
	for _, sec := range [][2][]dns.RR{{in.Answer, out.Answer}, {in.Ns, out.Ns}} {
		for _, r := range sec[1] {
			if !slices.ContainsFunc(sec[0], func(src dns.RR) bool { return sourceOf(src, r) }) {
				t.Errorf("record %v has no source with the same data and a TTL not below it", r)
			}
		}
	}
}

// sourceOf reports whether r can come from src without a longer TTL.
func sourceOf(src, r dns.RR) bool {
	if normalRR(src) != normalRR(r) || src.Header().Ttl < r.Header().Ttl {
		return false
	}
	s, isSOA := src.(*dns.SOA)
	o, _ := r.(*dns.SOA)
	return !isSOA || o != nil && s.Minttl >= o.Minttl
}
