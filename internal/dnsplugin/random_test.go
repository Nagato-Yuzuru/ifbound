package dnsplugin

import (
	"context"
	"fmt"
	"math"
	"math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/Nagato-Yuzuru/ifbound/internal/ipc"
)

// The oracle in this file computes the addresses of a reply from the
// spec, independent of collect.go. It compares names by their wire form
// with ASCII letters folded, so it shares no name logic with the code
// under test.

// nameKey returns the comparison key of a presentation name.
func nameKey(t testing.TB, name string) string {
	t.Helper()
	buf := make([]byte, 256)
	n, err := dns.PackDomainName(dns.Fqdn(name), buf, 0, nil, false)
	if err != nil {
		t.Fatalf("name %q does not pack: %v", name, err)
	}
	b := buf[:n]
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// clientAddrs returns every address that a client can decode from m, unmapped,
// and the smallest TTL of the records that carry them.
func clientAddrs(t testing.TB, m *dns.Msg) (map[netip.Addr]bool, uint32) {
	t.Helper()
	out := map[netip.Addr]bool{}
	minTTL := uint32(math.MaxUint32)
	add := func(ttl uint32, ips ...net.IP) {
		for _, ip := range ips {
			a, ok := netip.AddrFromSlice(ip)
			if !ok {
				t.Fatalf("undecodable address %v", ip)
			}
			out[a.Unmap()] = true
			minTTL = min(minTTL, ttl)
		}
	}
	for _, sec := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, r := range sec {
			var kvs []dns.SVCBKeyValue
			switch v := r.(type) {
			case *dns.A:
				add(v.Hdr.Ttl, v.A)
			case *dns.AAAA:
				add(v.Hdr.Ttl, v.AAAA)
			case *dns.SVCB:
				kvs = v.Value
			case *dns.HTTPS:
				kvs = v.Value
			}
			for _, kv := range kvs {
				switch h := kv.(type) {
				case *dns.SVCBIPv4Hint:
					add(r.Header().Ttl, h.Hint...)
				case *dns.SVCBIPv6Hint:
					add(r.Header().Ttl, h.Hint...)
				}
			}
		}
	}
	return out, minTTL
}

// firstChainTTL is an upper bound of the reported TTL: the smallest TTL
// of the CNAME records on the first-match chain from qname. The plugin
// follows every CNAME from qname, so its TTL is not above this bound.
func firstChainTTL(t testing.TB, qname string, m *dns.Msg) uint32 {
	t.Helper()
	ttl := uint32(math.MaxUint32)
	seen := map[string]bool{}
	cur := nameKey(t, qname)
	for !seen[cur] {
		seen[cur] = true
		var next *dns.CNAME
		for _, r := range m.Answer {
			if c, ok := r.(*dns.CNAME); ok && nameKey(t, c.Hdr.Name) == cur {
				next = c
				break
			}
		}
		if next == nil {
			break
		}
		ttl = min(ttl, next.Hdr.Ttl)
		cur = nameKey(t, next.Target)
	}
	return ttl
}

// decodeAs returns m as a client decodes it.
func decodeAs(t testing.TB, m *dns.Msg, compress bool) *dns.Msg {
	t.Helper()
	c := m.Copy()
	c.Compress = compress
	wire, err := c.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	out := new(dns.Msg)
	if err := out.Unpack(wire); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	return out
}

// outcome is what one ServeDNS call did.
type outcome struct {
	rcode int
	err   error
	reply *dns.Msg
	calls int
	obs   ipc.Observation
}

func serveOnce(t testing.TB, qname string, up *upstream, report func(context.Context, ipc.Observation) error) outcome {
	t.Helper()
	var (
		mu  sync.Mutex
		out outcome
	)
	rep := reporterFunc(func(ctx context.Context, o ipc.Observation) error {
		mu.Lock()
		out.calls++
		out.obs = o
		mu.Unlock()
		if report == nil {
			return nil
		}
		return report(ctx, o)
	})
	h := &handler{key: testKey, next: up, reporter: rep, timeout: 2 * time.Second}
	rec, rcode, err := serve(context.Background(), h, qname)
	out.rcode, out.err, out.reply = rcode, err, rec.Msg
	return out
}

// checkOutcome compares one outcome with the spec. It returns the violations.
func checkOutcome(t testing.TB, qname string, sent *dns.Msg, got outcome) []string {
	t.Helper()
	var bad []string
	fail := func(format string, args ...any) { bad = append(bad, fmt.Sprintf(format, args...)) }

	client := decodeAs(t, sent, false)
	wantAddrs, _ := clientAddrs(t, client)
	if got.reply == nil {
		fail("no reply (rcode %d, err %v) for %d addresses", got.rcode, got.err, len(wantAddrs))
		return bad
	}
	if a, b := decodeAs(t, got.reply, false), client; a.String() != b.String() {
		fail("client got\n%v\nwant\n%v", a, b)
	}
	if len(wantAddrs) == 0 {
		// A report can still ask whether to flatten the reply, but it
		// carries no address of the unprotected reply.
		if got.calls > 1 || got.calls == 1 && len(got.obs.Addrs) != 0 {
			fail("%d reports with %v for a reply without an address, want at most 1 without an address", got.calls, got.obs.Addrs)
		}
		return bad
	}
	if got.calls != 1 {
		fail("%d reports, want 1", got.calls)
		return bad
	}
	o := got.obs
	if o.QName != qname {
		fail("qname %q, want %q", o.QName, qname)
	}
	gotAddrs, addrBad := addressViolations(t, qname, client, o)
	bad = append(bad, addrBad...)
	return append(bad, safetyViolations(t, got.reply, gotAddrs)...)
}

// addressViolations checks the addresses of o against the reply that the
// client decodes: every address, and a TTL not above firstChainTTL. It
// returns the reported addresses, unmapped as ifboundd sees them, and the
// violations.
func addressViolations(t testing.TB, qname string, client *dns.Msg, o ipc.Observation) (map[netip.Addr]bool, []string) {
	t.Helper()
	var bad []string
	wantAddrs, addrTTL := clientAddrs(t, client)
	gotAddrs := map[netip.Addr]bool{}
	for _, a := range o.Addrs {
		gotAddrs[a.Unmap()] = true
	}
	for a := range wantAddrs {
		if !gotAddrs[a] {
			bad = append(bad, fmt.Sprintf("MISSING address %v", a))
		}
	}
	if len(wantAddrs) > 0 {
		bound := min(addrTTL, firstChainTTL(t, qname, client))
		if o.TTL > time.Duration(bound)*time.Second {
			bad = append(bad, fmt.Sprintf("address TTL %v above the bound %ds", o.TTL, bound))
		}
	}
	return gotAddrs, bad
}

// safetyViolations checks that, in each encoding of the reply, the client
// decodes no address that the acked report does not have.
func safetyViolations(t testing.TB, reply *dns.Msg, gotAddrs map[netip.Addr]bool) []string {
	t.Helper()
	var bad []string
	for _, compress := range []bool{false, true} {
		dec := decodeAs(t, reply, compress)
		decAddrs, _ := clientAddrs(t, dec)
		for a := range decAddrs {
			if !gotAddrs[a] {
				bad = append(bad, fmt.Sprintf("UNSAFE: client (compress=%v) decodes unreported address %v", compress, a))
			}
		}
	}
	return bad
}

// replyGen makes random replies whose records link up through a small name
// pool. The pool has names with escaped octets, so presentation forms vary.
type replyGen struct {
	r     *rand.Rand
	qname string
	pool  []string
	// linked holds the qname and the CNAME targets so far. A CNAME owner
	// from it extends the graph that the client can walk.
	linked []string
}

// randomName decodes random wire labels to the canonical presentation form.
func randomName(t testing.TB, r *rand.Rand, i int) string {
	t.Helper()
	specials := []string{"x.y", "a b", "\xc3\xaf", `q"t`, "s;c", "(p)", `b\s`, "UP", "_svc", "@"}
	var wire []byte
	labels := []string{fmt.Sprintf("n%d", i)}
	if r.IntN(3) == 0 {
		labels = append(labels, specials[r.IntN(len(specials))])
	}
	labels = append(labels, []string{"example", "test", "net"}[r.IntN(3)])
	for _, l := range labels {
		wire = append(wire, byte(len(l)))
		wire = append(wire, l...)
	}
	wire = append(wire, 0)
	s, _, err := dns.UnpackDomainName(wire, 0)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// randomCase flips the case of random ASCII letters. Escapes have no letters.
func randomCase(r *rand.Rand, s string) string {
	b := []byte(s)
	for i, c := range b {
		if ('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z') && r.IntN(2) == 0 {
			b[i] = c ^ 0x20
		}
	}
	return string(b)
}

func newReplyGen(t testing.TB, r *rand.Rand) *replyGen {
	t.Helper()
	size := []int{4, 8, 36, 48}[r.IntN(4)]
	g := &replyGen{r: r}
	for i := range size {
		g.pool = append(g.pool, randomName(t, r, i))
	}
	g.qname = randomCase(r, g.pool[0])
	g.linked = []string{g.qname}
	return g
}

func (g *replyGen) name() string { return randomCase(g.r, g.pool[g.r.IntN(len(g.pool))]) }

func (g *replyGen) owner() string {
	if g.r.IntN(3) == 0 {
		return randomCase(g.r, g.qname)
	}
	return g.name()
}

func (g *replyGen) ttl() uint32 {
	return []uint32{0, 1, 30, 60, 300, 3600, 86400, 1<<31 - 1, math.MaxUint32}[g.r.IntN(9)]
}

func (g *replyGen) hdr(owner string, typ uint16) dns.RR_Header {
	return dns.RR_Header{Name: owner, Rrtype: typ, Class: dns.ClassINET, Ttl: g.ttl()}
}

func (g *replyGen) v4() net.IP { return net.IPv4(192, 0, 2, byte(g.r.IntN(256))).To4() }

// v6 returns an AAAA address; mapped is false for a hint, which must not
// hold an IPv4-mapped address.
func (g *replyGen) v6(mapped bool) net.IP {
	if mapped && g.r.IntN(4) == 0 {
		return net.IPv4(198, 51, 100, byte(g.r.IntN(256))).To16() // IPv4-mapped
	}
	ip := net.ParseIP("2001:db8::")
	ip[15] = byte(g.r.IntN(256))
	return ip
}

func (g *replyGen) svcb(owner string) dns.SVCB {
	s := dns.SVCB{Priority: uint16(g.r.IntN(3))} // 0 is AliasMode
	switch g.r.IntN(10) {
	case 0, 1:
		s.Target = "."
	case 2, 3:
		s.Target = randomCase(g.r, owner)
	case 4:
		s.Target = randomCase(g.r, g.qname)
	default:
		s.Target = g.name()
	}
	if s.Priority > 0 {
		if g.r.IntN(2) == 0 {
			s.Value = append(s.Value, &dns.SVCBIPv4Hint{Hint: []net.IP{g.v4(), g.v4()}})
		}
		if g.r.IntN(2) == 0 {
			s.Value = append(s.Value, &dns.SVCBIPv6Hint{Hint: []net.IP{g.v6(false)}})
		}
	}
	return s
}

func (g *replyGen) record() (dns.RR, int) {
	section := 0
	if g.r.IntN(5) == 0 {
		section = 1 + g.r.IntN(2)
	}
	switch g.r.IntN(10) {
	case 0, 1, 2, 3:
		target := g.name()
		switch g.r.IntN(10) {
		case 0:
			target = "."
		case 1:
			target = randomCase(g.r, g.qname)
		}
		owner := g.owner()
		if g.r.IntN(2) == 0 {
			owner = randomCase(g.r, g.linked[g.r.IntN(len(g.linked))])
		}
		if section == 0 {
			g.linked = append(g.linked, target)
		}
		return &dns.CNAME{Hdr: g.hdr(owner, dns.TypeCNAME), Target: target}, section
	case 4, 5:
		owner := g.owner()
		s := g.svcb(owner)
		s.Hdr = g.hdr(owner, dns.TypeHTTPS)
		return &dns.HTTPS{SVCB: s}, g.r.IntN(3)
	case 6:
		owner := g.owner()
		s := g.svcb(owner)
		s.Hdr = g.hdr(owner, dns.TypeSVCB)
		return &s, g.r.IntN(3)
	case 7, 8:
		return &dns.A{Hdr: g.hdr(g.name(), dns.TypeA), A: g.v4()}, section
	default:
		return &dns.AAAA{Hdr: g.hdr(g.name(), dns.TypeAAAA), AAAA: g.v6(true)}, section
	}
}

func (g *replyGen) upstream() *upstream {
	n := g.r.IntN(12)
	if len(g.pool) > 32 {
		n = 30 + g.r.IntN(120)
	}
	up := &upstream{}
	if g.r.IntN(8) == 0 {
		up.rcode = dns.RcodeNameError
	}
	for range n {
		rec, sec := g.record()
		switch sec {
		case 0:
			up.answer = append(up.answer, rec)
		case 1:
			up.ns = append(up.ns, rec)
		default:
			up.extra = append(up.extra, rec)
		}
	}
	return up
}

// serveProtected asks qname with acks that say protected. It returns the
// reply, or nil, and the addresses of all reports before the reply.
func serveProtected(t testing.TB, qname string, up *upstream) (*dns.Msg, map[netip.Addr]bool) {
	t.Helper()
	reported := map[netip.Addr]bool{}
	rep := ackFunc(func(_ context.Context, o ipc.Observation) (ipc.Ack, error) {
		for _, a := range o.Addrs {
			reported[a.Unmap()] = true
		}
		return ipc.Ack{Protected: true}, nil
	})
	h := &handler{key: testKey, next: up, reporter: rep, timeout: 2 * time.Second}
	rec, _, _ := serve(context.Background(), h, qname) //nolint:errcheck // the caller reads the recorded reply, and a SERVFAIL writes nothing
	return rec.Msg, reported
}

// The same random replies to a protected name: the client gets SERVFAIL,
// or a reply whose addresses were all reported. A reply names nothing
// outside the qname, unless it goes out unchanged without an address and
// without a name that a client follows: such a reply needs no report.
func TestServeDNSProtectedRandomReplies(t *testing.T) {
	const iterations = 4000
	var failures, replies int
	for seed := range uint64(iterations) {
		r := rand.New(rand.NewPCG(seed, 116))
		g := newReplyGen(t, r)
		up := g.upstream()
		reply, reported := serveProtected(t, g.qname, up)
		if reply == nil {
			continue
		}
		replies++
		bad := safetyViolations(t, reply, reported)
		var outside []string
		for _, n := range namesOutside(g.qname, reply) {
			outside = append(outside, "names "+n)
		}
		// An unchanged reply is fine without any name outside, or when it
		// needed no report.
		unchanged := decodeAs(t, reply, false).String() == decodeAs(t, up.sent, false).String()
		if pass := passThroughViolations(t, reply); len(outside) > 0 && (!unchanged || len(pass) > 0) {
			bad = append(append(bad, outside...), pass...)
		}
		if len(bad) > 0 {
			failures++
			if failures <= 10 {
				t.Errorf("seed %d qname %q:\n  %s\nreply:\n%v", seed, g.qname, strings.Join(bad, "\n  "), reply)
			}
		}
	}
	if replies < iterations/4 {
		t.Errorf("only %d of %d protected queries got a reply", replies, iterations)
	}
}

// passThroughViolations returns why m needs flattening: an address, or a
// name that a client follows to another lookup.
func passThroughViolations(t testing.TB, m *dns.Msg) []string {
	t.Helper()
	var bad []string
	if as, _ := clientAddrs(t, m); len(as) > 0 {
		bad = append(bad, fmt.Sprintf("unchanged reply has addresses %v", as))
	}
	for _, sec := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, r := range sec {
			target := ""
			switch v := r.(type) {
			case *dns.CNAME, *dns.DNAME:
				bad = append(bad, fmt.Sprintf("unchanged reply has the alias %v", r))
			case *dns.HTTPS:
				target = v.Target
			case *dns.SVCB:
				target = v.Target
			}
			if target != "" && target != "." && nameKey(t, target) != nameKey(t, r.Header().Name) {
				bad = append(bad, fmt.Sprintf("unchanged reply has the target of %v", r))
			}
		}
	}
	return bad
}

func TestServeDNSAddressesOnRandomReplies(t *testing.T) {
	const iterations = 4000
	var failures, withAddrs, viaCNAME int
	for seed := range uint64(iterations) {
		r := rand.New(rand.NewPCG(seed, 116))
		g := newReplyGen(t, r)
		up := g.upstream()
		got := serveOnce(t, g.qname, up, nil)
		if up.sent == nil {
			t.Fatalf("seed %d: upstream wrote nothing", seed)
		}
		client := decodeAs(t, up.sent, false)
		if as, _ := clientAddrs(t, client); len(as) > 0 {
			withAddrs++
			if firstChainTTL(t, g.qname, client) != math.MaxUint32 {
				viaCNAME++
			}
		}
		if bad := checkOutcome(t, g.qname, up.sent, got); len(bad) > 0 {
			failures++
			if failures <= 10 {
				t.Errorf("seed %d qname %q:\n  %s\nreply:\n%v", seed, g.qname, strings.Join(bad, "\n  "), client)
			}
		}
	}
	t.Logf("%d replies: %d with addresses, %d of them with a CNAME from the qname; %d failed",
		iterations, withAddrs, viaCNAME, failures)
	if withAddrs < iterations/2 || viaCNAME < 200 {
		t.Errorf("generator does not reach the cases: withAddrs=%d viaCNAME=%d", withAddrs, viaCNAME)
	}
}

// TestRandomReportsReachIfboundd checks that ifboundd gets the same
// observation that the plugin reports, through the real socket.
func TestRandomReportsReachIfboundd(t *testing.T) {
	var (
		mu   sync.Mutex
		seen []ipc.Observation
	)
	client := startServer(t, observeFunc(func(_ context.Context, o ipc.Observation) error {
		mu.Lock()
		seen = append(seen, o)
		mu.Unlock()
		return nil
	}))
	for seed := range uint64(300) {
		r := rand.New(rand.NewPCG(seed, 7))
		g := newReplyGen(t, r)
		up := g.upstream()
		mu.Lock()
		seen = nil
		mu.Unlock()
		got := serveOnce(t, g.qname, up, func(ctx context.Context, o ipc.Observation) error {
			_, err := client.Report(ctx, o)
			return err
		})
		if bad := checkOutcome(t, g.qname, up.sent, got); len(bad) > 0 {
			t.Errorf("seed %d: %s", seed, strings.Join(bad, "; "))
			continue
		}
		mu.Lock()
		daemon := seen
		mu.Unlock()
		if got.calls == 0 {
			if len(daemon) != 0 {
				t.Errorf("seed %d: ifboundd got %d observations without a report", seed, len(daemon))
			}
			continue
		}
		if len(daemon) != 1 {
			t.Errorf("seed %d: ifboundd got %d observations, want 1", seed, len(daemon))
			continue
		}
		if want, d := got.obs, daemon[0]; d.QName != want.QName || d.TTL != want.TTL || !slices.Equal(d.Addrs, want.Addrs) {
			t.Errorf("seed %d: ifboundd got %+v, plugin reported %+v", seed, d, want)
		}
	}
}

// TestCheckOutcomeFlagsWrongReports proves that checkOutcome flags each class of wrong
// report. Each mutation of a correct outcome must be caught.
func TestCheckOutcomeFlagsWrongReports(t *testing.T) {
	up := &upstream{
		answer: []dns.RR{
			rr("q.example. 60 IN CNAME a.example."),
			rr("a.example. 30 IN HTTPS 1 svc.example. ipv4hint=192.0.2.7"),
			rr("a.example. 30 IN A 192.0.2.1"),
		},
	}
	good := serveOnce(t, "q.example.", up, nil)
	if bad := checkOutcome(t, "q.example.", up.sent, good); len(bad) > 0 {
		t.Fatalf("green outcome flagged: %v", bad)
	}
	mutate := map[string]func(o *outcome){
		"drop address":   func(o *outcome) { o.obs.Addrs = o.obs.Addrs[:1] },
		"other qname":    func(o *outcome) { o.obs.QName = "a.example." },
		"no report":      func(o *outcome) { o.calls = 0 },
		"TTL too long":   func(o *outcome) { o.obs.TTL = time.Hour },
		"reply withheld": func(o *outcome) { o.reply = nil },
	}
	for name, m := range mutate {
		t.Run(name, func(t *testing.T) {
			o := good
			o.obs.Addrs = slices.Clone(good.obs.Addrs)
			m(&o)
			if bad := checkOutcome(t, "q.example.", up.sent, o); len(bad) == 0 {
				t.Errorf("oracle did not flag %q", name)
			}
		})
	}
}
