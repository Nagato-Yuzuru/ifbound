package dnsplugin

import (
	"context"
	"fmt"
	"maps"
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

// The oracle in this file computes the alias set of a reply from the spec,
// independent of collect.go. It compares names by their wire form with ASCII
// letters folded, so it shares no name logic with the code under test.

// aliasKey returns the comparison key of a presentation name.
func aliasKey(t testing.TB, name string) string {
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

// aliasSpec is the alias set that the spec requires for one reply.
type aliasSpec struct {
	ttl   map[string]uint32          // key -> largest TTL of the records that point to it
	forms map[string]map[string]bool // key -> presentation forms seen as a target
	// qnameTarget is true when an SVCB or HTTPS TargetName equals the qname.
	// The spec accepts a report with or without the qname then.
	qnameTarget bool

	qk, rootK string // the keys of the qname and of the root
}

// wantAliases returns the alias set that the spec requires for qname in m.
func wantAliases(t testing.TB, qname string, m *dns.Msg) aliasSpec {
	t.Helper()
	w := aliasSpec{
		qk: aliasKey(t, qname), rootK: aliasKey(t, "."),
		ttl: map[string]uint32{}, forms: map[string]map[string]bool{},
	}
	w.walkCNAMEs(t, m.Answer)
	w.noteTargets(t, m)
	return w
}

// note records name as a target of a record with ttl. The qname and the
// root are never aliases.
func (w *aliasSpec) note(t testing.TB, name string, ttl uint32) {
	t.Helper()
	k := aliasKey(t, name)
	if k == w.rootK || k == w.qk {
		return
	}
	if old, ok := w.ttl[k]; !ok || ttl > old {
		w.ttl[k] = ttl
	}
	if w.forms[k] == nil {
		w.forms[k] = map[string]bool{}
	}
	w.forms[k][name] = true
}

// walkCNAMEs notes every name reachable from the qname along CNAME records
// in answer. It walks depth-first over a visited set; the order is not
// important.
func (w *aliasSpec) walkCNAMEs(t testing.TB, answer []dns.RR) {
	t.Helper()
	edges := map[string][]*dns.CNAME{}
	for _, r := range answer {
		if c, ok := r.(*dns.CNAME); ok {
			k := aliasKey(t, c.Hdr.Name)
			edges[k] = append(edges[k], c)
		}
	}
	visited := map[string]bool{w.qk: true}
	for stack := []string{w.qk}; len(stack) > 0; {
		k := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, c := range edges[k] {
			w.note(t, c.Target, c.Hdr.Ttl)
			if tk := aliasKey(t, c.Target); !visited[tk] {
				visited[tk] = true
				stack = append(stack, tk)
			}
		}
	}
}

// noteTargets notes every SVCB or HTTPS TargetName in any section of m that
// is not "." and not the owner of its record.
func (w *aliasSpec) noteTargets(t testing.TB, m *dns.Msg) {
	t.Helper()
	for _, r := range slices.Concat(m.Answer, m.Ns, m.Extra) {
		var target string
		switch v := r.(type) {
		case *dns.SVCB:
			target = v.Target
		case *dns.HTTPS:
			target = v.Target
		default:
			continue
		}
		tk := aliasKey(t, target)
		switch {
		case tk == w.rootK || tk == aliasKey(t, r.Header().Name):
		case tk == w.qk:
			w.qnameTarget = true
		default:
			w.note(t, target, r.Header().Ttl)
		}
	}
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

// firstChainTTL is the TTL bound of the base commit: the smallest TTL of
// the CNAME records on the first-match chain from qname. The new code must
// not report a larger TTL than the base did.
func firstChainTTL(t testing.TB, qname string, m *dns.Msg) uint32 {
	t.Helper()
	ttl := uint32(math.MaxUint32)
	seen := map[string]bool{}
	cur := aliasKey(t, qname)
	for !seen[cur] {
		seen[cur] = true
		var next *dns.CNAME
		for _, r := range m.Answer {
			if c, ok := r.(*dns.CNAME); ok && aliasKey(t, c.Hdr.Name) == cur {
				next = c
				break
			}
		}
		if next == nil {
			break
		}
		ttl = min(ttl, next.Hdr.Ttl)
		cur = aliasKey(t, next.Target)
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
	h := &handler{next: up, reporter: rep, timeout: 2 * time.Second}
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
	want := wantAliases(t, qname, client)
	wantAddrs, _ := clientAddrs(t, client)
	n := len(want.ttl)
	nMax := n
	if want.qnameTarget {
		nMax++
	}

	servfail := got.rcode == dns.RcodeServerFailure && got.reply == nil
	switch {
	case n > ipc.MaxAliases:
		if !servfail || got.calls != 0 {
			fail("%d aliases: rcode %d, reply %v, %d reports; want SERVFAIL, no reply, no report",
				n, got.rcode, got.reply != nil, got.calls)
		}
		return bad
	case nMax > ipc.MaxAliases && servfail:
		if got.calls != 0 {
			fail("SERVFAIL at the limit after %d reports", got.calls)
		}
		return bad
	}
	if got.reply == nil {
		fail("no reply (rcode %d, err %v) for %d aliases and %d addresses", got.rcode, got.err, n, len(wantAddrs))
		return bad
	}
	if a, b := decodeAs(t, got.reply, false), client; a.String() != b.String() {
		fail("client got\n%v\nwant\n%v", a, b)
	}
	if n == 0 && len(wantAddrs) == 0 {
		return bad // nothing to protect; a report is optional
	}
	if got.calls != 1 {
		fail("%d reports, want 1", got.calls)
		return bad
	}
	o := got.obs
	if o.QName != qname {
		fail("qname %q, want %q", o.QName, qname)
	}

	reported, aliasBad := aliasViolations(t, qname, want, o.Aliases)
	bad = append(bad, aliasBad...)

	gotAddrs, addrBad := addressViolations(t, qname, client, o)
	bad = append(bad, addrBad...)
	return append(bad, safetyViolations(t, qname, got.reply, reported, gotAddrs)...)
}

// addressViolations checks the addresses of o against the reply that the
// client decodes: every address, and a TTL not above the bound of the base
// behavior. It returns the reported addresses, unmapped as ifboundd sees
// them, and the violations.
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
			bad = append(bad, fmt.Sprintf("address TTL %v above the base bound %ds", o.TTL, bound))
		}
	}
	return gotAddrs, bad
}

// safetyViolations checks that, in each encoding of the reply, the client
// decodes no alias name and no address that the acked report does not
// have.
func safetyViolations(t testing.TB, qname string, reply *dns.Msg, reported map[string]ipc.Alias, gotAddrs map[netip.Addr]bool) []string {
	t.Helper()
	var bad []string
	for _, compress := range []bool{false, true} {
		dec := decodeAs(t, reply, compress)
		for k, forms := range wantAliases(t, qname, dec).forms {
			if _, ok := reported[k]; !ok {
				bad = append(bad, fmt.Sprintf("UNSAFE: client (compress=%v) decodes unreported alias %v",
					compress, slices.Collect(maps.Keys(forms))))
			}
		}
		decAddrs, _ := clientAddrs(t, dec)
		for a := range decAddrs {
			if !gotAddrs[a] {
				bad = append(bad, fmt.Sprintf("UNSAFE: client (compress=%v) decodes unreported address %v", compress, a))
			}
		}
	}
	return bad
}

// aliasViolations compares reported with the alias set that want gives
// for qname: each name once, every required name, the largest TTL, and a
// form that the client decodes. It returns the reported aliases by key and
// the violations.
func aliasViolations(t testing.TB, qname string, want aliasSpec, reported []ipc.Alias) (map[string]ipc.Alias, []string) {
	t.Helper()
	var bad []string
	fail := func(format string, args ...any) { bad = append(bad, fmt.Sprintf(format, args...)) }
	qk := aliasKey(t, qname)
	byKey := map[string]ipc.Alias{}
	for _, a := range reported {
		k := aliasKey(t, a.Name)
		if _, dup := byKey[k]; dup {
			fail("alias %q reported twice", a.Name)
		}
		byKey[k] = a
	}
	for k, ttl := range want.ttl {
		a, ok := byKey[k]
		switch {
		case !ok:
			fail("MISSING alias %q (TTL %d)", slices.Collect(maps.Keys(want.forms[k]))[0], ttl)
		case a.TTL != time.Duration(ttl)*time.Second:
			fail("alias %q TTL %v, want %ds", a.Name, a.TTL, ttl)
		case !want.forms[k][a.Name]:
			fail("alias %q not in a form the client decodes (%v)", a.Name, slices.Collect(maps.Keys(want.forms[k])))
		}
	}
	for k, a := range byKey {
		if _, ok := want.ttl[k]; ok || (k == qk && want.qnameTarget) {
			continue
		}
		fail("EXTRA alias %q", a.Name)
	}
	return byKey, bad
}

// requireAliasesReported fails the test when reported is not the alias set
// that the client decodes from sent for qname.
func requireAliasesReported(t *testing.T, qname string, sent *dns.Msg, reported []ipc.Alias) {
	t.Helper()
	_, bad := aliasViolations(t, qname, wantAliases(t, qname, decodeAs(t, sent, false)), reported)
	for _, b := range bad {
		t.Error(b)
	}
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

func TestServeDNSAliasesOnRandomReplies(t *testing.T) {
	const iterations = 4000
	var failures, over, atLimit, aliasOnly int
	for seed := range uint64(iterations) {
		r := rand.New(rand.NewPCG(seed, 116))
		g := newReplyGen(t, r)
		up := g.upstream()
		got := serveOnce(t, g.qname, up, nil)
		if up.sent == nil {
			t.Fatalf("seed %d: upstream wrote nothing", seed)
		}
		client := decodeAs(t, up.sent, false)
		w := wantAliases(t, g.qname, client)
		as, _ := clientAddrs(t, client)
		switch n := len(w.ttl); {
		case n > ipc.MaxAliases:
			over++
		case n == ipc.MaxAliases:
			atLimit++
		case n > 0 && len(as) == 0:
			aliasOnly++
		}
		if bad := checkOutcome(t, g.qname, up.sent, got); len(bad) > 0 {
			failures++
			if failures <= 10 {
				t.Errorf("seed %d qname %q:\n  %s\nreply:\n%v", seed, g.qname, strings.Join(bad, "\n  "), client)
			}
		}
	}
	t.Logf("%d replies: %d over the limit, %d at the limit, %d with aliases and no address; %d failed",
		iterations, over, atLimit, aliasOnly, failures)
	if over < 20 || atLimit < 10 || aliasOnly < 50 {
		t.Errorf("generator does not reach the boundaries: over=%d atLimit=%d aliasOnly=%d", over, atLimit, aliasOnly)
	}
}

// TestRandomAliasReportsReachIfboundd checks that ifboundd gets the same
// aliases that the plugin reports, byte for byte, through the real socket.
func TestRandomAliasReportsReachIfboundd(t *testing.T) {
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
		got := serveOnce(t, g.qname, up, client.Report)
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
		if want, d := got.obs.Aliases, daemon[0].Aliases; !slices.Equal(want, d) && (len(want)+len(d) != 0) {
			t.Errorf("seed %d: ifboundd aliases %+v, plugin reported %+v", seed, d, want)
		}
	}
}

func cnameChain(n int) []dns.RR {
	out := make([]dns.RR, 0, n+1)
	prev := "q.example."
	for i := range n {
		next := fmt.Sprintf("c%d.example.", i)
		out = append(out, &dns.CNAME{Hdr: dns.RR_Header{Name: prev, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: next})
		prev = next
	}
	return append(out, &dns.A{Hdr: dns.RR_Header{Name: prev, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 1)})
}

func cnameFan(n int) []dns.RR {
	out := make([]dns.RR, 0, n)
	for i := range n {
		out = append(out, &dns.CNAME{
			Hdr:    dns.RR_Header{Name: "q.example.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
			Target: fmt.Sprintf("f%d.example.", i),
		})
	}
	return out
}

func TestServeDNSAliasLimit(t *testing.T) {
	https := func(owner, target string) dns.RR {
		return rr(fmt.Sprintf("%s 60 IN HTTPS 1 %s", owner, target))
	}
	tests := []struct {
		name     string
		up       upstream
		wantN    int // aliases reported; -1 means SERVFAIL and no report
		wantSent bool
	}{
		{"32 in a chain", upstream{answer: cnameChain(32)}, 32, true},
		{"33 in a chain", upstream{answer: cnameChain(33)}, -1, false},
		{"32 in a fan, no address", upstream{answer: cnameFan(32)}, 32, true},
		{"33 in a fan, no address", upstream{answer: cnameFan(33)}, -1, false},
		{"32 in a chain and one HTTPS target in additional", upstream{
			answer: cnameChain(32), extra: []dns.RR{https("z.example.", "t.example.")},
		}, -1, false},
		{"32 in a chain and one HTTPS target in authority", upstream{
			answer: cnameChain(32), ns: []dns.RR{https("z.example.", "t.example.")},
		}, -1, false},
		{"32 in a chain and an HTTPS target equal to its owner", upstream{
			answer: cnameChain(32), extra: []dns.RR{https("z.example.", "Z.EXAMPLE.")},
		}, 32, true},
		{"32 in a chain and an HTTPS root target", upstream{
			answer: cnameChain(32), extra: []dns.RR{https("z.example.", ".")},
		}, 32, true},
		{"32 in a chain and a case variant of one of them", upstream{
			answer: cnameChain(32), extra: []dns.RR{https("z.example.", "C31.EXAMPLE.")},
		}, 32, true},
		{"32 in a chain and 40 unreachable CNAMEs", upstream{
			answer: append(cnameChain(32), func() []dns.RR {
				var out []dns.RR
				for i := range 40 {
					out = append(out, rr(fmt.Sprintf("u%d.example. 60 IN CNAME v%d.example.", i, i)))
				}
				return out
			}()...),
		}, 32, true},
		{"32 in a chain and a CNAME back to the qname", upstream{
			answer: append(cnameChain(32), rr("c31.example. 60 IN CNAME Q.example.")),
		}, 32, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			up := tc.up
			var reported []ipc.Alias
			got := serveOnce(t, "q.example.", &up, func(_ context.Context, o ipc.Observation) error {
				reported = o.Aliases
				return nil
			})
			if tc.wantN < 0 {
				if got.rcode != dns.RcodeServerFailure || got.reply != nil || got.calls != 0 || got.err == nil {
					t.Errorf("rcode %d, err %v, reply %v, %d reports; want SERVFAIL, error, no reply, no report",
						got.rcode, got.err, got.reply != nil, got.calls)
				}
				return
			}
			if got.reply == nil || got.calls != 1 || len(reported) != tc.wantN {
				t.Errorf("reply %v, %d reports, %d aliases; want a reply, 1 report, %d aliases",
					got.reply != nil, got.calls, len(reported), tc.wantN)
			}
			if bad := checkOutcome(t, "q.example.", up.sent, got); len(bad) > 0 {
				t.Error(strings.Join(bad, "\n"))
			}
		})
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
		"drop alias":  func(o *outcome) { o.obs.Aliases = o.obs.Aliases[:1] },
		"shorter TTL": func(o *outcome) { o.obs.Aliases[0].TTL-- },
		"extra alias": func(o *outcome) { o.obs.Aliases = append(o.obs.Aliases, ipc.Alias{Name: "zz.example."}) },
		"duplicate": func(o *outcome) {
			o.obs.Aliases = append(o.obs.Aliases, ipc.Alias{Name: "A.EXAMPLE.", TTL: 60 * time.Second})
		},
		"other form":     func(o *outcome) { o.obs.Aliases[0].Name = "A.EXAMPLE." },
		"drop address":   func(o *outcome) { o.obs.Addrs = o.obs.Addrs[:1] },
		"no report":      func(o *outcome) { o.calls = 0 },
		"TTL too long":   func(o *outcome) { o.obs.TTL = time.Hour },
		"reply withheld": func(o *outcome) { o.reply = nil },
	}
	for name, m := range mutate {
		t.Run(name, func(t *testing.T) {
			o := good
			o.obs.Aliases = slices.Clone(good.obs.Aliases)
			o.obs.Addrs = slices.Clone(good.obs.Addrs)
			m(&o)
			if bad := checkOutcome(t, "q.example.", up.sent, o); len(bad) == 0 {
				t.Errorf("oracle did not flag %q", name)
			}
		})
	}
}
