package dnsplugin

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/Nagato-Yuzuru/ifbound/internal/ipc"
)

// answeredLinks is the longest chain for which the oracle demands an
// answer. The spec leaves the limit to the plugin; every resolver
// follows 10 links.
const answeredLinks = 10

// maxFollowDepth bounds how deep the client follows synthetic names. Deeper
// nested names grow toward the 255-octet limit.
const maxFollowDepth = 4

type visit struct {
	name, meaning string
	qtype         uint16
	depth         int
}

type closureStats struct {
	turns, synth, servfail, nxdomain, completions, flattened, addrs int
}

// follow is the client of F3: it queries origin for A, AAAA, and HTTPS,
// and then each synthetic TargetName it gets, and checks F1, F2, F4, and
// F5 on each reply. meaning is the name in the world that a query stands
// for.
func (e *worldEnv) follow(origin string, st *closureStats) []string {
	var problems []string
	var queue []visit
	for _, qt := range clientQTypes {
		queue = append(queue, visit{origin, origin, qt, 0})
	}
	seen := map[string]bool{}
	for len(queue) > 0 {
		v := queue[0]
		queue = queue[1:]
		key := canonName(v.name) + "/" + dns.TypeToString[v.qtype]
		if seen[key] {
			continue
		}
		seen[key] = true
		if !isUnder(v.name, origin) {
			problems = append(problems, fmt.Sprintf("F3: the client reaches %s outside %s", v.name, origin))
			continue
		}
		t := e.ask(v.name, v.qtype, true)
		st.count(t, v)
		ref := e.w.resolve(v.meaning, v.qtype)
		problems = append(problems, safetyProblems(t, v, origin)...)
		problems = append(problems, faithfulnessProblems(t, ref, v)...)
		next, p := nextVisits(t, ref, v)
		queue = append(queue, next...)
		problems = append(problems, p...)
	}
	return problems
}

// safetyProblems checks F1 and F2 for one reply of the closure of origin.
func safetyProblems(t clientTurn, v visit, origin string) []string {
	var problems []string
	if t.writes > 1 {
		problems = append(problems, fmt.Sprintf("%s %s: %d replies", v.name, dns.TypeToString[v.qtype], t.writes))
	}
	if t.reply != nil {
		if esc := namesOutside(v.name, t.reply); len(esc) > 0 {
			problems = append(problems, fmt.Sprintf("F1: reply to %s %s names %v\n%v", v.name, dns.TypeToString[v.qtype], esc, t.reply))
		}
	}
	if p := ackedBeforeReply(t, origin); p != "" {
		problems = append(problems, "F2: "+p)
	}
	return problems
}

// nextVisits returns the queries for the synthetic targets in the
// reply, each with the world name that it stands for.
func nextVisits(t clientTurn, ref chainRef, v visit) ([]visit, []string) {
	if t.reply == nil || v.depth >= maxFollowDepth {
		return nil, nil
	}
	var next []visit
	var problems []string
	for _, rr := range t.reply.Answer {
		s := svcbOf(rr)
		if s == nil || s.Target == "." || canonName(s.Target) == canonName(v.name) {
			continue
		}
		src := sourceRecord(ref.finals, s)
		if src == nil || src.Target == "." {
			problems = append(problems, fmt.Sprintf("F4: %s has no source record in %v", rr, ref.finals))
			continue
		}
		for _, qt := range clientQTypes {
			next = append(next, visit{s.Target, canonName(src.Target), qt, v.depth + 1})
		}
	}
	return next, problems
}

func (st *closureStats) count(t clientTurn, v visit) {
	st.turns++
	if v.depth > 0 {
		st.synth++
	}
	if len(t.upQs) > 1 {
		st.completions++
	}
	switch t.rcode {
	case dns.RcodeServerFailure:
		st.servfail++
	case dns.RcodeNameError:
		st.nxdomain++
	}
	if t.reply != nil && len(t.upWires) > 0 && t.upWires[0] != nil && !bytes.Equal(zeroID(t.wire), zeroID(t.upWires[0])) {
		st.flattened++
	}
	if t.reply != nil {
		st.addrs += len(readableAddrs(t.reply))
	}
}

// sourceRecord returns the record of finals with the priority of s.
func sourceRecord(finals []dns.RR, s *dns.SVCB) *dns.SVCB {
	for _, f := range finals {
		if fs := svcbOf(f); fs != nil && fs.Priority == s.Priority {
			return fs
		}
	}
	return nil
}

// faithfulnessProblems checks F4 and F5 for one protected reply against the
// reference resolver.
func faithfulnessProblems(t clientTurn, ref chainRef, v visit) []string {
	var problems []string
	bad := func(f string, a ...any) {
		problems = append(problems, fmt.Sprintf("%s %s (world name %s): ", v.name, dns.TypeToString[v.qtype], v.meaning)+fmt.Sprintf(f, a...))
	}
	if ref.err != nil {
		if t.rcode != dns.RcodeServerFailure {
			bad("F5: chain fails (%v), but the client gets rcode %s\n%v", ref.err, dns.RcodeToString[t.rcode], t.reply)
		}
		return problems
	}
	if ref.links > answeredLinks {
		return problems
	}
	if t.reply == nil {
		bad("F4: SERVFAIL (%v) for a chain of %d links that resolves", t.err, ref.links)
		return problems
	}
	if t.reply.Truncated {
		return problems
	}
	if t.reply.Rcode != ref.rcode {
		bad("F4: rcode %s, want %s", dns.RcodeToString[t.reply.Rcode], dns.RcodeToString[ref.rcode])
	}
	got := readableAddrs(&dns.Msg{Answer: t.reply.Answer})
	want := readableAddrs(&dns.Msg{Answer: ref.finals})
	if !slices.Equal(got, want) {
		bad("F4: addresses %v, want %v", got, want)
	}
	if v.qtype == dns.TypeHTTPS && v.depth <= 2 {
		if g, w := svcKeys(t.reply.Answer), svcKeys(ref.finals); !slices.Equal(g, w) {
			bad("F4: HTTPS priority and params %q, want %q", g, w)
		}
	}
	for _, p := range ttlProblems(t.reply, ref) {
		bad("F4: %s", p)
	}
	return problems
}

// ttlProblems checks that no TTL in reply exceeds the smallest TTL of
// the chain and of the final records.
func ttlProblems(reply *dns.Msg, ref chainRef) []string {
	var problems []string
	bound := ref.linkTTL
	if len(ref.finals) > 0 {
		bound = min(bound, ref.finals[0].Header().Ttl)
	}
	for _, rr := range reply.Answer {
		if rr.Header().Ttl > bound {
			problems = append(problems, fmt.Sprintf("TTL of %s above %d", rr, bound))
		}
		if hasSyntheticName(rr) && rr.Header().Ttl > maxSynthTTL {
			problems = append(problems, fmt.Sprintf("TTL of %s with a synthetic name above %d", rr, maxSynthTTL))
		}
	}
	if len(reply.Answer) > 0 || ref.links == 0 {
		return problems
	}
	for _, rr := range reply.Ns {
		if soa, ok := rr.(*dns.SOA); ok && (soa.Hdr.Ttl > ref.linkTTL || soa.Minttl > ref.linkTTL) {
			problems = append(problems, fmt.Sprintf("negative TTL of %s above the chain TTL %d", soa, ref.linkTTL))
		}
	}
	return problems
}

// hasSyntheticName reports whether a name of rr has the label _ifb.
func hasSyntheticName(rr dns.RR) bool {
	return slices.ContainsFunc(rdataNames(rr), func(n string) bool {
		return slices.ContainsFunc(dns.SplitDomainName(n), func(l string) bool { return strings.EqualFold(l, synthLabel) })
	})
}

func svcKeys(rrs []dns.RR) []string {
	var out []string
	for _, rr := range rrs {
		if s := svcbOf(rr); s != nil {
			out = append(out, fmt.Sprintf("%d %s", s.Priority, svcParams(s)))
		}
	}
	slices.Sort(out)
	return out
}

func zeroID(wire []byte) []byte {
	if len(wire) < 2 {
		return wire
	}
	c := slices.Clone(wire)
	c[0], c[1] = 0, 0
	return c
}

// protectedClosure runs the client closure from every protected qname of
// one random world.
func protectedClosure(seed uint64, st *closureStats) []string {
	rnd := rand.New(rand.NewPCG(seed, 0x1f1f)) //nolint:gosec // deterministic test worlds
	w := randomWorld(rnd)
	e := newWorldEnv(w, rnd, newTagKey(), nil)
	e.up.partial = 0.3
	e.up.decorate = true
	var problems []string
	for _, q := range protectedQNames {
		problems = append(problems, e.follow(randomLetterCase(rnd, q), st)...)
	}
	return problems
}

// TestProtectedClientStaysInsideItsName checks F1 to F5 on every reply
// that a client gets when it follows a protected reply.
func TestProtectedClientStaysInsideItsName(t *testing.T) {
	var st closureStats
	for seed := range uint64(400) {
		if p := protectedClosure(seed, &st); len(p) > 0 {
			t.Errorf("seed %d:\n%s", seed, strings.Join(p[:min(len(p), 3)], "\n"))
		}
	}
	t.Logf("turns %d, synthetic %d, servfail %d, nxdomain %d, completed chains %d, changed replies %d, addresses %d",
		st.turns, st.synth, st.servfail, st.nxdomain, st.completions, st.flattened, st.addrs)
	// The generator must reach every kind of case, or the run proves
	// nothing about it.
	for name, n := range map[string]int{"synthetic": st.synth, "servfail": st.servfail, "nxdomain": st.nxdomain, "completed": st.completions, "changed": st.flattened} {
		if n < 50 {
			t.Errorf("the worlds gave only %d %s turns", n, name)
		}
	}
}

func FuzzProtectedClientStaysInsideItsName(f *testing.F) {
	for s := range uint64(8) {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, seed uint64) {
		if p := protectedClosure(seed, new(closureStats)); len(p) > 0 {
			t.Fatal(strings.Join(p, "\n"))
		}
	})
}

// TestUnprotectedReplyKeepsTheUpstreamBytes checks F6: with an ack that says not
// protected, the client gets the bytes of the upstream reply.
func TestUnprotectedReplyKeepsTheUpstreamBytes(t *testing.T) {
	var n unchangedCount
	for seed := range uint64(300) {
		rnd := rand.New(rand.NewPCG(seed, 0x6)) //nolint:gosec // deterministic test worlds
		w := randomWorld(rnd)
		e := newWorldEnv(w, rnd, newTagKey(), nil)
		e.up.partial, e.up.decorate, e.up.truncate = 0.3, true, true
		for _, q := range unprotectedQNames {
			for _, qt := range clientQTypes {
				tu := e.ask(randomLetterCase(rnd, q), qt, rnd.IntN(4) != 0)
				n.check(t, seed, tu)
			}
		}
	}
	if n.failures > 0 {
		t.Errorf("F6: %d of %d unprotected replies changed", n.failures, n.total)
	}
}

type unchangedCount struct{ failures, total int }

// check checks F6 and F2 for one unprotected reply.
func (n *unchangedCount) check(t *testing.T, seed uint64, tu clientTurn) {
	t.Helper()
	n.total++
	if p := ackedBeforeReply(tu, tu.qname); p != "" {
		t.Errorf("seed %d: F2: %s", seed, p)
	}
	if p := unchangedProblem(tu); p != "" {
		n.failures++
		if n.failures <= 3 {
			t.Errorf("seed %d: %s", seed, p)
		}
	}
}

// unchangedProblem checks F6, and that the plugin sends no query of its
// own for an unprotected name.
func unchangedProblem(t clientTurn) string {
	if len(t.upWires) != 1 {
		return fmt.Sprintf("%s: upstream got %d queries %v, want 1", t.qname, len(t.upWires), t.upQs)
	}
	up := t.upWires[0]
	switch {
	case up == nil && t.writes == 0 && t.rcode == dns.RcodeServerFailure:
		return ""
	case up == nil:
		return fmt.Sprintf("%s: upstream wrote nothing, plugin wrote %d, rcode %d", t.qname, t.writes, t.rcode)
	case t.writes != 1:
		return fmt.Sprintf("%s %s: plugin wrote %d replies, rcode %d, err %v", t.qname, dns.TypeToString[t.qtype], t.writes, t.rcode, t.err)
	case !bytes.Equal(zeroID(t.wire), zeroID(up)):
		um := new(dns.Msg)
		_ = um.Unpack(up)
		return fmt.Sprintf("%s %s: reply differs from upstream\nupstream (%d bytes):\n%v\nclient (%d bytes):\n%v", t.qname, dns.TypeToString[t.qtype], len(up), um, len(t.wire), t.reply)
	}
	return ""
}

func chainTo(from string, n int, end string) []string {
	var out []string
	cur := from
	for i := range n {
		next := fmt.Sprintf("c%d.cdn.test.", i)
		out = append(out, fmt.Sprintf("%s 300 IN CNAME %s", cur, next))
		cur = next
	}
	return append(out, fmt.Sprintf("%s 300 IN A %s", cur, end))
}

type failCase struct {
	name    string
	records []string
	fail    string
	rcode   int
	partial float64
	cutAt   int
	qname   string
	want    int
}

// TestBrokenChainFailsClosed checks F5 on fixed worlds.
func TestBrokenChainFailsClosed(t *testing.T) {
	tests := []failCase{
		{name: "two-name loop", records: []string{"www.p.test. 60 IN CNAME e0.cdn.test.", "e0.cdn.test. 60 IN CNAME e1.cdn.test.", "e1.cdn.test. 60 IN CNAME e0.cdn.test."}, want: dns.RcodeServerFailure},
		{name: "loop back to the qname", records: []string{"www.p.test. 60 IN CNAME e0.cdn.test.", "e0.cdn.test. 60 IN CNAME www.p.test."}, want: dns.RcodeServerFailure},
		{name: "loop found by completion", records: []string{"www.p.test. 60 IN CNAME e0.cdn.test.", "e0.cdn.test. 60 IN CNAME e1.cdn.test.", "e1.cdn.test. 60 IN CNAME e2.cdn.test.", "e2.cdn.test. 60 IN CNAME e0.cdn.test."}, partial: 1, want: dns.RcodeServerFailure},
		{name: "chain of 64 links", records: chainTo("www.p.test.", 64, "192.0.2.1"), want: dns.RcodeServerFailure},
		{name: "chain of 64 links in pieces", records: chainTo("www.p.test.", 64, "192.0.2.1"), partial: 1, want: dns.RcodeServerFailure},
		{name: "chain of 8 links resolves", records: chainTo("www.p.test.", 8, "192.0.2.1"), want: dns.RcodeSuccess},
		{name: "chain of 8 links in pieces resolves", records: chainTo("www.p.test.", 8, "192.0.2.1"), partial: 1, want: dns.RcodeSuccess},
		{name: "rest of the chain fails upstream", records: []string{"www.p.test. 60 IN CNAME e0.cdn.test.", "e0.cdn.test. 60 IN CNAME e1.cdn.test.", "e1.cdn.test. 60 IN A 192.0.2.1"}, fail: "e1.cdn.test.", partial: 1, want: dns.RcodeServerFailure},
		{name: "rest of the chain is refused upstream", records: []string{"www.p.test. 60 IN CNAME e0.cdn.test.", "e0.cdn.test. 60 IN CNAME e1.cdn.test.", "e1.cdn.test. 60 IN A 192.0.2.1"}, fail: "e1.cdn.test.", rcode: dns.RcodeRefused, cutAt: 1, want: dns.RcodeServerFailure},
		{name: "rest of the chain is not implemented upstream", records: []string{"www.p.test. 60 IN CNAME e0.cdn.test.", "e0.cdn.test. 60 IN CNAME e1.cdn.test.", "e1.cdn.test. 60 IN A 192.0.2.1"}, fail: "e1.cdn.test.", rcode: dns.RcodeNotImplemented, cutAt: 1, want: dns.RcodeServerFailure},
		{name: "qname fails upstream", records: []string{"www.p.test. 60 IN A 192.0.2.1"}, fail: "www.p.test.", want: dns.RcodeServerFailure},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for seed := range uint64(20) {
				tt.run(t, seed)
			}
		})
	}
}

func (tt failCase) run(t *testing.T, seed uint64) {
	t.Helper()
	w := newZoneWorld(tt.records...)
	switch {
	case tt.fail != "" && tt.rcode != 0:
		w.rcode[tt.fail] = tt.rcode
	case tt.fail != "":
		w.fail[tt.fail] = true
	}
	e := newWorldEnv(w, rand.New(rand.NewPCG(seed, 5)), newTagKey(), nil) //nolint:gosec // deterministic test worlds
	e.up.partial, e.up.cutAt = tt.partial, tt.cutAt
	res := e.ask("www.p.test.", dns.TypeA, true)
	if res.rcode != tt.want {
		t.Fatalf("seed %d: rcode %s, want %s\n%v", seed, dns.RcodeToString[res.rcode], dns.RcodeToString[tt.want], res.reply)
	}
	if p := safetyProblems(res, visit{name: "www.p.test.", qtype: dns.TypeA}, "www.p.test."); len(p) > 0 {
		t.Fatal(strings.Join(p, "\n"))
	}
	if tt.want == dns.RcodeSuccess && !slices.Equal(readableAddrs(res.reply), []netip.Addr{netip.MustParseAddr("192.0.2.1")}) {
		t.Fatalf("addresses %v, want 192.0.2.1", readableAddrs(res.reply))
	}
}

// tagWorld has one protected name with an HTTPS alias target.
func tagWorld() *zoneWorld {
	return newZoneWorld(
		"www.p.test. 300 IN HTTPS 1 e0.cdn.test. alpn=h2",
		"api.p.test. 300 IN HTTPS 1 e0.cdn.test. alpn=h2",
		"e0.cdn.test. 300 IN A 192.0.2.1",
		"e1.cdn.test. 300 IN A 192.0.2.2",
	)
}

// synthTargetOf asks qname for HTTPS and returns its one synthetic target.
func synthTargetOf(t *testing.T, e *worldEnv, qname string) string {
	t.Helper()
	res := e.ask(qname, dns.TypeHTTPS, true)
	if res.reply == nil || len(res.reply.Answer) != 1 {
		t.Fatalf("HTTPS reply to %s: %v", qname, res.reply)
	}
	s := svcbOf(res.reply.Answer[0])
	if s == nil || !isUnder(s.Target, qname) || canonName(s.Target) == canonName(qname) {
		t.Fatalf("no synthetic target below %s in %v", qname, res.reply.Answer[0])
	}
	return s.Target
}

func requireRefused(t *testing.T, e *worldEnv, name string) {
	t.Helper()
	res := e.ask(name, dns.TypeA, true)
	if res.rcode != dns.RcodeServerFailure || res.writes != 0 {
		t.Errorf("%s: rcode %s, %d writes, want SERVFAIL and no reply\n%v", name, dns.RcodeToString[res.rcode], res.writes, res.reply)
	}
	if len(res.upQs) != 0 {
		t.Errorf("%s: upstream got %v, want no query", name, res.upQs)
	}
	for _, ev := range res.events {
		if ev.obs != nil {
			t.Errorf("%s: report %v, want none", name, *ev.obs)
		}
	}
}

// TestSyntheticTagsResolveOnlyIssuedNames checks F7.
func TestSyntheticTagsResolveOnlyIssuedNames(t *testing.T) {
	rnd := rand.New(rand.NewPCG(7, 7)) //nolint:gosec // deterministic test worlds
	e := newWorldEnv(tagWorld(), rnd, newTagKey(), nil)
	syn := synthTargetOf(t, e, "www.p.test.")
	labels := dns.SplitDomainName(syn)
	// labels: e0 cdn test _ifb <tag> www p test
	i := slices.Index(labels, "_ifb")
	if i < 0 || i+1 >= len(labels) {
		t.Fatalf("synthetic name %s has no _ifb label", syn)
	}
	tag := labels[i+1]
	join := func(ls ...string) string { return strings.Join(ls, ".") + "." }

	t.Run("issued tag resolves in any case", func(t *testing.T) {
		for _, name := range []string{syn, strings.ToUpper(syn), randomLetterCase(rnd, syn)} {
			res := e.ask(name, dns.TypeA, true)
			if res.rcode != dns.RcodeSuccess || !slices.Equal(readableAddrs(res.reply), []netip.Addr{netip.MustParseAddr("192.0.2.1")}) {
				t.Errorf("%s: rcode %s, reply %v", name, dns.RcodeToString[res.rcode], res.reply)
			}
			if p := ackedBeforeReply(res, "www.p.test."); p != "" {
				t.Errorf("F2: %s", p)
			}
		}
	})
	t.Run("changed tag", func(t *testing.T) {
		flip := []byte(tag)
		flip[0] = map[bool]byte{true: 'b', false: 'a'}[flip[0] == 'a']
		requireRefused(t, e, join(append(append(slices.Clone(labels[:i+1]), string(flip)), labels[i+2:]...)...))
		requireRefused(t, e, join(append(append(slices.Clone(labels[:i+1]), strings.Repeat("a", len(tag))), labels[i+2:]...)...))
		requireRefused(t, e, join(append(append(slices.Clone(labels[:i+1]), tag[:len(tag)-1]), labels[i+2:]...)...))
		requireRefused(t, e, join(append(slices.Clone(labels[:i+1]), labels[i+2:]...)...))
	})
	t.Run("tag of another target", func(t *testing.T) {
		requireRefused(t, e, join(append([]string{"e1"}, labels[1:]...)...))
	})
	t.Run("tag of another origin", func(t *testing.T) {
		requireRefused(t, e, join(append(slices.Clone(labels[:i+2]), "api", "p", "test")...))
		requireRefused(t, e, join(append(slices.Clone(labels[:i+2]), "p", "test")...))
	})
	t.Run("new instance rejects old tags", func(t *testing.T) {
		e2 := newWorldEnv(tagWorld(), rnd, newTagKey(), nil)
		requireRefused(t, e2, syn)
		if s2 := synthTargetOf(t, e2, "www.p.test."); canonName(s2) == canonName(syn) {
			t.Errorf("new instance issued the old name %s", s2)
		}
	})
}

// FuzzForgedSyntheticNameIsRefused checks F7 for names the plugin never issued.
func FuzzForgedSyntheticNameIsRefused(f *testing.F) {
	f.Add("e0.cdn.test", "aaaaaaaaaaaaaaaaaaaaaaaaaa", "www.p.test")
	f.Add("x", "", "p.test")
	f.Add("a.b", "zz", "q.www.p.test")
	key := newTagKey()
	f.Fuzz(func(t *testing.T, target, tag, origin string) {
		name := dns.Fqdn(target) + "_ifb." + tag + "." + dns.Fqdn(origin)
		if _, ok := dns.IsDomainName(name); !ok {
			return
		}
		if _, err := wireName(name); err != nil {
			return
		}
		// An escape can hide the label: "\\._ifb" is one label.
		labels := dns.SplitDomainName(name)
		if !slices.ContainsFunc(labels[1:], func(l string) bool { return strings.EqualFold(l, "_ifb") }) {
			return
		}
		e := newWorldEnv(tagWorld(), rand.New(rand.NewPCG(1, 1)), key, nil) //nolint:gosec // deterministic test worlds
		requireRefused(t, e, name)
	})
}

// rawFrame writes one IPC frame.
func rawFrame(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	buf := binary.BigEndian.AppendUint32(nil, uint32(len(b))) //nolint:gosec // test frames are small
	_, err = w.Write(append(buf, b...))
	return err
}

func readRawFrame(r io.Reader) (map[string]json.RawMessage, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	b := make([]byte, binary.BigEndian.Uint32(hdr[:]))
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	var env map[string]json.RawMessage
	return env, json.Unmarshal(b, &env)
}

// fixedReplyDaemon serves each connection with one fixed raw reply.
func fixedReplyDaemon(t *testing.T, reply string) string {
	t.Helper()
	path := socketPath(t)
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				if _, err := readRawFrame(c); err != nil {
					return
				}
				var v any
				_ = json.Unmarshal([]byte(reply), &v)
				_ = rawFrame(c, v)
			}()
		}
	}()
	return path
}

func ipcWorld() *zoneWorld {
	return newZoneWorld("www.p.test. 300 IN CNAME e0.cdn.test.", "e0.cdn.test. 300 IN A 192.0.2.1", "e1.cdn.test. 300 IN A 192.0.2.2")
}

// TestDaemonOfAnotherVersionGivesServfail checks F8 with the real ipc.Client of
// the plugin and fake daemons on a unix socket.
func TestDaemonOfAnotherVersionGivesServfail(t *testing.T) {
	bad := map[string]string{
		"v2 daemon ack":                    `{"v":2,"type":"ack"}`,
		"v2 daemon ack with protected":     `{"v":2,"type":"ack","body":{"protected":true}}`,
		"v2 daemon ack with not protected": `{"v":2,"type":"ack","body":{"protected":false}}`,
		"v2 daemon reject of v3":           `{"v":2,"type":"reject","body":{"reason":"unsupported version 3"}}`,
		"v3 ack without body":              `{"v":3,"type":"ack"}`,
		"v3 ack with empty body":           `{"v":3,"type":"ack","body":{}}`,
		"v3 ack with null flag":            `{"v":3,"type":"ack","body":{"protected":null}}`,
		"v3 ack with string flag":          `{"v":3,"type":"ack","body":{"protected":"false"}}`,
		"v4 ack":                           `{"v":4,"type":"ack","body":{"protected":false}}`,
	}
	for name, reply := range bad {
		t.Run(name, func(t *testing.T) {
			client := ipc.NewClient(fixedReplyDaemon(t, reply), selfUID())
			e := newWorldEnv(ipcWorld(), rand.New(rand.NewPCG(1, 2)), newTagKey(), client) //nolint:gosec // deterministic test worlds
			for _, q := range []string{"www.p.test.", "e1.cdn.test."} {
				res := e.ask(q, dns.TypeA, true)
				if res.writes != 0 || res.rcode != dns.RcodeServerFailure {
					t.Errorf("%s: %d replies, rcode %s, want SERVFAIL\n%v", q, res.writes, dns.RcodeToString[res.rcode], res.reply)
				}
			}
		})
	}
}

// TestTooLongSyntheticNameDropsOnlyItsRecord checks the HTTPS record
// whose synthetic name does not fit in 255 octets: only that record goes
// away. HTTPS records are optional, and the client falls back to A and
// AAAA. F1 and F2 hold.
func TestTooLongSyntheticNameDropsOnlyItsRecord(t *testing.T) {
	long := strings.Repeat(strings.Repeat("a", 50)+".", 4) + "www.p.test."
	w := newZoneWorld(
		long+" 300 IN HTTPS 1 e0.cdn.test. alpn=h2 ipv4hint=192.0.2.9",
		long+" 300 IN HTTPS 2 . alpn=h3",
		long+" 300 IN A 192.0.2.1",
		"e0.cdn.test. 300 IN A 192.0.2.2",
	)
	e := newWorldEnv(w, rand.New(rand.NewPCG(3, 3)), newTagKey(), nil) //nolint:gosec // deterministic test worlds
	res := e.ask(long, dns.TypeHTTPS, true)
	if res.reply == nil || res.rcode != dns.RcodeSuccess {
		t.Fatalf("rcode %s, reply %v; want the reply without the long record", dns.RcodeToString[res.rcode], res.reply)
	}
	if esc := namesOutside(long, res.reply); len(esc) > 0 {
		t.Fatalf("F1: %v", esc)
	}
	if p := ackedBeforeReply(res, long); p != "" {
		t.Fatalf("F2: %s", p)
	}
	if got, want := svcKeys(res.reply.Answer), []string{"2 alpn=h3"}; !slices.Equal(got, want) {
		t.Errorf("HTTPS records %q, want %q\n%v", got, want, res.reply)
	}
}

// TestRefusedQNameKeepsItsRcode pins the case that F4 and F5 leave
// open: the upstream refuses the protected qname itself. The reply has no
// address and no name, so it goes out as it is: REFUSED without a record.
func TestRefusedQNameKeepsItsRcode(t *testing.T) {
	w := newZoneWorld("www.p.test. 60 IN CNAME e0.cdn.test.", "e0.cdn.test. 60 IN A 192.0.2.1")
	w.rcode["www.p.test."] = dns.RcodeRefused
	e := newWorldEnv(w, rand.New(rand.NewPCG(4, 4)), newTagKey(), nil) //nolint:gosec // deterministic test worlds
	res := e.ask("www.p.test.", dns.TypeA, true)
	if res.rcode != dns.RcodeRefused || res.reply == nil || len(res.reply.Answer)+len(res.reply.Ns) > 0 {
		t.Errorf("rcode %s, reply %v; want REFUSED without a record", dns.RcodeToString[res.rcode], res.reply)
	}
}

// TestKnownGapListsEveryNameType keeps knownGapTypes complete: each record
// type of miekg/dns whose data has a name is in the list, or flatten has a
// rule of its own for it. A new type in a new release of miekg/dns fails
// here until someone decides how a protected reply treats it.
func TestKnownGapListsEveryNameType(t *testing.T) {
	ownRule := map[uint16]bool{
		dns.TypeCNAME: true, dns.TypeDNAME: true, dns.TypeHTTPS: true, dns.TypeSVCB: true,
		dns.TypeRRSIG: true, dns.TypeNSEC: true,
	}
	for typ, newRR := range dns.TypeToRR {
		has := hasNameField(reflect.TypeOf(newRR()).Elem())
		switch {
		case has && !ownRule[typ] && !knownGapTypes[typ]:
			t.Errorf("type %s has a name in its data, but it is not in knownGapTypes", dns.TypeToString[typ])
		case !has && knownGapTypes[typ]:
			t.Errorf("type %s in knownGapTypes has no name in its data", dns.TypeToString[typ])
		}
	}
}

// hasNameField reports whether a field of the record struct t, at any
// depth, holds a domain name.
func hasNameField(t reflect.Type) bool {
	for i := range t.NumField() {
		f := t.Field(i)
		switch {
		case f.Type == reflect.TypeFor[dns.RR_Header]():
		case f.Type.Kind() == reflect.Struct && hasNameField(f.Type):
			return true
		case strings.Contains(f.Tag.Get("dns"), "domain-name"):
			return true
		}
	}
	return false
}
