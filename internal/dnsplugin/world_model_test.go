package dnsplugin

// This file is the model of the tests in world_checks_test.go. It
// computes every expected value from a randomized world of zones, not
// from the code under test: a world, a fake upstream that answers from
// it (the next plugin), a reference resolver that follows the chains in
// it, a fake daemon, and a client writer that keeps the order of acks and
// replies.
//
// The tests name the rules that they check:
//
//	F1  a reply to a protected name names nothing outside that name,
//	    except the SOA of a negative answer and the known gap
//	    (knownGapTypes)
//	F2  every address of a reply is in an ack before the reply
//	F3  a client that follows the synthetic names stays below the name
//	F4  the reply has the addresses, rcode, HTTPS parameters, and no
//	    longer TTL than the chain that a resolver follows
//	F5  a chain that a resolver cannot follow gives SERVFAIL
//	F6  an unprotected reply keeps the bytes of the upstream reply
//	F7  only a synthetic name that the plugin made resolves
//	F8  a daemon of another protocol version gives SERVFAIL
//	F9  the ack is protected when the name matches a policy

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"

	"github.com/Nagato-Yuzuru/ifbound/internal/ipc"
)

// worldApex is the protected apex of the fake daemon.
const worldApex = "p.test."

var (
	errWorldLoop     = errors.New("oracle: CNAME loop in the world")
	errWorldFail     = errors.New("oracle: upstream fails for a name on the chain")
	errWorldUpstream = errors.New("oracle: upstream error without a reply")
)

func canonName(n string) string { return strings.ToLower(dns.Fqdn(n)) }

// isUnder reports whether name is root or below root, without ASCII case.
func isUnder(name, root string) bool {
	n, r := canonName(name), canonName(root)
	return r == "." || n == r || strings.HasSuffix(n, "."+r)
}

func worldRR(s string) dns.RR {
	r, err := dns.NewRR(s)
	if err != nil {
		panic(fmt.Sprintf("fixture %q: %v", s, err))
	}
	return r
}

type worldLink struct {
	target string
	ttl    uint32
}

// zoneWorld is the authoritative data of all zones.
type zoneWorld struct {
	cname map[string]worldLink
	dname map[string]worldLink
	rrs   map[string][]dns.RR
	fail  map[string]bool
	// rcode makes the upstream answer a name with this rcode and no
	// record, as for a refused or failed query.
	rcode map[string]int
}

func newZoneWorld(records ...string) *zoneWorld {
	w := &zoneWorld{
		cname: map[string]worldLink{},
		dname: map[string]worldLink{},
		rrs:   map[string][]dns.RR{},
		fail:  map[string]bool{},
		rcode: map[string]int{},
	}
	for _, s := range records {
		w.add(s)
	}
	return w
}

func (w *zoneWorld) add(s string) {
	r := worldRR(s)
	k := canonName(r.Header().Name)
	switch v := r.(type) {
	case *dns.CNAME:
		w.cname[k] = worldLink{canonName(v.Target), v.Hdr.Ttl}
	case *dns.DNAME:
		w.dname[k] = worldLink{canonName(v.Target), v.Hdr.Ttl}
	default:
		w.rrs[k] = append(w.rrs[k], r)
	}
}

// exists reports whether n has data or a name below it (NODATA, not
// NXDOMAIN).
func (w *zoneWorld) exists(n string) bool {
	if len(w.rrs[n]) > 0 {
		return true
	}
	if _, ok := w.cname[n]; ok {
		return true
	}
	if _, ok := w.dname[n]; ok {
		return true
	}
	below := func(k string) bool { return strings.HasSuffix(k, "."+n) }
	for k := range w.rrs {
		if below(k) {
			return true
		}
	}
	for k := range w.cname {
		if below(k) {
			return true
		}
	}
	return false
}

// step returns the next name of the chain at cur and the records that a
// resolver adds for the link.
func (w *zoneWorld) step(cur string) (string, uint32, []dns.RR, bool) {
	for o, l := range w.dname {
		if strings.HasSuffix(cur, "."+o) {
			next := strings.TrimSuffix(cur, o) + l.target
			return next, l.ttl, []dns.RR{
				&dns.DNAME{Hdr: dns.RR_Header{Name: o, Rrtype: dns.TypeDNAME, Class: dns.ClassINET, Ttl: l.ttl}, Target: l.target},
				&dns.CNAME{Hdr: dns.RR_Header{Name: cur, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: l.ttl}, Target: next},
			}, true
		}
	}
	if l, ok := w.cname[cur]; ok {
		return l.target, l.ttl, []dns.RR{
			&dns.CNAME{Hdr: dns.RR_Header{Name: cur, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: l.ttl}, Target: l.target},
		}, true
	}
	return "", 0, nil, false
}

func (w *zoneWorld) finals(cur string, qtype uint16) []dns.RR {
	var out []dns.RR
	for _, r := range w.rrs[cur] {
		if r.Header().Rrtype == qtype {
			out = append(out, dns.Copy(r))
		}
	}
	return out
}

func zoneOf(n string) string {
	if isUnder(n, worldApex) {
		return worldApex
	}
	l := dns.SplitDomainName(n)
	if len(l) < 2 {
		return "test."
	}
	return strings.Join(l[len(l)-2:], ".") + "."
}

func soaOf(n string) dns.RR {
	z := zoneOf(n)
	return worldRR(fmt.Sprintf("%s 900 IN SOA ns.%s host.%s 1 7200 3600 1209600 600", z, z, z))
}

// chainRef is what a resolver that follows the chain gets.
type chainRef struct {
	rcode   int
	end     string
	finals  []dns.RR
	links   int
	linkTTL uint32
	err     error
}

func (w *zoneWorld) resolve(name string, qtype uint16) chainRef {
	r := chainRef{linkTTL: math.MaxUint32}
	cur := canonName(name)
	seen := map[string]bool{cur: true}
	for {
		if _, ok := w.rcode[cur]; ok || w.fail[cur] {
			r.err = errWorldFail
			return r
		}
		next, ttl, _, ok := w.step(cur)
		if !ok {
			break
		}
		r.links++
		r.linkTTL = min(r.linkTTL, ttl)
		if seen[next] {
			r.err = errWorldLoop
			return r
		}
		seen[next] = true
		cur = next
	}
	r.end = cur
	r.finals = w.finals(cur, qtype)
	if len(r.finals) == 0 && !w.exists(cur) {
		r.rcode = dns.RcodeNameError
	}
	return r
}

// worldUpstream is the next plugin: a recursive resolver over the world.
// partial is the chance that it stops a chain early (as some upstreams
// do), and decorate adds DNSSEC records, glue, NS records, stray records,
// and EDNS options.
type worldUpstream struct {
	w        *zoneWorld
	rnd      *rand.Rand
	partial  float64
	decorate bool
	truncate bool
	// cutAt, when set, is the link after which every chain stops.
	cutAt int

	mu    sync.Mutex
	qs    []dns.Question
	wires [][]byte
}

func (*worldUpstream) Name() string { return "worldupstream" }

func (u *worldUpstream) ServeDNS(_ context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.qs = append(u.qs, r.Question[0])
	m := u.build(r)
	if m == nil {
		u.wires = append(u.wires, nil)
		return dns.RcodeServerFailure, errWorldUpstream
	}
	wire, err := m.Pack()
	if err != nil {
		panic(fmt.Sprintf("upstream reply does not pack: %v\n%v", err, m))
	}
	u.wires = append(u.wires, wire)
	if err := w.WriteMsg(m); err != nil {
		return dns.RcodeServerFailure, err
	}
	return dns.RcodeSuccess, nil
}

func (u *worldUpstream) reset() ([]dns.Question, [][]byte) {
	u.mu.Lock()
	defer u.mu.Unlock()
	qs, ws := u.qs, u.wires
	u.qs, u.wires = nil, nil
	return qs, ws
}

func (u *worldUpstream) build(r *dns.Msg) *dns.Msg {
	q := r.Question[0]
	m := new(dns.Msg)
	m.SetReply(r)
	m.RecursionAvailable = true
	m.Compress = u.rnd.IntN(2) == 0
	cur := canonName(q.Name)
	cut := -1
	if u.rnd.Float64() < u.partial {
		cut = 1 + u.rnd.IntN(3)
	}
	if u.cutAt > 0 {
		cut = u.cutAt
	}
	seen := map[string]bool{cur: true}
	for links := 0; ; {
		if rc, ok := u.w.rcode[cur]; ok {
			f := new(dns.Msg)
			f.SetRcode(r, rc)
			return f
		}
		if u.w.fail[cur] {
			if u.rnd.IntN(2) == 0 {
				return nil
			}
			f := new(dns.Msg)
			f.SetRcode(r, dns.RcodeServerFailure)
			return f
		}
		next, _, emitted, ok := u.w.step(cur)
		if !ok {
			break
		}
		m.Answer = append(m.Answer, emitted...)
		links++
		if seen[next] || links == cut {
			// A loop as the chain records, or a chain that stops early.
			return u.finish(r, m, cur)
		}
		seen[next] = true
		cur = next
	}
	finals := u.w.finals(cur, q.Qtype)
	m.Answer = append(m.Answer, finals...)
	if len(finals) == 0 {
		if !u.w.exists(cur) {
			m.Rcode = dns.RcodeNameError
		}
		m.Ns = append(m.Ns, soaOf(cur))
	}
	return u.finish(r, m, cur)
}

func (u *worldUpstream) finish(r, m *dns.Msg, end string) *dns.Msg {
	q := r.Question[0]
	for _, rr := range m.Answer {
		if canonName(rr.Header().Name) == canonName(q.Name) && u.rnd.IntN(2) == 0 {
			rr.Header().Name = q.Name // the spelling of the client
		}
	}
	if u.decorate {
		u.decorations(m, end)
	}
	if o := r.IsEdns0(); o != nil {
		opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
		opt.SetUDPSize(1232)
		opt.SetDo(o.Do())
		if u.decorate {
			opt.Option = append(opt.Option,
				&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "0123456789abcdef0123456789abcdef"},
				&dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, SourceScope: 24, Address: net.ParseIP("192.0.2.0").To4()},
				&dns.EDNS0_LOCAL{Code: 65001, Data: []byte{1, 2, 3}},
				&dns.EDNS0_PADDING{Padding: make([]byte, u.rnd.IntN(16))},
			)
		}
		m.Extra = append(m.Extra, opt)
	}
	if u.truncate && u.rnd.IntN(20) == 0 {
		m.Truncated = true
	}
	return m
}

func (u *worldUpstream) decorations(m *dns.Msg, end string) {
	m.AuthenticatedData = u.rnd.IntN(2) == 0
	if u.rnd.IntN(3) == 0 {
		var sigs []dns.RR
		for _, rr := range m.Answer {
			h := rr.Header()
			sigs = append(sigs, &dns.RRSIG{
				Hdr:         dns.RR_Header{Name: h.Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: h.Ttl},
				TypeCovered: h.Rrtype, Algorithm: dns.ECDSAP256SHA256, Labels: uint8(dns.CountLabel(h.Name)), //nolint:gosec // a name has at most 127 labels
				OrigTtl: h.Ttl, Expiration: 1900000000, Inception: 1700000000, KeyTag: 12345,
				SignerName: zoneOf(h.Name), Signature: base64.StdEncoding.EncodeToString(make([]byte, 64)),
			})
		}
		m.Answer = append(m.Answer, sigs...)
	}
	if u.rnd.IntN(4) == 0 && len(m.Answer) > 0 {
		m.Answer = append(m.Answer, worldRR("stray.cdn.test. 60 IN A 192.0.2.99"))
	}
	if u.rnd.IntN(3) == 0 {
		if m.Rcode == dns.RcodeSuccess && len(m.Answer) > 0 {
			m.Ns = append(m.Ns, worldRR("cdn.test. 300 IN NS ns1.cdn.test."))
		} else {
			m.Ns = append(m.Ns, &dns.NSEC{
				Hdr:        dns.RR_Header{Name: end, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
				NextDomain: "zz." + zoneOf(end), TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC},
			})
		}
		m.Extra = append(m.Extra, worldRR("ns1.cdn.test. 300 IN A 192.0.2.53"), worldRR("ns1.cdn.test. 300 IN AAAA 2001:db8::53"))
	}
}

// logEvent is an ack of the fake daemon or a reply to the client, in
// the order they happened.
type logEvent struct {
	obs       *ipc.Observation
	protected bool
	write     *dns.Msg
}

type eventLog struct {
	mu     sync.Mutex
	events []logEvent
}

func (l *eventLog) add(e logEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, e)
}

func (l *eventLog) take() []logEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.events
	l.events = nil
	return e
}

// apexDaemon acks every report. The ack is protected iff the qname is at
// or below apex (F9 for a policy "*.p.test").
type apexDaemon struct {
	log  *eventLog
	apex string
}

func (d *apexDaemon) Report(_ context.Context, o ipc.Observation) (ipc.Ack, error) {
	p := isUnder(o.QName, d.apex)
	d.log.add(logEvent{obs: &o, protected: p})
	return ipc.Ack{Protected: p}, nil
}

type noProbes struct{}

func (noProbes) ReportProbe(context.Context, string) error { return nil }

// clientWriter is the client side: it packs each reply as a server does.
type clientWriter struct {
	test.ResponseWriter
	log   *eventLog
	wires [][]byte
}

func (w *clientWriter) WriteMsg(m *dns.Msg) error {
	wire, err := m.Pack()
	if err != nil {
		return err
	}
	out := new(dns.Msg)
	if err := out.Unpack(wire); err != nil {
		return err
	}
	w.wires = append(w.wires, wire)
	w.log.add(logEvent{write: out})
	return nil
}

type worldEnv struct {
	w   *zoneWorld
	up  *worldUpstream
	log *eventLog
	h   *handler
}

func newWorldEnv(w *zoneWorld, rnd *rand.Rand, key *tagKey, rep reporter) *worldEnv {
	log := new(eventLog)
	up := &worldUpstream{w: w, rnd: rnd}
	if rep == nil {
		rep = &apexDaemon{log: log, apex: worldApex}
	}
	return &worldEnv{w: w, up: up, log: log, h: &handler{next: up, reporter: rep, probes: noProbes{}, timeout: time.Second, key: key}}
}

// clientTurn is one client query and what happened.
type clientTurn struct {
	qname   string
	qtype   uint16
	reply   *dns.Msg // nil when the handler wrote nothing
	wire    []byte
	writes  int
	rcode   int // what the client sees
	err     error
	events  []logEvent
	upQs    []dns.Question
	upWires [][]byte
	reqID   uint16
}

func (e *worldEnv) ask(qname string, qtype uint16, edns bool) clientTurn {
	e.log.take()
	e.up.reset()
	req := new(dns.Msg)
	req.SetQuestion(qname, qtype)
	if edns {
		req.SetEdns0(4096, true)
	}
	w := &clientWriter{log: e.log}
	rc, err := e.h.ServeDNS(context.Background(), w, req)
	t := clientTurn{qname: qname, qtype: qtype, rcode: rc, err: err, writes: len(w.wires), reqID: req.Id}
	t.events = e.log.take()
	t.upQs, t.upWires = e.up.reset()
	for _, ev := range t.events {
		if ev.write != nil {
			t.reply = ev.write
		}
	}
	if len(w.wires) > 0 {
		t.wire = w.wires[len(w.wires)-1]
		t.rcode = t.reply.Rcode
	}
	return t
}

// rdataNames returns the owner and every name-valued RDATA field of rr.
func rdataNames(rr dns.RR) []string {
	names := []string{rr.Header().Name}
	var walk func(v reflect.Value)
	walk = func(v reflect.Value) {
		t := v.Type()
		for i := range t.NumField() {
			f := t.Field(i)
			if f.Type == reflect.TypeFor[dns.RR_Header]() {
				continue
			}
			if f.Type.Kind() == reflect.Struct {
				walk(v.Field(i))
				continue
			}
			if !strings.Contains(f.Tag.Get("dns"), "domain-name") {
				continue
			}
			switch f.Type.Kind() { //nolint:exhaustive // only string and []string carry names
			case reflect.String:
				names = append(names, v.Field(i).String())
			case reflect.Slice:
				for j := range v.Field(i).Len() {
					names = append(names, v.Field(i).Index(j).String())
				}
			}
		}
	}
	walk(reflect.ValueOf(rr).Elem())
	return names
}

// knownGapTypes are the types whose data names another host, and whose
// names stay in a flattened reply (see flatten). The client looks such a
// name up as a name of its own. A type that is not here and names a host
// must not reach a protected client: TestKnownGapListsEveryNameType keeps
// the list complete for the record types that miekg/dns knows.
var knownGapTypes = map[uint16]bool{
	dns.TypeSRV: true, dns.TypeMX: true, dns.TypeNS: true, dns.TypeNAPTR: true,
	// Types of the same kind, rare in replies to a host name. AMTRELAY
	// and IPSECKEY can hold a gateway name in a field that miekg/dns does
	// not tag as a name, so neither this list nor rdataNames sees it.
	dns.TypeAFSDB: true, dns.TypeHIP: true, dns.TypeKX: true,
	dns.TypeLP: true, dns.TypeMB: true, dns.TypeMD: true, dns.TypeMF: true, dns.TypeMG: true,
	dns.TypeMINFO: true, dns.TypeMR: true, dns.TypeNSAPPTR: true, dns.TypeNXT: true,
	dns.TypePTR: true, dns.TypePX: true, dns.TypeRP: true, dns.TypeRT: true, dns.TypeSIG: true,
	dns.TypeSOA: true, dns.TypeTALINK: true, dns.TypeTKEY: true, dns.TypeTSIG: true,
}

// namesOutside returns each name in m outside the subtree of qname (F1).
// The authority section describes the zone of the answer: the client
// looks up none of its SOA, NS, and DNSSEC names, so they do not count.
// requireNoAlias is stricter for a flattened reply.
func namesOutside(qname string, m *dns.Msg) []string {
	var out []string
	for si, sec := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range sec {
			t := rr.Header().Rrtype
			if t == dns.TypeOPT || si == 1 && zoneTypes[t] {
				continue
			}
			out = append(out, namesOutsideOf(qname, rr)...)
		}
	}
	return out
}

// zoneTypes are the types of the authority section of a reply.
var zoneTypes = map[uint16]bool{
	dns.TypeSOA: true, dns.TypeNS: true, dns.TypeRRSIG: true, dns.TypeNSEC: true, dns.TypeNSEC3: true,
}

// unfollowedTypes have names in their data that a client never looks up:
// the signer of a signature, and the next name of a denial.
var unfollowedTypes = map[uint16]bool{dns.TypeRRSIG: true, dns.TypeNSEC: true}

func namesOutsideOf(qname string, rr dns.RR) []string {
	var out []string
	t := rr.Header().Rrtype
	for i, n := range rdataNames(rr) {
		isTarget := i > 0 && (t == dns.TypeHTTPS || t == dns.TypeSVCB)
		if (isTarget && n == ".") || isUnder(n, qname) || i > 0 && (knownGapTypes[t] || unfollowedTypes[t]) {
			continue
		}
		out = append(out, fmt.Sprintf("%s: %s", dns.TypeToString[t], n))
	}
	return out
}

// readableAddrs returns every address a client can read in m: A, AAAA, and
// SVCB or HTTPS hints, in every section.
func readableAddrs(m *dns.Msg) []netip.Addr {
	var out []netip.Addr
	for _, sec := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range sec {
			out = append(out, readableAddrsOf(rr)...)
		}
	}
	slices.SortFunc(out, netip.Addr.Compare)
	return slices.Compact(out)
}

func readableAddrsOf(rr dns.RR) []netip.Addr {
	var ips []net.IP
	switch v := rr.(type) {
	case *dns.A:
		ips = []net.IP{v.A}
	case *dns.AAAA:
		ips = []net.IP{v.AAAA}
	case *dns.SVCB:
		ips = hintIPs(v)
	case *dns.HTTPS:
		ips = hintIPs(&v.SVCB)
	}
	var out []netip.Addr
	for _, b := range ips {
		if a, ok := netip.AddrFromSlice(b); ok {
			out = append(out, a.Unmap())
		}
	}
	return out
}

func hintIPs(s *dns.SVCB) []net.IP {
	var out []net.IP
	for _, kv := range s.Value {
		switch v := kv.(type) {
		case *dns.SVCBIPv4Hint:
			out = append(out, v.Hint...)
		case *dns.SVCBIPv6Hint:
			out = append(out, v.Hint...)
		}
	}
	return out
}

// ackedBeforeReply checks F2: the acks before the reply, for origin, hold
// every address of the reply together. It returns a problem or "".
func ackedBeforeReply(t clientTurn, origin string) string {
	if t.reply == nil {
		return ""
	}
	addrs := readableAddrs(t.reply)
	if len(addrs) == 0 {
		return ""
	}
	var acked []netip.Addr
	for _, ev := range t.events {
		if ev.write != nil {
			break
		}
		if ev.obs != nil && canonName(ev.obs.QName) == canonName(origin) {
			acked = append(acked, ev.obs.Addrs...)
		}
	}
	if !slices.ContainsFunc(addrs, func(a netip.Addr) bool { return !slices.Contains(acked, a) }) {
		return ""
	}
	return fmt.Sprintf("addresses %v of the reply to %s are not in the acks under %s before the reply (events %s)", addrs, t.qname, origin, eventsString(t.events))
}

func eventsString(evs []logEvent) string {
	var b strings.Builder
	for _, ev := range evs {
		switch {
		case ev.write != nil:
			b.WriteString("[write] ")
		case ev.obs != nil:
			fmt.Fprintf(&b, "[ack %s %v p=%v] ", ev.obs.QName, ev.obs.Addrs, ev.protected)
		}
	}
	return b.String()
}

// svcParams is the SvcParams of s in presentation form.
func svcParams(s *dns.SVCB) string {
	var p []string
	for _, kv := range s.Value {
		p = append(p, kv.Key().String()+"="+kv.String())
	}
	return strings.Join(p, " ")
}

func svcbOf(rr dns.RR) *dns.SVCB {
	switch v := rr.(type) {
	case *dns.SVCB:
		return v
	case *dns.HTTPS:
		return &v.SVCB
	}
	return nil
}

// randomLetterCase changes the case of the letters of n at random.
func randomLetterCase(rnd *rand.Rand, n string) string {
	b := []byte(n)
	for i, c := range b {
		if 'a' <= c && c <= 'z' && rnd.IntN(2) == 0 {
			b[i] = c - 'a' + 'A'
		}
	}
	return string(b)
}

// Names of the random worlds. The protected qnames are below worldApex.
var (
	protectedQNames = []string{"www.p.test.", "api.p.test.", "p.test.", "x.y.p.test.", "y.p.test.", "nope.p.test."}
	dataNames       = []string{
		"www.p.test.", "api.p.test.", "p.test.", "x.y.p.test.", "a.p.test.", "z.www.p.test.",
		"e0.cdn.test.", "e1.cdn.test.", "e2.cdn.test.", "e3.cdn.test.", "e4.cdn.test.", "e5.cdn.test.",
		"f0.other.test.", "f1.other.test.", "h.new.test.", "g.new.test.",
	}
	targetNames         = append(slices.Clone(dataNames), "h.old.test.", "g.old.test.", "gone.cdn.test.")
	unprotectedQNames   = []string{"e0.cdn.test.", "e1.cdn.test.", "e2.cdn.test.", "e3.cdn.test.", "f0.other.test.", "h.old.test.", "gone.cdn.test.", "h.new.test."}
	clientQTypes        = []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeHTTPS}
	errUnexpectedRecord = errors.New("oracle: record without a source in the world")
)

// randomWorld builds zones with CNAME chains, a DNAME, HTTPS records in
// ServiceMode and AliasMode with hints, NODATA, NXDOMAIN, loops, and
// names whose upstream fails.
func randomWorld(rnd *rand.Rand) *zoneWorld {
	w := newZoneWorld(fmt.Sprintf("old.test. %d IN DNAME new.test.", randomTTL(rnd)))
	for _, n := range dataNames {
		switch r := rnd.Float64(); {
		case r < 0.3:
			w.add(fmt.Sprintf("%s %d IN CNAME %s", n, randomTTL(rnd), randomTarget(rnd, n)))
		case r < 0.38:
			// no data: NXDOMAIN unless a name below exists
		default:
			randomNode(rnd, w, n)
		}
	}
	if rnd.Float64() < 0.15 {
		w.fail[targetNames[rnd.IntN(len(targetNames))]] = true
	}
	return w
}

func randomTarget(rnd *rand.Rand, not string) string {
	for {
		if t := targetNames[rnd.IntN(len(targetNames))]; t != not {
			return t
		}
	}
}

func randomAddr4(rnd *rand.Rand) string { return fmt.Sprintf("192.0.2.%d", 1+rnd.IntN(250)) }
func randomAddr6(rnd *rand.Rand) string { return fmt.Sprintf("2001:db8::%x", 1+rnd.IntN(0xfff)) }

// randomNode adds A, AAAA, and HTTPS records for n. One RRset has one
// TTL.
func randomNode(rnd *rand.Rand, w *zoneWorld, n string) {
	for _, set := range []struct {
		typ  string
		p    float64
		addr func(*rand.Rand) string
	}{{"A", 0.6, randomAddr4}, {"AAAA", 0.5, randomAddr6}} {
		if rnd.Float64() >= set.p {
			continue
		}
		ttl := randomTTL(rnd)
		for range 1 + rnd.IntN(2) {
			w.add(fmt.Sprintf("%s %d IN %s %s", n, ttl, set.typ, set.addr(rnd)))
		}
	}
	if rnd.Float64() >= 0.6 {
		return
	}
	ttl := randomTTL(rnd)
	if rnd.Float64() < 0.25 {
		w.add(fmt.Sprintf("%s %d IN HTTPS 0 %s", n, ttl, randomTarget(rnd, n)))
		return
	}
	for prio := range 1 + rnd.IntN(2) {
		t := []string{".", n, randomTarget(rnd, n)}[rnd.IntN(3)]
		w.add(fmt.Sprintf("%s %d IN HTTPS %d %s%s", n, ttl, prio+1, t, randomParams(rnd)))
	}
}

func randomTTL(rnd *rand.Rand) uint32 { return 10 + rnd.Uint32N(3600) }

func randomParams(rnd *rand.Rand) string {
	var p string
	if rnd.IntN(2) == 0 {
		p += ` alpn="h2,h3"`
	}
	if rnd.IntN(3) == 0 {
		p += " port=8443"
	}
	if rnd.IntN(2) == 0 {
		p += " ipv4hint=" + randomAddr4(rnd)
	}
	if rnd.IntN(2) == 0 {
		p += " ipv6hint=" + randomAddr6(rnd)
	}
	return p
}
