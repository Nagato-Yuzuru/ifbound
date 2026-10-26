//go:build e2e && darwin

package e2e

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	_ "github.com/coredns/coredns/plugin/bind"    // the listen address of the plugin stack
	_ "github.com/coredns/coredns/plugin/forward" // the upstream of the plugin stack
	"github.com/miekg/dns"

	"github.com/Nagato-Yuzuru/ifbound/internal/dnsplugin"
	"github.com/Nagato-Yuzuru/ifbound/internal/ipc"
	"github.com/Nagato-Yuzuru/ifbound/internal/macresolver"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/syslookup"
)

// registerPlugin adds the ifbound directive once: CoreDNS accepts a
// plugin name once per process.
var registerPlugin = sync.OnceValue(dnsplugin.Register)

// leaked is the answer of the alias resolver. The plugin stack never gives
// it, so a lookup that returns it went around ifbound-dns.
var leaked = netip.MustParseAddr("198.18.0.66")

// flattenStack is the plugin stack of ifbound-dns on loopback: CoreDNS with
// the ifbound plugin before forward, a fake upstream, and a fake ifboundd
// that protects the names below apex. The aliases in the upstream answers
// are below out, whose resolver entry points to a server that records
// each query and answers leaked.
type flattenStack struct {
	apex, out policy.Domain
	plugin    netip.AddrPort
	upstream  *zoneDNS
	alias     *testDNS

	mu      sync.Mutex
	reports []ipc.Observation
}

func startFlattenStack(t *testing.T) *flattenStack {
	t.Helper()
	if err := registerPlugin(); err != nil {
		t.Fatalf("Register: %v", err)
	}
	s := &flattenStack{upstream: startZoneDNS(t), alias: startDNS(t, leaked)}

	dir, err := os.MkdirTemp("", "ifbe2e")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s")
	srv, err := ipc.Listen(ipc.ServerConfig{Path: sock, Handler: s, AllowedUIDs: []uint32{0}})
	if err != nil {
		t.Fatalf("ipc.Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-served; err != nil {
			t.Errorf("ipc Serve: %v", err)
		}
	})

	dnsserver.Quiet = true
	inst, err := caddy.Start(caddy.CaddyfileInput{
		Contents: []byte(".:0 {\n bind 127.0.0.1\n ifbound " + sock + "\n forward . " +
			s.upstream.addr.String() + "\n}\n"),
		Filepath:       "Corefile",
		ServerTypeName: "dns",
	})
	if err != nil {
		t.Fatalf("start CoreDNS: %v", err)
	}
	t.Cleanup(func() { _ = inst.Stop() })
	s.plugin = inst.Servers()[0].LocalAddr().(*net.UDPAddr).AddrPort()

	r := macresolver.New(macresolver.Dir, macresolver.Scutil{})
	s.apex = writeEntry(t, r, s.plugin)
	s.out = writeEntry(t, r, s.alias.addr)
	s.waitRouted(t)
	return s
}

// ready is the upstream answer for the names that waitRouted asks. It
// differs from leaked, so a lookup shows which server answered.
var ready = netip.MustParseAddr("198.18.0.77")

// waitRouted waits until macOS applies both resolver entries. A test that
// asks before then gets an error from the default resolver, not from the
// stack under test. Each attempt uses a new name, because mDNSResponder
// keeps negative answers.
func (s *flattenStack) waitRouted(t *testing.T) {
	t.Helper()
	routed := func(domain policy.Domain, want netip.Addr) func() (bool, string) {
		return func() (bool, string) {
			name := "ifbound-ready-" + nonce(t) + "." + domain.String() + "."
			s.upstream.set(name + " 30 IN A " + ready.String())
			addrs, err := syslookup.Resolver{}.Resolve(t.Context(), name)
			return err == nil && slices.Equal(addrs, []netip.Addr{want}), fmt.Sprintf("%s: %v %v", name, addrs, err)
		}
	}
	waitFor(t, 5*time.Second, routed(s.apex, ready))
	waitFor(t, 5*time.Second, routed(s.out, leaked))
	s.upstream.set()
	// The wait itself queried the alias resolver. Only the queries of the
	// test may count.
	s.alias.mu.Lock()
	s.alias.names = nil
	s.alias.mu.Unlock()
	s.mu.Lock()
	s.reports = nil
	s.mu.Unlock()
}

// Observe implements ipc.Handler for the fake ifboundd.
func (s *flattenStack) Observe(_ context.Context, o ipc.Observation) (ipc.Ack, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reports = append(s.reports, o)
	return ipc.Ack{Protected: dns.IsSubDomain(s.apex.String()+".", dns.CanonicalName(o.QName))}, nil
}

func (s *flattenStack) reportedUnder(qname string, a netip.Addr) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.ContainsFunc(s.reports, func(o ipc.Observation) bool {
		return strings.EqualFold(o.QName, qname) && slices.Contains(o.Addrs, a)
	})
}

// in returns label below apex, and outside returns label below out.
func (s *flattenStack) in(label string) string      { return label + "." + s.apex.String() + "." }
func (s *flattenStack) outside(label string) string { return label + "." + s.out.String() + "." }

// requireNoAliasQuery fails when a query for a name reached the alias
// resolver. The DDR probe of mDNSResponder (RFC 9462) asks each resolver
// that it uses for _dns.resolver.arpa. That probe names no alias, so it
// does not count.
func (s *flattenStack) requireNoAliasQuery(t *testing.T) {
	t.Helper()
	s.alias.mu.Lock()
	defer s.alias.mu.Unlock()
	var names []string
	for _, n := range s.alias.names {
		if !dns.IsSubDomain("resolver.arpa.", dns.Fqdn(n)) {
			names = append(names, n)
		}
	}
	if len(names) > 0 {
		t.Errorf("the alias resolver got queries for %v", names)
	}
}

func resolve(t *testing.T, name string) []netip.Addr {
	t.Helper()
	addrs, err := syslookup.Resolver{}.Resolve(t.Context(), name)
	if err != nil {
		t.Fatalf("resolve %s: %v", name, err)
	}
	return addrs
}

// queryRecord asks the system resolver for name and qtype as
// DNSServiceQueryRecord does, the API under URLSession and NWConnection
// for HTTPS records. dns-sd runs until it is killed, so the context ends
// it after the answer has had time to come.
func queryRecord(t *testing.T, name string, qtype uint16) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "/usr/bin/dns-sd", "-Q", name, dns.TypeToString[qtype]).Output() // killed at the deadline by design
	return string(out)
}

// A CNAME chain to a name outside the protected domain reaches the client
// as addresses of the protected name. When the address expires and the
// CNAME would still be valid, the next lookup still goes to ifbound-dns.
func TestFlattenedCNAMEChainNeverReachesTheAliasResolver(t *testing.T) {
	requireResolverE2E(t)
	s := startFlattenStack(t)
	want := netip.MustParseAddr("198.18.0.10")
	www := s.in("www")
	s.upstream.set(
		www+" 300 IN CNAME "+s.outside("a"),
		s.outside("a")+" 300 IN CNAME "+s.outside("b"),
		s.outside("b")+" 1 IN A "+want.String(),
	)
	for range 2 {
		if got := resolve(t, www); !slices.Equal(got, []netip.Addr{want}) {
			t.Fatalf("resolve %s = %v, want %v", www, got, want)
		}
		// Let the A record expire. Without flattening, the client keeps
		// the CNAME records for 300 s and asks the alias resolver next.
		time.Sleep(2 * time.Second) // waits for a TTL in mDNSResponder; no event exists
	}
	s.requireNoAliasQuery(t)
	if !s.reportedUnder(www, want) {
		t.Errorf("no report of %v under %s", want, www)
	}
}

// A chain to a name outside the protected domain that ends in NODATA,
// with a SOA and without, gives no address. The client asks again later,
// and its query still goes to ifbound-dns.
func TestFlattenedNegativeChainNeverReachesTheAliasResolver(t *testing.T) {
	requireResolverE2E(t)
	s := startFlattenStack(t)
	withSOA, withoutSOA := s.in("soa"), s.in("nosoa")
	s.upstream.set(
		withSOA+" 300 IN CNAME "+s.outside("empty"),
		withoutSOA+" 300 IN CNAME "+s.outside("bare"),
		s.outside("empty")+" 300 IN TXT \"no address\"",
		s.outside("bare")+" 300 IN TXT \"no address\"",
	)
	s.upstream.withoutSOA(s.outside("bare"))
	for range 2 {
		for _, name := range []string{withSOA, withoutSOA} {
			if addrs, err := (syslookup.Resolver{}).Resolve(t.Context(), name); err == nil {
				t.Errorf("resolve %s = %v, want no address", name, addrs)
			}
		}
		time.Sleep(2 * time.Second) // waits for the negative TTL in mDNSResponder; no event exists
	}
	s.requireNoAliasQuery(t)
}

// HTTPS records with a TargetName of "." at the end of a chain, a
// ServiceMode target, and an AliasMode target outside the protected
// domain. The client then looks up the TargetName, which a flattened reply
// names below the protected name, and the lookup goes to ifbound-dns.
func TestFlattenedHTTPSTargetsNeverReachTheAliasResolver(t *testing.T) {
	requireResolverE2E(t)
	s := startFlattenStack(t)
	dot, service, aliasMode := s.in("dot"), s.in("svc"), s.in("alias")
	dotAddr := netip.MustParseAddr("198.18.0.20")
	svcAddr := netip.MustParseAddr("198.18.0.21")
	poolAddr := netip.MustParseAddr("198.18.0.22")
	s.upstream.set(
		dot+" 300 IN CNAME "+s.outside("edge"),
		s.outside("edge")+" 60 IN HTTPS 1 . alpn=h2",
		s.outside("edge")+" 60 IN A "+dotAddr.String(),
		service+" 300 IN HTTPS 1 "+s.outside("svc")+" alpn=h2",
		s.outside("svc")+" 60 IN A "+svcAddr.String(),
		aliasMode+" 300 IN HTTPS 0 "+s.outside("pool"),
		s.outside("pool")+" 60 IN A "+poolAddr.String(),
	)

	for name, want := range map[string]netip.Addr{dot: dotAddr, service: svcAddr, aliasMode: poolAddr} {
		target := httpsTarget(t, name)
		if target != "." && !dns.IsSubDomain(name, target) {
			t.Errorf("the client got the TargetName %s, outside %s", target, name)
		}
		if target == "." {
			target = name
		}
		if got := resolve(t, target); !slices.Equal(got, []netip.Addr{want}) {
			t.Errorf("resolve %s = %v, want %v", target, got, want)
		}
		if !s.reportedUnder(name, want) {
			t.Errorf("no report of %v under %s", want, name)
		}
	}
	s.requireNoAliasQuery(t)
}

// httpsTarget asks the system resolver for the HTTPS record of name, as
// DNSServiceQueryRecord does, and returns the TargetName that the client
// got. dns-sd prints the rdata in hex: SvcPriority, then TargetName.
func httpsTarget(t *testing.T, name string) string {
	t.Helper()
	out := queryRecord(t, name, dns.TypeHTTPS)
	for line := range strings.Lines(out) {
		_, hex, ok := strings.Cut(line, " bytes: ")
		if !ok || !strings.Contains(strings.ToLower(line), strings.TrimSuffix(name, ".")) {
			continue
		}
		var rdata []byte
		for _, f := range strings.Fields(hex) {
			b, err := strconv.ParseUint(f, 16, 8)
			if err != nil {
				t.Fatalf("rdata %q: %v", hex, err)
			}
			rdata = append(rdata, byte(b))
		}
		target, _, err := dns.UnpackDomainName(rdata, 2)
		if err != nil {
			t.Fatalf("TargetName in %q: %v", hex, err)
		}
		return target
	}
	t.Fatalf("dns-sd -Q %s HTTPS gave no record:\n%s", name, out)
	return ""
}

// zoneDNS is a fake recursive resolver on loopback. It answers each
// question with the records of its name: the CNAME records from the name
// and the records at the end of the chain, of the asked type. Without
// such records, the answer is NODATA with a SOA of the parent of the end,
// except for the names in noSOA.
type zoneDNS struct {
	addr netip.AddrPort

	mu    sync.Mutex
	rrs   []dns.RR
	noSOA map[string]bool
}

// withoutSOA makes the NODATA answers for names come without a SOA.
func (z *zoneDNS) withoutSOA(names ...string) {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.noSOA = map[string]bool{}
	for _, n := range names {
		z.noSOA[dns.CanonicalName(n)] = true
	}
}

func (z *zoneDNS) set(lines ...string) {
	var rrs []dns.RR
	for _, l := range lines {
		r, err := dns.NewRR(l)
		if err != nil {
			panic(err)
		}
		rrs = append(rrs, r)
	}
	z.mu.Lock()
	z.rrs = rrs
	z.mu.Unlock()
}

func (z *zoneDNS) answer(q dns.Question) (answer, ns []dns.RR) {
	z.mu.Lock()
	defer z.mu.Unlock()
	name := q.Name
	final := false
	for range 8 {
		var next string
		for _, r := range z.rrs {
			if !strings.EqualFold(r.Header().Name, name) {
				continue
			}
			if c, ok := r.(*dns.CNAME); ok {
				answer = append(answer, r)
				next = c.Target
			} else if r.Header().Rrtype == q.Qtype {
				answer = append(answer, r)
				final = true
			}
		}
		if next == "" {
			break
		}
		name = next
	}
	if final || z.noSOA[dns.CanonicalName(name)] {
		return answer, nil
	}
	_, parent, _ := strings.Cut(dns.CanonicalName(name), ".")
	soa, err := dns.NewRR(parent + " 30 IN SOA ns." + parent + " host." + parent + " 1 7200 3600 1209600 30")
	if err != nil {
		panic(err)
	}
	return answer, []dns.RR{soa}
}

func startZoneDNS(t *testing.T) *zoneDNS {
	t.Helper()
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	z := &zoneDNS{addr: pc.LocalAddr().(*net.UDPAddr).AddrPort()}
	started := make(chan struct{})
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		m := new(dns.Msg).SetReply(q)
		m.RecursionAvailable = true
		m.Answer, m.Ns = z.answer(q.Question[0])
		_ = w.WriteMsg(m) // a lost reply makes the lookup in the test fail
	}), NotifyStartedFunc: func() { close(started) }}
	done := make(chan error, 1)
	go func() { done <- srv.ActivateAndServe() }()
	select {
	case <-started:
	case err := <-done:
		t.Fatalf("DNS server stopped at start: %v", err)
	}
	t.Cleanup(func() {
		_ = srv.Shutdown() // the test result does not depend on a clean stop
		<-done             //nolint:errcheck // wait for the server goroutine to exit; its error after Shutdown is not under test
	})
	return z
}
