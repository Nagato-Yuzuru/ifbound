//go:build e2e

package e2e

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/Nagato-Yuzuru/ifbound/internal/macresolver"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
	"github.com/Nagato-Yuzuru/ifbound/internal/syslookup"
	"github.com/Nagato-Yuzuru/ifbound/internal/testenv"
)

// These tests write files in /etc/resolver and use the system resolver.
// Each test uses a new domain below .test (RFC 6761), so a cached answer
// from an earlier run cannot pass as a result.

func requireResolverE2E(t *testing.T) {
	t.Helper()
	testenv.RequireDisposableHost(t)
	testenv.RequireOS(t, "darwin")
	testenv.RequireRoot(t)
	testenv.RequireCommand(t, "scutil")
}

// TestResolverEntryRoutesLookups checks that an entry that Write adds
// routes the lookups of new names below its domain to its server within
// a few seconds. The slowest measured application of a new file took
// 1.55 s.
func TestResolverEntryRoutesLookups(t *testing.T) {
	requireResolverE2E(t)
	// 198.18.0.0/15 is reserved for benchmark tests (RFC 2544): no real
	// resolver gives this answer.
	answer := netip.MustParseAddr("198.18.0.53")
	srv := startDNS(t, answer)
	r := macresolver.New(macresolver.Dir, macresolver.Scutil{})
	apex := writeEntry(t, r, srv.addr)

	waitFor(t, 5*time.Second, func() (bool, string) {
		// A new name each time, so no cached negative answer can count.
		name := "ifbound-probe-" + nonce(t) + "." + apex.String()
		addrs, err := syslookup.Resolver{}.Resolve(t.Context(), name)
		return err == nil && slices.Equal(addrs, []netip.Addr{answer}) && srv.saw(name),
			fmt.Sprintf("resolve %s = %v, %v", name, addrs, err)
	})
}

// TestResolverReportsMoreSpecificFile checks that Read reports a file
// that ifbound does not manage below an ifbound entry. On macOS the more
// specific file takes those names from the ifbound entry.
func TestResolverReportsMoreSpecificFile(t *testing.T) {
	requireResolverE2E(t)
	r := macresolver.New(macresolver.Dir, macresolver.Scutil{})
	apex := writeEntry(t, r, netip.MustParseAddrPort("127.0.0.1:10053"))

	sub := "www." + apex.String()
	path := filepath.Join(macresolver.Dir, sub)
	if err := os.WriteFile(path, []byte("nameserver 127.0.0.1\nport 10054\n"), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	t.Cleanup(func() {
		if err := os.Remove(path); err != nil {
			t.Errorf("remove %s: %v", path, err)
		}
	})

	waitFor(t, 5*time.Second, func() (bool, string) {
		st, err := r.Read(t.Context())
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		var texts []string
		for _, p := range st.Problems {
			texts = append(texts, p.Text)
		}
		found := slices.ContainsFunc(st.Shadowed, func(d policy.Domain) bool { return d.String() == sub })
		return found, "problems " + strings.Join(texts, "; ")
	})
}

// writeEntry writes an ifbound entry for a new domain and registers its
// removal.
func writeEntry(t *testing.T, r *macresolver.Resolver, server netip.AddrPort) policy.Domain {
	t.Helper()
	apex, err := policy.ParseDomain("ifbound-e2e-" + nonce(t) + ".test")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Write(t.Context(), reconcile.ResolverEntry{Domain: apex, Server: server}); err != nil {
		t.Fatalf("Write %s: %v", apex, err)
	}
	t.Cleanup(func() {
		// t.Context is already canceled when cleanups run; Remove does not use it.
		if err := r.Remove(t.Context(), apex); err != nil {
			t.Errorf("Remove %s: %v", apex, err)
		}
	})
	return apex
}

// waitFor polls cond until it holds or the timeout passes.
func waitFor(t *testing.T, timeout time.Duration, cond func() (bool, string)) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		ok, state := cond()
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("condition not met after %v; last state: %s", timeout, state)
		}
		time.Sleep(100 * time.Millisecond) // polls system state; no event exists to wait on
	}
}

func nonce(t *testing.T) string {
	t.Helper()
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// testDNS is a DNS server on loopback that answers every A query with one
// address and records the query names.
type testDNS struct {
	addr  netip.AddrPort
	mu    sync.Mutex
	names []string
}

func startDNS(t *testing.T, answer netip.Addr) *testDNS {
	t.Helper()
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &testDNS{addr: pc.LocalAddr().(*net.UDPAddr).AddrPort()}
	started := make(chan struct{})
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(q)
		for _, question := range q.Question {
			s.mu.Lock()
			s.names = append(s.names, strings.TrimSuffix(strings.ToLower(question.Name), "."))
			s.mu.Unlock()
			if question.Qtype == dns.TypeA {
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1},
					A:   answer.AsSlice(),
				})
			}
		}
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
		if err := srv.Shutdown(); err != nil {
			t.Errorf("stop DNS server: %v", err)
		}
		if err := <-done; err != nil {
			t.Errorf("DNS server: %v", err)
		}
	})
	return s
}

func (s *testDNS) saw(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Contains(s.names, name)
}
