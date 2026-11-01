package dnsconf

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	_ "github.com/coredns/coredns/plugin/bind"
	_ "github.com/coredns/coredns/plugin/cache"
	_ "github.com/coredns/coredns/plugin/errors"
	_ "github.com/coredns/coredns/plugin/forward"
	"github.com/miekg/dns"

	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

const dotName = "dot.test"

// testPKI makes a CA and a server certificate for dotName. It writes the CA
// to a file and returns the file name and the server certificate.
func testPKI(t *testing.T) (caFile string, cert tls.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ifbound test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: dotName},
		DNSNames:     []string{dotName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caFile = filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	if err := os.WriteFile(caFile, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return caFile, tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: key}
}

// dotServer is a DNS-over-TLS server that answers each A query with ans.
type dotServer struct {
	addr netip.AddrPort
	hits atomic.Int64
}

func startDoT(t *testing.T, network, host string, cert tls.Certificate, ans string) *dotServer {
	t.Helper()
	ln, err := new(net.ListenConfig).Listen(t.Context(), network, net.JoinHostPort(host, "0"))
	if err != nil {
		t.Skipf("no %s on this host: %v", network, err)
	}
	s := &dotServer{addr: netip.MustParseAddrPort(ln.Addr().String())}
	srv := &dns.Server{
		Listener: tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}),
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			s.hits.Add(1)
			m := new(dns.Msg).SetReply(r)
			rr, err := dns.NewRR(fmt.Sprintf("%s 60 IN A %s", r.Question[0].Name, ans))
			if err == nil {
				m.Answer = append(m.Answer, rr)
			}
			_ = w.WriteMsg(m) //nolint:errcheck // a failed write shows as a failed query in the test
		}),
	}
	var wg sync.WaitGroup
	wg.Go(func() { _ = srv.ActivateAndServe() }) //nolint:errcheck // returns after shutdown
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.ShutdownContext(ctx); err != nil {
			t.Error(err)
		}
		wg.Wait()
	})
	return s
}

// startRendered starts CoreDNS with the rendered Corefile. The ifbound
// plugin needs ifboundd, so the test drops its line; every other line, the
// forward line included, runs as rendered. It returns the address of the
// server and a stop function that CoreDNS may call once.
func startRendered(t *testing.T, caFile string, upstreams []policy.Upstream) (addr string, stop func()) {
	t.Helper()
	d := policy.DNS{Listen: netip.MustParseAddrPort("127.0.0.1:1"), Upstream: upstreams}
	var out []string
	for l := range strings.SplitSeq(string(mustNew(t, "/s.sock", caFile).Corefile(d)), "\n") {
		switch {
		case strings.HasPrefix(l, "\tifbound"):
		case strings.HasPrefix(l, ".:"):
			out = append(out, ".:0 {")
		default:
			out = append(out, l)
		}
	}
	dnsserver.Quiet = true
	inst, err := caddy.Start(caddy.CaddyfileInput{
		Contents:       []byte(strings.Join(out, "\n")),
		Filepath:       "Corefile",
		ServerTypeName: "dns",
	})
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	stop = func() {
		once.Do(func() {
			// The shutdown callbacks make the errors plugin write its
			// pending count.
			if errs := inst.ShutdownCallbacks(); len(errs) > 0 {
				t.Error(errs)
			}
			if err := inst.Stop(); err != nil {
				t.Error(err)
			}
		})
	}
	t.Cleanup(stop)
	return inst.Servers()[0].LocalAddr().String(), stop
}

func ask(t *testing.T, addr, qname string) *dns.Msg {
	t.Helper()
	r, err := dns.Exchange(new(dns.Msg).SetQuestion(qname, dns.TypeA), addr)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func upstreamOf(s *dotServer) policy.Upstream {
	d, err := policy.ParseDomain(dotName)
	if err != nil {
		panic(err) // a constant
	}
	return policy.Upstream{Addr: s.addr, ServerName: d}
}

func requireAnswer(t *testing.T, r *dns.Msg, want string) {
	t.Helper()
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 {
		t.Fatalf("reply = %v, want an answer %s", r, want)
	}
	if a, ok := r.Answer[0].(*dns.A); !ok || a.A.String() != want {
		t.Fatalf("answer = %v, want %s", r.Answer[0], want)
	}
}

func TestRenderedForwardReachesIPv4AndIPv6Upstreams(t *testing.T) {
	caFile, cert := testPKI(t)
	v4 := startDoT(t, "tcp4", "127.0.0.1", cert, "192.0.2.4")
	v6 := startDoT(t, "tcp6", "::1", cert, "192.0.2.6")

	t.Run("ipv4", func(t *testing.T) {
		addr, _ := startRendered(t, caFile, []policy.Upstream{upstreamOf(v4)})
		requireAnswer(t, ask(t, addr, "v4.example."), "192.0.2.4")
	})
	t.Run("ipv6", func(t *testing.T) {
		addr, _ := startRendered(t, caFile, []policy.Upstream{upstreamOf(v6)})
		requireAnswer(t, ask(t, addr, "v6.example."), "192.0.2.6")
	})
	t.Run("mixed", func(t *testing.T) {
		v4.hits.Store(0)
		v6.hits.Store(0)
		addr, _ := startRendered(t, caFile, []policy.Upstream{upstreamOf(v4), upstreamOf(v6)})
		// forward picks an upstream at random, so many names make it
		// certain that both servers answer.
		for i := range 60 {
			r := ask(t, addr, fmt.Sprintf("q%d.example.", i))
			if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 {
				t.Fatalf("query %d: reply = %v", i, r)
			}
		}
		if v4.hits.Load() == 0 || v6.hits.Load() == 0 {
			t.Errorf("hits: IPv4 server %d, IPv6 server %d; want both above zero", v4.hits.Load(), v6.hits.Load())
		}
	})
}

// syncBuffer is a bytes.Buffer that several goroutines can write.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestFailedQueryLeavesNoQueryNameInTheLog(t *testing.T) {
	// A closed port: the upstream refuses the connection, so the query fails.
	ln, err := new(net.ListenConfig).Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := netip.MustParseAddrPort(ln.Addr().String())
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	caFile, _ := testPKI(t)
	d, err := policy.ParseDomain(dotName)
	if err != nil {
		t.Fatal(err)
	}

	var logs syncBuffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	addr, stop := startRendered(t, caFile, []policy.Upstream{{Addr: dead, ServerName: d}})
	const qname = "secret-query-name.example."
	if r := ask(t, addr, qname); r.Rcode != dns.RcodeServerFailure {
		t.Fatalf("reply = %v, want SERVFAIL", r)
	}
	stop()
	got := logs.String()
	if !strings.Contains(got, "errors like") {
		t.Errorf("the failed query left no consolidated error in the log:\n%s", got)
	}
	if strings.Contains(got, "secret-query-name") {
		t.Errorf("the log has the query name:\n%s", got)
	}
}
