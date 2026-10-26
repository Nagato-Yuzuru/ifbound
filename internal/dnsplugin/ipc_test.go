package dnsplugin

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/Nagato-Yuzuru/ifbound/internal/ipc"
)

type observeFunc func(ctx context.Context, o ipc.Observation) error

// Observe acks as not protected.
func (f observeFunc) Observe(ctx context.Context, o ipc.Observation) (ipc.Ack, error) {
	return ipc.Ack{}, f(ctx, o)
}

func selfUID() uint32 { return uint32(os.Getuid()) } //nolint:gosec // uid is never negative on unix

// socketPath returns a socket path short enough for macOS (104 bytes).
func socketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ifb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	return filepath.Join(dir, "s.sock")
}

// startServerAt runs a real ipc.Server at path for the test.
func startServerAt(t *testing.T, path string, h ipc.Handler) {
	t.Helper()
	srv, err := ipc.Listen(ipc.ServerConfig{Path: path, Handler: h, AllowedUIDs: []uint32{selfUID()}})
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- srv.Serve(context.Background()) }()
	t.Cleanup(func() {
		_ = srv.Close() //nolint:errcheck // Serve returns the close error below, and the test fails on it
		if err := <-served; err != nil {
			t.Errorf("Serve returned %v", err)
		}
	})
}

// startServer runs a real ipc.Server and returns a client for it.
func startServer(t *testing.T, h ipc.Handler) *ipc.Client {
	t.Helper()
	path := socketPath(t)
	startServerAt(t, path, h)
	return ipc.NewClient(path, selfUID())
}

func TestReportReachesIfboundd(t *testing.T) {
	seen := make(chan ipc.Observation, 1)
	client := startServer(t, observeFunc(func(_ context.Context, o ipc.Observation) error {
		seen <- o
		return nil
	}))
	up := &upstream{answer: []dns.RR{
		rr("www.example.org. 60 IN CNAME a.example.net."),
		rr("a.example.net. 300 IN AAAA 2001:db8::1"),
	}}
	h := &handler{key: testKey, next: up, reporter: client, timeout: 2 * time.Second}

	rec, rcode, err := serve(t.Context(), h, "www.example.org.")
	if err != nil || rcode != dns.RcodeSuccess {
		t.Fatalf("ServeDNS = %d, %v; want success", rcode, err)
	}
	select {
	case got := <-seen:
		want := ipc.Observation{QName: "www.example.org.", Addrs: addrs("2001:db8::1"), TTL: 60 * time.Second}
		if got.QName != want.QName || got.TTL != want.TTL || !slices.Equal(got.Addrs, want.Addrs) {
			t.Errorf("ifboundd got %+v, want %+v", got, want)
		}
	default:
		t.Fatal("ServeDNS replied before ifboundd saw the observation")
	}
	if rec.Msg == nil || rec.Msg.String() != up.sent.String() {
		t.Errorf("client got\n%v\nwant\n%v", rec.Msg, up.sent)
	}
}

func TestRejectionByIfbounddGivesServfail(t *testing.T) {
	client := startServer(t, observeFunc(func(context.Context, ipc.Observation) error {
		return errors.New("table full")
	}))
	h := &handler{key: testKey, next: writeA(done), reporter: client, timeout: 2 * time.Second}
	rec, rcode, err := serve(t.Context(), h, "example.org.")
	if rcode != dns.RcodeServerFailure || !errors.Is(err, ipc.ErrRejected) || rec.Msg != nil {
		t.Errorf("ServeDNS = %d, %v, client got %v; want SERVFAIL, ErrRejected, no reply", rcode, err, rec.Msg)
	}
}

// TestDenseIPv4HintReplyIsReported sends a 64 KiB reply that holds its
// addresses in one ipv4hint, the densest address form. The observation
// must fit in one frame, so the client gets the reply after the ack.
func TestDenseIPv4HintReplyIsReported(t *testing.T) {
	seen := make(chan int, 1)
	client := startServer(t, observeFunc(func(_ context.Context, o ipc.Observation) error {
		seen <- len(o.Addrs)
		return nil
	}))
	var hint []net.IP
	for x := 100; x < 256 && len(hint) < 16000; x++ {
		for y := 100; y < 256 && len(hint) < 16000; y++ {
			hint = append(hint, net.IPv4(100, 100, byte(x), byte(y)).To4())
		}
	}
	up := &upstream{answer: []dns.RR{&dns.HTTPS{SVCB: dns.SVCB{
		Hdr:      dns.RR_Header{Name: "q.example.", Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 60},
		Priority: 1, Target: ".",
		Value: []dns.SVCBKeyValue{&dns.SVCBIPv4Hint{Hint: hint}},
	}}}}
	h := &handler{key: testKey, next: up, reporter: client, timeout: 5 * time.Second}
	rec, rcode, err := serve(t.Context(), h, "q.example.")
	if err != nil || rec.Msg == nil {
		t.Fatalf("ServeDNS = %d, %v; want the reply after an ack", rcode, err)
	}
	if wire, err := rec.Msg.Pack(); err != nil || len(wire) < 60000 {
		t.Errorf("reply is %d bytes (%v), want a reply near 64 KiB", len(wire), err)
	}
	if n := <-seen; n != len(hint) {
		t.Errorf("ifboundd got %d addresses, want %d", n, len(hint))
	}
}

// fakeDaemon is the ipc.Handler of a daemon that protects the names at and
// below one domain, and records the reports.
type fakeDaemon struct {
	domain string

	mu   sync.Mutex
	seen []ipc.Observation
}

func (d *fakeDaemon) Observe(_ context.Context, o ipc.Observation) (ipc.Ack, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.seen = append(d.seen, o)
	return ipc.Ack{Protected: dns.IsSubDomain(d.domain, dns.CanonicalName(o.QName))}, nil
}

func (d *fakeDaemon) reports() []ipc.Observation {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.seen)
}

// The protected flag of the ack, through the real socket, decides if the
// client gets the flattened reply. The query for the synthetic name in the
// flattened reply reports under the protected name.
func TestAckThroughTheSocketDrivesTheFlattening(t *testing.T) {
	d := &fakeDaemon{domain: "example.com."}
	client := startServer(t, d)
	replies := map[string]zoneReply{
		zkey("www.example.com.", dns.TypeA): {answer: []string{
			"www.example.com. 300 IN CNAME a.cdn.net.",
			"a.cdn.net. 60 IN A 192.0.2.20",
		}},
		zkey("www.example.org.", dns.TypeA): {answer: []string{
			"www.example.org. 300 IN CNAME a.cdn.net.",
			"a.cdn.net. 60 IN A 192.0.2.20",
		}},
		zkey("www.example.com.", dns.TypeHTTPS): {answer: []string{
			"www.example.com. 300 IN HTTPS 1 svc.cdn.net. alpn=h2",
		}},
		zkey("svc.cdn.net.", dns.TypeA): {answer: []string{"svc.cdn.net. 60 IN A 192.0.2.21"}},
	}
	z := &zone{replies: replies}
	h := &handler{key: testKey, next: z, reporter: client, timeout: 2 * time.Second}

	res := query(t, h, "www.example.com.", dns.TypeA)
	if res.err != nil || !slices.Equal(strs(res.reply.Answer), records("www.example.com. 60 IN A 192.0.2.20")) {
		t.Errorf("protected: ServeDNS = %d, %v, answer %v; want the flattened answer", res.rcode, res.err, res.reply)
	}
	res = query(t, h, "www.example.org.", dns.TypeA)
	if got, err := res.reply.Pack(); res.err != nil || err != nil || !bytes.Equal(got, z.sent[zkey("www.example.org.", dns.TypeA)]) {
		t.Errorf("not protected: ServeDNS = %d, %v; want the upstream reply:\n%v", res.rcode, res.err, res.reply)
	}

	res = query(t, h, "www.example.com.", dns.TypeHTTPS)
	if res.err != nil {
		t.Fatalf("HTTPS: ServeDNS = %d, %v", res.rcode, res.err)
	}
	syn := targetOf(t, res.reply)
	res = query(t, h, syn, dns.TypeA)
	if res.err != nil || !slices.Equal(strs(res.reply.Answer), records(syn+" 60 IN A 192.0.2.21")) {
		t.Errorf("synthetic: ServeDNS = %d, %v, reply %v", res.rcode, res.err, res.reply)
	}
	seen := d.reports()
	if last := seen[len(seen)-1]; last.QName != "www.example.com." || !slices.Equal(addrStrings(last.Addrs), []string{"192.0.2.21"}) {
		t.Errorf("daemon got %+v for the synthetic name, want www.example.com. [192.0.2.21]", last)
	}
}
