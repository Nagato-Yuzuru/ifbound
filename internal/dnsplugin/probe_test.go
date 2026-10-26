package dnsplugin

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"

	"github.com/Nagato-Yuzuru/ifbound/internal/ipc"
)

// proberFunc is a prober made from a function.
type proberFunc func(ctx context.Context, qname string) error

func (f proberFunc) ReportProbe(ctx context.Context, qname string) error { return f(ctx, qname) }

// countingNext is a next plugin that fails the test when it gets a query.
type countingNext struct{ calls atomic.Int32 }

func (n *countingNext) ServeDNS(context.Context, dns.ResponseWriter, *dns.Msg) (int, error) {
	n.calls.Add(1)
	return dns.RcodeServerFailure, nil
}

func (*countingNext) Name() string { return "next" }

func TestProbeIsReportedBeforeTheLocalAnswer(t *testing.T) {
	for _, qname := range []string{ipc.ProbePrefix + "0a1b.cdn.test.", "IFBOUND-PROBE-0A1B.Cdn.Test."} {
		t.Run(qname, func(t *testing.T) {
			next := &countingNext{}
			rec := dnstest.NewRecorder(&test.ResponseWriter{})
			var got string
			var repliedBefore bool
			h := &handler{key: testKey, next: next, reporter: &recorder{}, timeout: time.Second,
				probes: proberFunc(func(_ context.Context, q string) error {
					got, repliedBefore = q, rec.Msg != nil
					return nil
				})}

			rcode, err := h.ServeDNS(t.Context(), rec, new(dns.Msg).SetQuestion(qname, dns.TypeA))

			if err != nil || rcode != dns.RcodeNameError {
				t.Fatalf("ServeDNS = %d, %v; want NXDOMAIN", rcode, err)
			}
			if got != qname || repliedBefore {
				t.Errorf("probe reported %q (after the reply: %v), want %q before the reply", got, repliedBefore, qname)
			}
			if next.calls.Load() != 0 {
				t.Error("the probe went to the next plugin")
			}
			if rec.Msg == nil || rec.Msg.Rcode != dns.RcodeNameError || len(rec.Msg.Answer) != 0 {
				t.Errorf("client got %v, want NXDOMAIN without records", rec.Msg)
			}
		})
	}
}

func TestFailedProbeReportStillAnswersLocally(t *testing.T) {
	next := &countingNext{}
	h := &handler{key: testKey, next: next, reporter: &recorder{}, timeout: time.Second,
		probes: proberFunc(func(context.Context, string) error { return ipc.ErrUnavailable })}

	rec, rcode, err := serve(t.Context(), h, ipc.ProbePrefix+"0a1b.cdn.test.")

	if rcode != dns.RcodeNameError || !errors.Is(err, ipc.ErrUnavailable) {
		t.Errorf("ServeDNS = %d, %v; want NXDOMAIN and the report error for the log", rcode, err)
	}
	if rec.Msg == nil || next.calls.Load() != 0 {
		t.Errorf("client got %v, next plugin calls %d; want a local answer only", rec.Msg, next.calls.Load())
	}
}

func TestProbeReportWaitsAtMostTheTimeout(t *testing.T) {
	var deadline time.Time
	h := &handler{key: testKey, next: &countingNext{}, reporter: &recorder{}, timeout: 300 * time.Millisecond,
		probes: proberFunc(func(ctx context.Context, _ string) error {
			deadline, _ = ctx.Deadline()
			<-ctx.Done()
			return ctx.Err()
		})}
	begin := time.Now()

	_, rcode, _ := serve(t.Context(), h, ipc.ProbePrefix+"0a1b.cdn.test.") //nolint:errcheck // the test checks the rcode; the error carries no more

	if rcode != dns.RcodeNameError || deadline.Sub(begin) > 300*time.Millisecond+50*time.Millisecond {
		t.Errorf("rcode %d, probe deadline %v after the start; want NXDOMAIN within the timeout", rcode, deadline.Sub(begin))
	}
}

// probeGate is ifboundd for the deadlock test: each report waits until
// the probe of its qname arrives, so each report holds its slot while its
// probe needs a slot.
type probeGate struct {
	mu   sync.Mutex
	seen map[string]chan struct{}
}

func (g *probeGate) ch(qname string) chan struct{} {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.seen == nil {
		g.seen = map[string]chan struct{}{}
	}
	c := g.seen[qname]
	if c == nil {
		c = make(chan struct{})
		g.seen[qname] = c
	}
	return c
}

func (g *probeGate) ProbeSeen(qname string) {
	c := g.ch(qname)
	g.mu.Lock()
	defer g.mu.Unlock()
	select {
	case <-c:
	default:
		close(c)
	}
}

func (g *probeGate) Observe(ctx context.Context, o ipc.Observation) (ipc.Ack, error) {
	select {
	case <-g.ch(ipc.ProbePrefix + "x." + o.QName):
		return ipc.Ack{}, nil
	case <-ctx.Done():
		return ipc.Ack{}, ctx.Err()
	}
}

// The plugin holds all its report slots with reports that wait for
// probes. The probe queries must still reach ifboundd through the same
// client, or every report times out.
func TestProbesPassWhileEveryReportWaits(t *testing.T) {
	g := &probeGate{}
	path := socketPath(t)
	srv, err := ipc.Listen(ipc.ServerConfig{Path: path, Handler: g, Probes: g, AllowedUIDs: []uint32{selfUID()}})
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
	client := ipc.NewClient(path, selfUID())
	h := &handler{key: testKey, next: writeA(done), reporter: client, probes: client, timeout: 10 * time.Second}

	const n = 40 // more than the report slots of the client
	replies := make(chan int, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			_, rcode, _ := serve(t.Context(), h, fmt.Sprintf("r%d.test.", i)) //nolint:errcheck // the test counts the rcodes; the error carries no more
			replies <- rcode
		})
	}
	time.Sleep(100 * time.Millisecond) // lets the reports fill the slots; no other signal exists
	for i := range n {
		wg.Go(func() {
			if _, rcode, err := serve(t.Context(), h, fmt.Sprintf("%sx.r%d.test.", ipc.ProbePrefix, i)); err != nil {
				t.Errorf("probe %d: ServeDNS = %d, %v", i, rcode, err)
			}
		})
	}
	wg.Wait()
	close(replies)
	for rcode := range replies {
		if rcode != dns.RcodeSuccess {
			t.Errorf("report rcode = %d, want success after its probe", rcode)
		}
	}
}
