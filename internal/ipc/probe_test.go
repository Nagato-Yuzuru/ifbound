package ipc

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// probeBoard is a Handler and a ProbeHandler. Each report waits until
// the probe "ifbound-probe-x.<qname>" is seen, so each report holds its
// slot while its probe needs a slot.
type probeBoard struct {
	mu   sync.Mutex
	seen map[string]chan struct{}
}

func newProbeBoard() *probeBoard { return &probeBoard{seen: map[string]chan struct{}{}} }

func (b *probeBoard) ch(qname string) chan struct{} {
	b.mu.Lock()
	defer b.mu.Unlock()
	c := b.seen[qname]
	if c == nil {
		c = make(chan struct{})
		b.seen[qname] = c
	}
	return c
}

func (b *probeBoard) ProbeSeen(qname string) {
	c := b.ch(qname)
	b.mu.Lock()
	defer b.mu.Unlock()
	select {
	case <-c:
	default:
		close(c)
	}
}

func (b *probeBoard) Observe(ctx context.Context, o Observation) (Ack, error) {
	select {
	case <-b.ch(ProbePrefix + "x." + o.QName):
		return Ack{}, nil
	case <-ctx.Done():
		return Ack{}, ctx.Err()
	}
}

func startProbes(t *testing.T, h Handler, p ProbeHandler) *Client {
	t.Helper()
	path := shortPath(t)
	srv, err := Listen(ServerConfig{Path: path, Handler: h, Probes: p, AllowedUIDs: []uint32{self()}})
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- srv.Serve(context.Background()) }()
	t.Cleanup(func() {
		_ = srv.Close()
		if err := <-served; err != nil {
			t.Errorf("Serve returned %v", err)
		}
	})
	return NewClient(path, self())
}

// Every report slot is held by a report that waits for its probe. The
// probes must still reach the server, or no report ever acks.
func TestProbesPassWhileEveryReportSlotWaits(t *testing.T) {
	b := newProbeBoard()
	c := startProbes(t, b, b)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	reports := make(chan error, maxInFlight)
	for i := range maxInFlight {
		go func() { reports <- errOf(c.Report(ctx, Observation{QName: fmt.Sprintf("r%d.test", i)})) }()
	}
	for len(c.inflight) < maxInFlight {
		time.Sleep(time.Millisecond) // waits for the slots to fill; no other signal exists
	}

	var probes sync.WaitGroup
	errs := make(chan error, maxInFlight)
	for i := range maxInFlight { // more probes than probe slots
		probes.Go(func() { errs <- c.ReportProbe(ctx, fmt.Sprintf("%sx.r%d.test", ProbePrefix, i)) })
	}
	probes.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("ReportProbe = %v while the report slots are full", err)
		}
	}
	for range maxInFlight {
		if err := <-reports; err != nil {
			t.Errorf("Report = %v, want an ack after its probe", err)
		}
	}
}

func TestProbeRoundTrip(t *testing.T) {
	b := newProbeBoard()
	c := startProbes(t, handlerFunc(ack), b)
	name := ProbePrefix + "0123456789abcdef.cdn.test."

	if err := c.ReportProbe(t.Context(), name); err != nil {
		t.Fatalf("ReportProbe = %v", err)
	}
	select {
	case <-b.ch(name):
	default:
		t.Errorf("the handler did not get %q before the ack", name)
	}
}

func TestProbeRejections(t *testing.T) {
	for _, tc := range []struct {
		name   string
		probes ProbeHandler
		qname  string
		want   string
	}{
		{"no probe handler", nil, ProbePrefix + "x.cdn.test", "probes are not served"},
		{"empty name", newProbeBoard(), "", "invalid qname"},
		{"name too long", newProbeBoard(), strings.Repeat("a", MaxQNameLen+1), "invalid qname"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := startProbes(t, handlerFunc(ack), tc.probes)

			err := c.ReportProbe(t.Context(), tc.qname)

			if !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("ReportProbe = %v, want ErrRejected with %q", err, tc.want)
			}
		})
	}
}

func TestReportProbeWaitingForSlotHonorsContext(t *testing.T) {
	c := NewClient("/nonexistent/s.sock", self())
	for range maxProbesInFlight {
		c.probes <- struct{}{}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()

	if err := c.ReportProbe(ctx, ProbePrefix+"x.a.test"); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("ReportProbe = %v, want DeadlineExceeded", err)
	}
	if len(c.inflight) != 0 {
		t.Error("a probe took a report slot")
	}
}

func TestIsProbe(t *testing.T) {
	yes := []string{
		ProbePrefix + "0123.cdn.test", ProbePrefix + "0123.cdn.test.", "IFBOUND-PROBE-AB.cdn.test",
		ProbePrefix + ".cdn.test", // an empty nonce is still the probe form
	}
	no := []string{
		"", ".", ProbePrefix + "0123", "cdn.test", "x" + ProbePrefix + "0.cdn.test",
		"ifbound-probe.cdn.test", "a." + ProbePrefix + "0.cdn.test", ProbePrefix + "0..cdn.test",
	}
	for _, q := range yes {
		if !IsProbe(q) {
			t.Errorf("IsProbe(%q) = false, want true", q)
		}
	}
	for _, q := range no {
		if IsProbe(q) {
			t.Errorf("IsProbe(%q) = true, want false", q)
		}
	}
}
