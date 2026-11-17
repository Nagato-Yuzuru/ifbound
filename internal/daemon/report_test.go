package daemon_test

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/daemon"
	"github.com/Nagato-Yuzuru/ifbound/internal/hostsfile"
)

// blockingHosts blocks Version while blocked is set, until the test
// closes the channel. The loop calls Version first in each pass.
type blockingHosts struct {
	daemon.HostsReader
	mu      sync.Mutex
	blocked chan struct{}
}

func (b *blockingHosts) Version() (hostsfile.Version, error) {
	b.mu.Lock()
	ch := b.blocked
	b.mu.Unlock()
	if ch != nil {
		<-ch
	}
	return b.HostsReader.Version()
}

// block makes the next Version calls wait, and returns the release.
func (b *blockingHosts) block() func() {
	ch := make(chan struct{})
	b.mu.Lock()
	b.blocked = ch
	b.mu.Unlock()
	return func() {
		b.mu.Lock()
		b.blocked = nil
		b.mu.Unlock()
		close(ch)
	}
}

// Reports run on the goroutine of the caller. While the loop waits in a
// pass, outside the Guard, a report of each path gets its answer: a name
// that matches no policy (no pf call), a known address, and a new
// address (a commit to the book).
func TestReportsDoNotWaitForTheLoop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSpec(t, configV1)
		s.hosts = &fakeHosts{}
		hosts := &blockingHosts{HostsReader: s.hosts}
		s.reader = hosts
		h := launch(t, s)
		defer h.stop()
		h.wantState(daemon.StateReady)
		if err := h.observe(obs("www.example.net", "203.0.113.1")); err != nil {
			t.Fatalf("Observe before the block: %v", err)
		}

		release := hosts.block()
		heal() // the self-heal pass now waits in the read of the host file
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		if err := h.d.Reconfigure(ctx, parse(t, configV1)); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Reconfigure while the loop waits = %v, want DeadlineExceeded: the loop is not blocked", err)
		}

		writes := h.world.Writes()
		if ack, err := h.d.Observe(t.Context(), obs("unmatched.test", "203.0.113.9")); err != nil || ack.Protected {
			t.Errorf("unmatched name = (%+v, %v), want an unprotected ack", ack, err)
		}
		if n := h.world.Writes() - writes; n != 0 {
			t.Errorf("unmatched name made %d Backend writes, want 0", n)
		}
		for _, a := range []string{"203.0.113.1", "203.0.113.2"} {
			if ack, err := h.d.Observe(t.Context(), obs("www.example.net", a)); err != nil || !ack.Protected {
				t.Errorf("%s while the loop waits = (%+v, %v), want a protected ack", a, ack, err)
			}
		}
		if got := h.saved("web"); len(got) != 2 {
			t.Errorf("book web = %v, want both addresses", got)
		}
		release()
	})
}

// Run closes the book only after each report in its section ended: the
// commit of that report still reaches the book. The report gets
// ErrStopped, because the gate after its check is the closed gate of the
// stop. A report after the stop gets ErrStopped at once.
func TestStopWaitsForAReportInItsSection(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		h.wantState(daemon.StateReady)
		release := make(chan struct{})
		h.world.SetBeforeWrite(func(int) error { <-release; return nil })
		res := make(chan error, 1)
		go func() {
			_, err := h.d.Observe(t.Context(), obs("www.example.net", "203.0.113.5"))
			res <- err
		}()
		synctest.Wait() // the report waits in its table add

		stopped := make(chan struct{})
		go func() { h.stop(); close(stopped) }()
		synctest.Wait()
		select {
		case <-stopped:
			t.Fatal("Run returned while a report was in its section")
		default:
		}
		close(release)
		if err := <-res; !errors.Is(err, daemon.ErrStopped) {
			t.Errorf("report during the stop = %v, want ErrStopped", err)
		}
		<-stopped
		if got := h.saved("web"); !slices.Contains(got, netip.MustParseAddr("203.0.113.5")) {
			t.Errorf("book web = %v, want the address of the report: its commit came before the close", got)
		}
		if _, err := h.d.Observe(t.Context(), obs("www.example.net", "203.0.113.6")); !errors.Is(err, daemon.ErrStopped) {
			t.Errorf("report after the stop = %v, want ErrStopped", err)
		}
	})
}
