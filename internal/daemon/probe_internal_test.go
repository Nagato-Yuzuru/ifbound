package daemon

import (
	"context"
	"errors"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

// These tests check the probe wait itself. The probe error is not
// exported, so the tests are internal.

// probeLookup records each name. When it returns, onResolve may report a
// name to the daemon, as ifbound-dns would.
type probeLookup struct {
	mu        sync.Mutex
	names     []string
	onResolve func(names []string)
}

func (l *probeLookup) Resolve(_ context.Context, name string) ([]netip.Addr, error) {
	l.mu.Lock()
	l.names = append(l.names, name)
	names := append([]string(nil), l.names...)
	l.mu.Unlock()
	if l.onResolve != nil {
		l.onResolve(names)
	}
	return nil, nil
}

func (l *probeLookup) sent() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.names...)
}

func testProbeDomain(t *testing.T) policy.Domain {
	t.Helper()
	d, err := policy.ParseDomain("Example.COM")
	if err != nil {
		t.Fatal(err)
	}
	return d
}

var probeNamePattern = regexp.MustCompile(`^ifbound-probe-[0-9a-f]{16}\.example\.com$`)

func TestProbeSucceedsWhenThePluginReportsTheName(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := &probeLookup{}
		d := New(Config{Lookup: l})
		l.onResolve = func(names []string) { d.ProbeSeen(strings.ToUpper(names[len(names)-1]) + ".") }
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		start := time.Now()
		if err := d.probe(ctx, testProbeDomain(t)); err != nil {
			t.Fatalf("probe = %v, want nil", err)
		}
		if waited := time.Since(start); waited != 0 {
			t.Errorf("probe took %v after the report, want no wait", waited)
		}
		if names := l.sent(); len(names) != 1 || !probeNamePattern.MatchString(names[0]) {
			t.Errorf("probe names %q, want one name ifbound-probe-<16 hex>.example.com", names)
		}
	})
}

func TestProbeCountsALateReportOfAnEarlierName(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := &probeLookup{}
		d := New(Config{Lookup: l})
		l.onResolve = func(names []string) {
			if len(names) == 3 {
				d.ProbeSeen(names[0])
			}
		}
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		if err := d.probe(ctx, testProbeDomain(t)); err != nil {
			t.Fatalf("probe = %v, want nil", err)
		}
		names := l.sent()
		if len(names) != 3 {
			t.Fatalf("probe sent %d names, want 3", len(names))
		}
		seen := map[string]bool{}
		for _, n := range names {
			if !probeNamePattern.MatchString(n) || seen[n] {
				t.Errorf("probe name %q is malformed or repeated", n)
			}
			seen[n] = true
		}
	})
}

// A probe that ifbound-dns never reports fails with errProbe when the
// budget of its ctx ends.
func TestProbeTimesOutWithAnError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const budget = 700 * time.Millisecond
		l := &probeLookup{}
		d := New(Config{Lookup: l})
		// Unrelated and malformed reports do not end the probe.
		l.onResolve = func([]string) {
			d.ProbeSeen("ifbound-probe-0000000000000000.example.com")
			d.ProbeSeen("..")
			d.ProbeSeen("")
		}
		checkProbeFails(t.Context(), t, d, budget)
		if n := len(l.sent()); n < int(budget/ProbeInterval)-1 {
			t.Errorf("probe sent %d names in %v, want one per %v", n, budget, ProbeInterval)
		}
		// The probe dropped its names: a report after the end is harmless.
		for _, n := range l.sent() {
			d.ProbeSeen(n)
		}
	})
}

// A probe whose ctx has no deadline fails at once and sends no name: the
// caller must bound every probe. The ctx can be canceled, so a probe that
// does not check the deadline ends at its first name instead of running
// on.
func TestProbeWithoutDeadlineFailsAtOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		l := &probeLookup{onResolve: func([]string) { cancel() }}
		d := New(Config{Lookup: l})
		checkProbeFails(ctx, t, d, 0)
		if names := l.sent(); len(names) != 0 {
			t.Errorf("probe sent %q, want no name", names)
		}
	})
}

// checkProbeFails runs a probe with ctx and, when budget is not 0, a
// deadline budget from now. It wants errProbe when the budget ends.
func checkProbeFails(ctx context.Context, t *testing.T, d *Daemon, budget time.Duration) {
	t.Helper()
	if budget > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, budget)
		defer cancel()
	}
	start := time.Now()
	err := d.probe(ctx, testProbeDomain(t))
	if !errors.Is(err, errProbe) {
		t.Fatalf("probe = %v, want errProbe", err)
	}
	if waited := time.Since(start); waited != budget {
		t.Errorf("probe gave up after %v, want %v", waited, budget)
	}
}
