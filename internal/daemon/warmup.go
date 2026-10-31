package daemon

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/syslookup"
)

const (
	// WarmUpConcurrency is the maximum number of warm-up names in work at
	// one time. One lookup can give two reports (A and AAAA), and
	// ifbound-dns has 32 report slots: the warm-up leaves most of them to
	// the applications.
	WarmUpConcurrency = 4
	// WarmUpTimeout is the budget of the probe of one warm-up name, and
	// then the budget of its lookup. The probe budget is more than three
	// times the longest apply time of a new resolver entry measured on
	// macOS (1.55 s). The report of a lookup does not depend on the lookup
	// budget: ifbound-dns reports with its own budget, also after the
	// lookup returned. It does not follow the ack timeout.
	WarmUpTimeout = 5 * time.Second
)

// warmUp resolves the names of the configuration through the system
// resolver. The lookups go to ifbound-dns, and their reports learn the
// addresses of the names before an application asks.
// The warm-up itself writes nothing.
//
// A lookup is useful only when it goes to ifbound-dns. The system applies
// a new resolver entry after a delay, and ifbound-dns can be down for a
// short time, for example when launchd restarts it. So each name first
// gets a probe (see Daemon.probe), and only a name whose probe succeeded
// gets its lookup. A name whose probe failed gets another try after
// SelfHealInterval.
//
// Only the Run goroutine calls its methods. Its lookups run on their own
// goroutines, outside the loop, so a slow lookup never delays a report.
type warmUp struct {
	lookup SystemResolver
	// prove returns nil when ifbound-dns reported a probe name below
	// domain before ctx ended. Daemon.probe implements it.
	prove func(ctx context.Context, domain policy.Domain) error
	log   *slog.Logger
	// slots bounds the names in work of all warm-ups together. A stopped
	// warm-up starts no new name, but it does not stop the lookups that
	// it started: a system lookup can go on after Resolve returns (see
	// syslookup.Resolver), so each lookup keeps its slot until its own
	// budget ends.
	slots chan struct{}
	wg    sync.WaitGroup
	// cancel stops the current warm-up. It is nil when no warm-up was
	// started for gen while the phase acks.
	cancel context.CancelFunc
	gen    uint64
	// results receives a value when res changes. It has room for one
	// value, and a send that finds it full is dropped: the loop reads the
	// latest res.
	results chan struct{}
	resMu   sync.Mutex
	res     warmResult
}

// warmResult holds the latest configuration generations of the
// self-test: proved is the generation under which a probe reached
// ifbound-dns, and missed the generation under which a whole pass
// ended with no such probe.
type warmResult struct {
	proved, missed uint64
}

func newWarmUp(lookup SystemResolver, prove func(context.Context, policy.Domain) error, log *slog.Logger) *warmUp {
	return &warmUp{
		lookup: lookup, prove: prove, log: log,
		slots:   make(chan struct{}, WarmUpConcurrency),
		results: make(chan struct{}, 1),
	}
}

// sync runs one warm-up for each configuration while the phase acks. It
// stops the warm-up when the configuration changes or the phase stops
// acking. A warm-up starts again from its first name when the phase acks
// again: the reports of its lookups were not acked meanwhile.
func (w *warmUp) sync(ctx context.Context, l *loop) {
	if w.cancel != nil && (w.gen != l.gen || !l.phase.acks()) {
		w.cancel()
		w.cancel = nil
	}
	if w.cancel != nil || !l.phase.acks() {
		return
	}
	names := warmUpNames(l.cfg)
	var wctx context.Context
	wctx, w.cancel = context.WithCancel(ctx)
	w.gen = l.gen
	gen := l.gen
	w.wg.Go(func() { w.run(wctx, ctx, names, gen) })
}

// run warms up names in passes until each name had a successful probe,
// or wctx ends. wctx is the life of the warm-up, and ctx is the life of
// Run.
func (w *warmUp) run(wctx, ctx context.Context, names []policy.Domain, gen uint64) {
	for first := true; ; first = false {
		tried := len(names)
		names = w.pass(wctx, ctx, names, first, gen)
		if len(names) == 0 {
			return
		}
		if len(names) == tried && wctx.Err() == nil {
			w.report(func(r *warmResult) { r.missed = gen })
		}
		select {
		case <-wctx.Done():
			return
		case <-time.After(SelfHealInterval):
		}
	}
}

// pass starts the work on one name when a slot is free, until wctx ends.
// It returns when the work on each started name has ended, with the names
// whose probe failed.
func (w *warmUp) pass(wctx, ctx context.Context, names []policy.Domain, first bool, gen uint64) []policy.Domain {
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		unproven []policy.Domain
	)
	for _, name := range names {
		if !w.acquire(wctx) {
			break
		}
		wg.Go(func() {
			defer func() { <-w.slots }()
			if !w.warm(wctx, ctx, name, first, gen) {
				mu.Lock()
				unproven = append(unproven, name)
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	return unproven
}

// acquire takes a slot. It reports false, with no slot, when wctx ends
// first.
func (w *warmUp) acquire(wctx context.Context) bool {
	select {
	case w.slots <- struct{}{}:
	case <-wctx.Done():
		return false
	}
	// select picks at random when both are ready.
	if wctx.Err() != nil {
		<-w.slots
		return false
	}
	return true
}

// warm probes below name, and then resolves name when the probe
// succeeded. It reports whether the probe succeeded. The lookup ends with
// its budget or with ctx, not with wctx: see warmUp.slots.
func (w *warmUp) warm(wctx, ctx context.Context, name policy.Domain, first bool, gen uint64) bool {
	pctx, cancel := context.WithTimeout(wctx, WarmUpTimeout)
	err := w.prove(pctx, name)
	cancel()
	if err != nil {
		if first && wctx.Err() == nil {
			w.log.WarnContext(ctx, "warm-up: no proof that the queries for the name go to ifbound-dns; the warm-up tries the name again later",
				slog.String("name", name.String()), slog.Any("error", err))
		}
		return false
	}
	w.report(func(r *warmResult) { r.proved = gen })
	lctx, cancel := context.WithTimeout(ctx, WarmUpTimeout)
	defer cancel()
	// The report of ifbound-dns learns the answer, so only the error
	// tells something here.
	_, err = w.lookup.Resolve(lctx, name.String())
	switch {
	case err == nil || ctx.Err() != nil:
	case errors.Is(err, syslookup.ErrNotFound) || errors.Is(err, context.DeadlineExceeded):
		// A name without addresses is normal, for example the domain of
		// a suffix destination. At the deadline, the system lookup and its
		// report can still complete.
		w.log.DebugContext(ctx, "warm-up lookup gave no addresses in time",
			slog.String("name", name.String()), slog.Any("error", err))
	default:
		w.log.WarnContext(ctx, "warm-up lookup failed", slog.String("name", name.String()), slog.Any("error", err))
	}
	return true
}

// report changes the result with f and tells the loop.
func (w *warmUp) report(f func(*warmResult)) {
	w.resMu.Lock()
	f(&w.res)
	w.resMu.Unlock()
	select {
	case w.results <- struct{}{}:
	default:
	}
}

// result returns the latest result.
func (w *warmUp) result() warmResult {
	w.resMu.Lock()
	defer w.resMu.Unlock()
	return w.res
}

// wait returns when every lookup of every warm-up has returned.
func (w *warmUp) wait() { w.wg.Wait() }

// warmUpNames returns the names that the warm-up resolves: each exact
// destination and the domain of each suffix destination, in file order
// and without duplicates.
func warmUpNames(cfg policy.Config) []policy.Domain {
	var out []policy.Domain
	seen := make(map[policy.Domain]bool)
	for _, p := range cfg.Policies {
		for _, dest := range p.To {
			var name policy.Domain
			switch d := dest.(type) {
			case policy.ExactDomain:
				name = d.Domain()
			case policy.DomainSuffix:
				name = d.Domain()
			case policy.IPAddr, policy.CIDR:
				continue // not a name
			}
			if !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	return out
}
