package daemon

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/blockable"
	"github.com/Nagato-Yuzuru/ifbound/internal/daemon/core"
	"github.com/Nagato-Yuzuru/ifbound/internal/ipc"
	"github.com/Nagato-Yuzuru/ifbound/internal/logattr"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
)

// reportView is what a DNS report reads of the loop: the gate and the
// address book. The loop publishes a new view when either changes, and
// then closes next of the old view.
type reportView struct {
	gate core.Gate
	// ledger is the book that the loop holds. It is not nil while the
	// gate is open: the gate opens only with the loaded book.
	ledger reconcile.Ledger
	next   chan struct{}
}

func newView(g core.Gate, l reconcile.Ledger) *reportView {
	return &reportView{gate: g, ledger: l, next: make(chan struct{})}
}

// publishView makes a view of the gate g and the ledger l the current
// one, when it differs from the current one.
func publishView(p *atomic.Pointer[reportView], g core.Gate, l reconcile.Ledger) {
	old := p.Load()
	if old != nil && old.gate == g && old.ledger == l {
		return
	}
	p.Store(newView(g, l))
	if old != nil {
		close(old.next)
	}
}

// Observe implements ipc.Handler. It runs on the goroutine of the
// caller: a report does not wait for the loop. A name that matches no
// policy gets a nil error and an unprotected ack. The address list and
// the ruleset are not checked then. For a name that matches a policy, a
// nil error means that every address is in the table of each matching
// policy and in the address book on disk, and that the installed
// ruleset is loaded. The ack is then protected. It returns ErrNotReady
// in StateStarting, ErrUnenforced when enforcement is not installed, an
// error that wraps matcher.ErrMalformedName for a name that cannot be
// classified, ErrStopped after Run returned, and the platform error
// otherwise.
//
// A report that a convergence overtakes (reconcile.ErrStale) waits for
// the gate of that convergence and runs again. When ctx ends first, it
// returns ctx.Err(). A report whose ctx ends never gets a protected
// ack; the addresses that it added to a table only block more.
func (d *Daemon) Observe(ctx context.Context, o ipc.Observation) (ipc.Ack, error) {
	began := time.Now()
	var waited time.Duration
	for {
		v := d.view.Load()
		a, stale := d.answer(ctx, v, o)
		if !stale {
			d.reports.note(a)
			outcome := logattr.ReportUnprotected
			switch {
			case a.Err() != nil:
				outcome = logattr.ReportNotAcknowledged
			case a.Protected():
				outcome = logattr.ReportProtected
			}
			d.logReport(ctx, outcome, waited, time.Since(began))
			if err := a.Err(); err != nil {
				return ipc.Ack{}, err
			}
			return ipc.Ack{Protected: a.Protected()}, nil
		}
		w := time.Now()
		select {
		case <-v.next:
			waited += time.Since(w)
		case <-ctx.Done():
			d.logReport(ctx, logattr.ReportNotAcknowledged, waited+time.Since(w), time.Since(began))
			return ipc.Ack{}, ctx.Err()
		}
	}
}

// answer runs the report o against the view v. stale is true when a
// convergence overtook the report: the report must run again with the
// next view.
func (d *Daemon) answer(ctx context.Context, v *reportView, o ipc.Observation) (a core.Answer, stale bool) {
	names, epoch, a, decided := core.Admit(v.gate, o.QName)
	if decided {
		return a, false
	}
	c, err := reconcile.Record(ctx, d.cfg.Platform.Guard, v.ledger, reconcile.Sighting{
		Names: names, Addrs: blockable.Filter(o.Addrs), TTL: o.TTL, At: time.Now(), Epoch: epoch,
	})
	// The gate after Record: the answer never trusts an older gate.
	a = core.AckAfterCheck(d.view.Load().gate, c, err)
	return a, errors.Is(a.Err(), reconcile.ErrStale)
}

// logReport writes the debug event of one Observe call. wait is the time
// that the report waited for a new gate, and took is the time of the
// whole call.
func (d *Daemon) logReport(ctx context.Context, outcome string, wait, took time.Duration) {
	d.cfg.Logger.LogAttrs(ctx, slog.LevelDebug, "report",
		slog.String(logattr.ReportResult, outcome),
		slog.Int64(logattr.ReportWaitUS, wait.Microseconds()),
		slog.Int64(logattr.ReportObserveUS, took.Microseconds()))
}

// reportCell carries the outcomes of the reports to the loop, which
// gives them to core. It keeps them in order, but it merges a failure
// at the step of the failure before it, and it keeps a success only
// after a failure: core needs no more. ready has room for one value and
// gets one when the cell has events.
type reportCell struct {
	// failed is true after a failure, until a success follows it. A
	// success reads it without the lock: most reports succeed after a
	// success.
	failed atomic.Bool
	mu     sync.Mutex
	events []core.Event
	ready  chan struct{}
}

func newReportCell() *reportCell {
	return &reportCell{ready: make(chan struct{}, 1)}
}

// note keeps the outcome of the answer a.
func (c *reportCell) note(a core.Answer) {
	step, err, failed := a.Failure()
	if !failed && (!a.Protected() || !c.failed.Load()) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case failed:
		c.failed.Store(true)
		if n := len(c.events); n > 0 {
			if last, ok := c.events[n-1].(core.ReportFailed); ok && last.Step == step {
				return
			}
		}
		c.events = append(c.events, core.ReportFailed{At: time.Now(), Step: step, Err: err})
	case c.failed.CompareAndSwap(true, false):
		c.events = append(c.events, core.ReportSucceeded{At: time.Now()})
	default:
		return
	}
	select {
	case c.ready <- struct{}{}:
	default:
	}
}

// drain returns the events in order and empties the cell.
func (c *reportCell) drain() []core.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	ev := c.events
	c.events = nil
	return ev
}
