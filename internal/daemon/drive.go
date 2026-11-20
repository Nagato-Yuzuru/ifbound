package daemon

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/daemon/core"
	"github.com/Nagato-Yuzuru/ifbound/internal/logattr"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
)

// drive gives ev to core.Step and runs the effects that it returns, in
// their order. A sync effect runs on the loop, and runSync gives its
// result to drive at once, before the next effect runs. So a sync chain
// ends before drive returns: a pass reads the host values and the book
// state right after its drive. A Converge does not run a pass here:
// runSync records it, and Run starts the pass after the current request
// or event. So a pass never runs inside another pass, and the place of
// Converge in the list does not change what the pass sees. After each
// Step, the gate is the one of the new state.
//
// Each case gives the effect to the function of its sub sum, so the
// compiler checks the sub sum of each effect. gochecksumtype does not
// take a sub sum as a case, so the switch names each effect.
func (l *loop) drive(ctx context.Context, ev core.Event) {
	var effects []core.Effect
	l.core, effects = core.Step(l.core, ev)
	l.gate = core.GateOf(l.core)
	for _, e := range effects {
		switch e := e.(type) {
		case core.Converge:
			l.runSync(ctx, e)
		case core.ReadHosts:
			l.runSync(ctx, e)
		case core.ReadKernelHosts:
			l.runSync(ctx, e)
		case core.OpenBook:
			l.runSync(ctx, e)
		case core.AdoptBook:
			l.runSync(ctx, e)
		case core.ExpireBook:
			l.runSync(ctx, e)
		case core.PruneBook:
			l.runSync(ctx, e)
		case core.ReadAccounts:
			l.runAsync(ctx, e)
		case core.AccountsOverdue:
			l.emit(ctx, e)
		case core.AccountLookupsFailed:
			l.emit(ctx, e)
		case core.HostsReadFailed:
			l.emit(ctx, e)
		case core.KernelHostsFailed:
			l.emit(ctx, e)
		case core.ReportPathFailed:
			l.emit(ctx, e)
		default:
			panic(fmt.Sprintf("daemon: unknown effect %T", e))
		}
	}
}

// runSync runs e, and gives its result, if it has one, to drive.
func (l *loop) runSync(ctx context.Context, e core.SyncEffect) {
	var res core.Event
	switch e := e.(type) {
	case core.Converge:
		l.pending = cmp.Or(l.pending, e.Trigger)
		return
	case core.ReadHosts:
		res = l.readHosts(ctx, e)
	case core.ReadKernelHosts:
		res = l.readKernelHosts(ctx, e)
	case core.OpenBook:
		res = l.openBookNow(ctx, e)
	case core.AdoptBook:
		res = l.adoptBook(ctx, e)
	case core.ExpireBook:
		res = l.expireBook(ctx, e)
	case core.PruneBook:
		res = l.pruneBook(ctx, e)
	default:
		panic(fmt.Sprintf("daemon: unknown sync effect %T", e))
	}
	l.drive(ctx, res)
}

func (l *loop) runAsync(ctx context.Context, e core.AsyncEffect) {
	switch e := e.(type) {
	case core.ReadAccounts:
		l.readAccounts(ctx, e)
	default:
		panic(fmt.Sprintf("daemon: unknown async effect %T", e))
	}
}

func (l *loop) emit(ctx context.Context, e core.OutEffect) {
	switch e := e.(type) {
	case core.AccountsOverdue:
		l.log.WarnContext(ctx, "account read takes longer than its budget")
	case core.AccountLookupsFailed:
		l.logLookupsFailed(ctx, e)
	case core.HostsReadFailed:
		l.log.WarnContext(ctx, "host file read failed",
			slog.String(logattr.ErrorType, logattr.ErrorTypeHostsRead), slog.String(logattr.ExceptionMessage, e.Err.Error()))
	case core.KernelHostsFailed:
		l.log.WarnContext(ctx, "reading the kernel entries for the host file failed",
			slog.String(logattr.ErrorType, logattr.ErrorTypePlatform), slog.String(logattr.ExceptionMessage, e.Err.Error()))
	case core.ReportPathFailed:
		errType := logattr.ErrorTypePlatform
		if e.Step == reconcile.StepCommit {
			errType = logattr.ErrorTypeAddressBook
		}
		l.log.WarnContext(ctx, "DNS report got no ack",
			slog.String(logattr.ErrorType, errType), slog.String(logattr.ExceptionMessage, e.Err.Error()))
	default:
		panic(fmt.Sprintf("daemon: unknown out effect %T", e))
	}
}

// armWake sets t to the time at which core wants a Tick, or stops it
// when nothing is due.
func (l *loop) armWake(t *time.Timer) {
	at, ok := core.NextWake(l.core)
	if !ok {
		t.Stop()
		return
	}
	t.Reset(time.Until(at))
}
