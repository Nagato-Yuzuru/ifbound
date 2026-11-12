package daemon

import (
	"context"
	"fmt"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/daemon/core"
)

// drive gives ev to core.Step and runs the effects that it returns, in
// their order. A sync effect runs on the loop before drive returns, so it
// ends before the loop takes the next outside event.
//
// Each case gives the effect to the function of its sub sum, so the
// compiler checks the sub sum of each effect. gochecksumtype does not
// take a sub sum as a case, so the switch names each effect.
func (l *loop) drive(ctx context.Context, ev core.Event) {
	var effects []core.Effect
	l.core, effects = core.Step(l.core, ev)
	for _, e := range effects {
		switch e := e.(type) {
		case core.Converge:
			l.runSync(ctx, e)
		case core.ReadAccounts:
			l.runAsync(ctx, e)
		case core.AccountsOverdue:
			l.emit(ctx, e)
		case core.AccountLookupsFailed:
			l.emit(ctx, e)
		default:
			panic(fmt.Sprintf("daemon: unknown effect %T", e))
		}
	}
}

func (l *loop) runSync(ctx context.Context, e core.SyncEffect) {
	switch e := e.(type) {
	case core.Converge:
		_ = l.reconcile(ctx, e.Trigger) //nolint:errcheck // the phase holds the outcome
	default:
		panic(fmt.Sprintf("daemon: unknown sync effect %T", e))
	}
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
