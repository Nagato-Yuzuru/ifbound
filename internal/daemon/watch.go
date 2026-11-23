package daemon

import (
	"context"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/daemon/core"
)

const (
	// WatchPeriod is the period of the poll that finds a change of the
	// firewall that another program made, such as a disabled pf or a new
	// main ruleset. pf sends no event for such a change, so the daemon
	// polls. A poll is three ioctl calls (see reconcile.Backend.Digest).
	// In a measurement in a guest, a period of 1 s cost about 1.3 idle
	// wakeups per second.
	WatchPeriod = 1 * time.Second
	// WatchFastPeriod is the period of the poll for WatchFastFor after
	// each interface change. VPN clients change pf when they connect and
	// disconnect, and these steps change the interfaces too. A fixed
	// period of 100 ms cost about 15.6 idle wakeups per second and 14.5
	// s of CPU time per hour in the same measurement, so the daemon polls
	// this fast only when a change of pf is likely.
	WatchFastPeriod = 100 * time.Millisecond
	// WatchFastFor is the time after the last interface change during
	// which the poll uses WatchFastPeriod.
	WatchFastFor = 10 * time.Second
)

// watcher polls for a change of the firewall that ifbound did not make,
// and sends the results to the loop as core events. Run starts one
// watcher and stops it before it returns.
type watcher struct {
	// changed is reconcile.Guard.Changed.
	changed func(context.Context) (bool, error)
	// kicks gets a value at each interface change. It has room for one:
	// changes that the watcher did not take yet merge into one.
	kicks chan struct{}
	// events carries the results of the polls to the loop.
	events chan core.Event
}

func newWatcher(changed func(context.Context) (bool, error)) *watcher {
	return &watcher{changed: changed, kicks: make(chan struct{}, 1), events: make(chan core.Event)}
}

// kick tells the watcher of an interface change. It never blocks.
func (w *watcher) kick() {
	select {
	case w.kicks <- struct{}{}:
	default:
	}
}

// run polls until ctx ends. The first poll comes WatchPeriod after the
// start. A poll that finds a change sends core.FirewallChanged. A failed
// poll sends core.WatchFailed, and the first good poll after it sends
// core.WatchSucceeded. A send waits for the loop, so no poll runs while
// the loop has not taken the last result.
//
// The period is WatchPeriod, and WatchFastPeriod until WatchFastFor
// after the last kick. A kick moves the next poll nearer, never farther
// away: interface changes that come faster than WatchFastPeriod do not
// stop the polls.
func (w *watcher) run(ctx context.Context) {
	next := time.Now().Add(WatchPeriod)
	t := time.NewTimer(WatchPeriod)
	defer t.Stop()
	var fastUntil time.Time
	failing := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.kicks:
			now := time.Now()
			fastUntil = now.Add(WatchFastFor)
			if soon := now.Add(WatchFastPeriod); next.After(soon) {
				next = soon
				t.Reset(WatchFastPeriod)
			}
			continue
		case <-t.C:
		}
		if !w.poll(ctx, &failing) {
			return
		}
		period := WatchPeriod
		if time.Now().Before(fastUntil) {
			period = WatchFastPeriod
		}
		next = time.Now().Add(period)
		t.Reset(period)
	}
}

// poll runs one poll and sends its results. failing is true after a
// failed poll, until a good one. It reports false when ctx ended.
func (w *watcher) poll(ctx context.Context, failing *bool) bool {
	changed, err := w.changed(ctx)
	if ctx.Err() != nil {
		return false
	}
	var out []core.Event
	switch {
	case err != nil:
		*failing = true
		out = append(out, core.WatchFailed{At: time.Now(), Err: err})
	case *failing:
		*failing = false
		out = append(out, core.WatchSucceeded{At: time.Now()})
	}
	if changed {
		out = append(out, core.FirewallChanged{At: time.Now()})
	}
	for _, ev := range out {
		select {
		case w.events <- ev:
		case <-ctx.Done():
			return false
		}
	}
	return true
}
