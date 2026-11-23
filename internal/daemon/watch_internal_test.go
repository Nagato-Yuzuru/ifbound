package daemon

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/daemon/core"
)

// These tests check the poll times of the watcher. The bubble clock
// makes them exact.

// polls records the time of each poll from the start of the test, and
// answers each poll with the result of answer for its number from 1.
type polls struct {
	start  time.Time
	answer func(n int) (bool, error)
	mu     sync.Mutex
	at     []time.Duration
}

func (p *polls) changed(context.Context) (bool, error) {
	p.mu.Lock()
	p.at = append(p.at, time.Since(p.start))
	n := len(p.at)
	p.mu.Unlock()
	if p.answer == nil {
		return false, nil
	}
	return p.answer(n)
}

func (p *polls) times() []time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.at)
}

// runWatcher runs a watcher on p until stop. The events of the watcher
// go to got.
func runWatcher(p *polls) (w *watcher, got func() []core.Event, stop func()) {
	w = newWatcher(p.changed)
	ctx, cancel := context.WithCancel(context.Background())
	var mu sync.Mutex
	var events []core.Event
	var wg sync.WaitGroup
	wg.Go(func() { w.run(ctx) })
	wg.Go(func() {
		for {
			select {
			case ev := <-w.events:
				mu.Lock()
				events = append(events, ev)
				mu.Unlock()
			case <-ctx.Done():
				return
			}
		}
	})
	got = func() []core.Event {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(events)
	}
	return w, got, func() { cancel(); wg.Wait() }
}

// sleepUntil sleeps until the time d after start.
func sleepUntil(start time.Time, d time.Duration) {
	time.Sleep(time.Until(start.Add(d)))
}

// series returns the times from first to last, step apart.
func series(first, last, step time.Duration) []time.Duration {
	var out []time.Duration
	for d := first; d <= last; d += step {
		out = append(out, d)
	}
	return out
}

// The poll period is WatchPeriod. After an interface change it is
// WatchFastPeriod, until WatchFastFor after the last change. A second
// change in the fast window extends the window.
func TestWatcherPeriodFollowsInterfaceChanges(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := &polls{start: time.Now()}
		w, _, stop := runWatcher(p)
		const first, second = 3500 * time.Millisecond, 8050 * time.Millisecond
		sleepUntil(p.start, first)
		w.kick()
		sleepUntil(p.start, second)
		w.kick()
		sleepUntil(p.start, 25*time.Second)
		stop()

		// The kick at first moves the poll at 4 s to first+100ms. The
		// window ends at second+WatchFastFor = 18.05 s: the poll at 18 s
		// is in it, so the poll after it comes 100 ms later, and the
		// polls after that one come WatchPeriod apart.
		var want []time.Duration
		want = append(want, series(WatchPeriod, 3*WatchPeriod, WatchPeriod)...)
		want = append(want, series(first+WatchFastPeriod, 18100*time.Millisecond, WatchFastPeriod)...)
		want = append(want, series(18100*time.Millisecond+WatchPeriod, 25*time.Second, WatchPeriod)...)
		if got := p.times(); !slices.Equal(got, want) {
			t.Errorf("poll times =\n%v\nwant\n%v", got, want)
		}
	})
}

// Interface changes that come faster than WatchFastPeriod do not delay
// the polls.
func TestWatcherKicksDoNotStarveThePolls(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := &polls{start: time.Now()}
		w, _, stop := runWatcher(p)
		const kickEvery = 30 * time.Millisecond
		for range 40 {
			w.kick()
			time.Sleep(kickEvery)
		}
		// Not at the time of a poll: the stop and the poll would race.
		time.Sleep(WatchFastPeriod / 2)
		stop()
		want := series(WatchFastPeriod, 40*kickEvery, WatchFastPeriod)
		if got := p.times(); !slices.Equal(got, want) {
			t.Errorf("poll times = %v, want %v", got, want)
		}
	})
}

var errPoll = errors.New("ioctl failed")

// A failed poll sends WatchFailed each time. The first good poll after
// it sends WatchSucceeded. A poll that finds a change sends
// FirewallChanged.
func TestWatcherSendsPollResults(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := &polls{start: time.Now(), answer: func(n int) (bool, error) {
			switch n {
			case 2, 3:
				return false, errPoll
			case 5:
				return true, nil
			default:
				return false, nil
			}
		}}
		_, got, stop := runWatcher(p)
		sleepUntil(p.start, 5*WatchPeriod+WatchPeriod/2)
		stop()
		var kinds []string
		for _, ev := range got() {
			kinds = append(kinds, fmt.Sprintf("%T", ev))
		}
		want := []string{"core.WatchFailed", "core.WatchFailed", "core.WatchSucceeded", "core.FirewallChanged"}
		if !slices.Equal(kinds, want) {
			t.Errorf("events = %v, want %v", kinds, want)
		}
	})
}
