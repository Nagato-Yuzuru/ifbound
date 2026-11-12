package core

import (
	"errors"
	"testing"
	"time"
)

var (
	t0      = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	budget  = 5 * time.Second
	errRead = errors.New("read failed")
)

func at(d time.Duration) time.Time { return t0.Add(d) }

func TestObservedStartsOneFlightAndKeepsOnePendingRead(t *testing.T) {
	var o Observed[int]
	o, started := o.Start(1, at(0), budget)
	if !started {
		t.Fatal("Start on an idle input did not start a read")
	}
	f, ok := o.InFlight()
	if !ok || f.ID != 1 || !f.Deadline.Equal(at(budget)) {
		t.Fatalf("InFlight = %+v, %v; want ID 1 with the deadline %v", f, ok, at(budget))
	}
	if o.Again() {
		t.Error("Again after the first Start, want false")
	}
	for range 3 {
		o, started = o.Start(2, at(time.Second), budget)
		if started {
			t.Fatal("Start during a flight started a second read")
		}
	}
	if f, _ := o.InFlight(); f.ID != 1 {
		t.Errorf("flight ID = %d after a Start during the flight, want 1", f.ID)
	}
	if !o.Again() {
		t.Error("Again = false after a Start during the flight, want true")
	}

	o, ok = o.Finish(1, 7, nil, at(2*time.Second))
	if !ok {
		t.Fatal("Finish of the flight was refused")
	}
	if !o.Again() {
		t.Error("Finish cleared the pending read")
	}
	o, started = o.Start(3, at(2*time.Second), budget)
	if !started || o.Again() {
		t.Errorf("Start after Finish: started %v, Again %v; want a new read and no pending read", started, o.Again())
	}
}

func TestObservedFinishKeepsTheLastGoodSampleAndCountsFailures(t *testing.T) {
	var o Observed[int]
	if _, ok := o.Last(); ok {
		t.Error("Last on the zero Observed has a sample")
	}
	if _, ok := o.Failing(); ok {
		t.Error("Failing on the zero Observed has a failure")
	}

	o = finish(t, o, 1, 10, nil, at(time.Second))
	wantSample(t, o, 10, at(time.Second))
	if _, ok := o.Failing(); ok {
		t.Error("Failing after a good read")
	}

	o = finish(t, o, 2, 0, errRead, at(10*time.Second))
	o = finish(t, o, 3, 0, errRead, at(20*time.Second))
	wantSample(t, o, 10, at(time.Second))
	f, ok := o.Failing()
	if !ok || f.Count != 2 || !f.Since.Equal(at(10*time.Second)) || !f.At.Equal(at(20*time.Second)) || !errors.Is(f.Err, errRead) {
		t.Errorf("Failing = %+v, %v; want 2 failures since %v, the last at %v", f, ok, at(10*time.Second), at(20*time.Second))
	}

	o = finish(t, o, 4, 11, nil, at(30*time.Second))
	wantSample(t, o, 11, at(30*time.Second))
	if f, ok := o.Failing(); ok {
		t.Errorf("Failing = %+v after a good read, want none", f)
	}
	if _, ok := o.InFlight(); ok {
		t.Error("a flight is left after Finish")
	}
}

func TestObservedIgnoresAStaleResult(t *testing.T) {
	var o Observed[int]
	if _, ok := o.Finish(1, 5, nil, at(0)); ok {
		t.Error("Finish without a flight was taken")
	}
	o, _ = o.Start(2, at(0), budget)
	before := o
	got, ok := o.Finish(1, 5, nil, at(time.Second))
	if ok {
		t.Error("Finish with the ID of an older read was taken")
	}
	if got != before {
		t.Errorf("a stale result changed the Observed: %+v, want %+v", got, before)
	}
}

func TestObservedOverdueFromTheDeadline(t *testing.T) {
	var o Observed[int]
	if o.Overdue(at(time.Hour)) {
		t.Error("Overdue without a flight")
	}
	o, _ = o.Start(1, at(0), budget)
	for _, c := range []struct {
		now  time.Time
		want bool
	}{
		{at(0), false},
		{at(budget - time.Nanosecond), false},
		{at(budget), true},
		{at(budget + time.Hour), true},
	} {
		if got := o.Overdue(c.now); got != c.want {
			t.Errorf("Overdue(%v) = %v, want %v", c.now.Sub(t0), got, c.want)
		}
	}
}

func TestObservedLateWhenTheReadEndsAtOrAfterItsDeadline(t *testing.T) {
	for _, c := range []struct {
		name string
		took time.Duration
		err  error
		want bool
	}{
		{"on time", budget - time.Nanosecond, nil, false},
		{"at the deadline", budget, nil, true},
		{"after the deadline", 2 * budget, nil, true},
		{"failed after the deadline", 2 * budget, errRead, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			var o Observed[int]
			o, _ = o.Start(1, at(0), budget)
			o = finish(t, o, 1, 1, c.err, at(c.took))
			if o.Late() != c.want {
				t.Errorf("Late = %v, want %v", o.Late(), c.want)
			}
		})
	}

	// A read on time after a late one clears Late.
	var o Observed[int]
	o, _ = o.Start(1, at(0), budget)
	o = finish(t, o, 1, 1, nil, at(2*budget))
	o, _ = o.Start(2, at(2*budget), budget)
	if !o.Late() {
		t.Error("Start cleared Late of the last read")
	}
	o = finish(t, o, 2, 1, nil, at(2*budget+time.Second))
	if o.Late() {
		t.Error("Late after a read on time")
	}
}

// finish starts the read id when no read is in flight, and finishes it.
func finish(t *testing.T, o Observed[int], id ReqID, v int, err error, now time.Time) Observed[int] {
	t.Helper()
	if _, ok := o.InFlight(); !ok {
		o, _ = o.Start(id, now, budget)
	}
	o, ok := o.Finish(id, v, err, now)
	if !ok {
		t.Fatalf("Finish(%d) was refused", id)
	}
	return o
}

func wantSample(t *testing.T, o Observed[int], v int, when time.Time) {
	t.Helper()
	s, ok := o.Last()
	if !ok || s.Value != v || !s.At.Equal(when) {
		t.Errorf("Last = %+v, %v; want %d at %v", s, ok, v, when)
	}
}
