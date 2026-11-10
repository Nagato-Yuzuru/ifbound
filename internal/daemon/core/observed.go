package core

import "time"

// ReqID identifies one read that Step started. Its result carries it
// back, so that Step can refuse the result of a read that is not the
// current one.
type ReqID uint64

// Observed is what Step knows of one external input that the shell reads
// outside the loop: the last good sample, the failure after it, the read
// in flight, and one pending read. At most one read is in flight. A
// trigger during the flight does not start a second read: it asks for
// one more read after the flight ends.
//
// The zero Observed has no sample and no read. Each method returns a new
// value and never changes the old one.
type Observed[T any] struct {
	last    *Sample[T]
	failure *Failure
	flight  *Flight
	// again is true when a trigger came during the flight.
	again bool
	// late is true when the last read that ended was at or after its
	// deadline.
	late bool
}

// Sample is the value of the last good read.
type Sample[T any] struct {
	Value T
	At    time.Time
}

// Failure is the series of failed reads after the last good sample.
type Failure struct {
	Err   error     // of the last failed read
	Since time.Time // the end of the first failed read of the series
	At    time.Time // the end of the last failed read
	Count int       // failed reads in a row
}

// Flight is the read in flight.
type Flight struct {
	ID       ReqID
	Deadline time.Time
}

// Start starts the read id with a budget, and reports true. During a
// flight it starts nothing, asks for one more read after the flight, and
// reports false.
func (o Observed[T]) Start(id ReqID, now time.Time, budget time.Duration) (Observed[T], bool) {
	if o.flight != nil {
		o.again = true
		return o, false
	}
	o.flight = &Flight{ID: id, Deadline: now.Add(budget)}
	o.again = false
	return o, true
}

// Finish ends the read id with its value v, or with err. It reports
// false, and changes nothing, when id is not the read in flight. A good
// read makes a new sample and ends the failure series. A failed read
// keeps the last sample. The pending read stays for the caller to start.
func (o Observed[T]) Finish(id ReqID, v T, err error, now time.Time) (Observed[T], bool) {
	o, ok := o.Keep(id, now)
	if !ok {
		return o, false
	}
	if err != nil {
		f := Failure{Err: err, Since: now, At: now, Count: 1}
		if o.failure != nil {
			f.Since, f.Count = o.failure.Since, o.failure.Count+1
		}
		o.failure = &f
		return o, true
	}
	o.last = &Sample[T]{Value: v, At: now}
	o.failure = nil
	return o, true
}

// Keep ends the read id with no value and no error: the read gave nothing
// new. The last sample and the failure stay. It reports false, and
// changes nothing, when id is not the read in flight. The pending read
// stays for the caller to start.
func (o Observed[T]) Keep(id ReqID, now time.Time) (Observed[T], bool) {
	if o.flight == nil || o.flight.ID != id {
		return o, false
	}
	o.late = !now.Before(o.flight.Deadline)
	o.flight = nil
	return o, true
}

// Last returns the last good sample. It reports false before the first
// good read.
func (o Observed[T]) Last() (Sample[T], bool) {
	if o.last == nil {
		return Sample[T]{}, false
	}
	return *o.last, true
}

// Failing returns the failures after the last good sample. It reports
// false when the last read was good, or no read ended.
func (o Observed[T]) Failing() (Failure, bool) {
	if o.failure == nil {
		return Failure{}, false
	}
	return *o.failure, true
}

// InFlight returns the read in flight. It reports false when no read is
// in flight.
func (o Observed[T]) InFlight() (Flight, bool) {
	if o.flight == nil {
		return Flight{}, false
	}
	return *o.flight, true
}

// Again reports whether a trigger came during the last flight, and no
// read started after it.
func (o Observed[T]) Again() bool { return o.again }

// Overdue reports whether the read in flight is at or past its deadline
// at now.
func (o Observed[T]) Overdue(now time.Time) bool {
	return o.flight != nil && !now.Before(o.flight.Deadline)
}

// Late reports whether the last read that ended was at or past its
// deadline.
func (o Observed[T]) Late() bool { return o.late }
