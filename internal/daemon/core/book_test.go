package core

import (
	"testing"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/addrstore"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

// openTorn steps a configured state through a pass start and the open
// of a torn book whose next expiry is at next.
func openTorn(t *testing.T, next time.Time) (State, addrstore.BookFacts) {
	t.Helper()
	s, _ := Step(New(t0, true), ConfigRead{At: t0, Config: scoped(nil, nil)})
	s, _ = Step(s, PassStarted{At: t0})
	f := addrstore.BookFacts{Retain: time.Hour, Counts: map[policy.Name]int{"web": 1}, NextExpiry: next}
	s, effects := Step(s, BookOpened{At: t0, Facts: f, Torn: true})
	if countOf[AdoptBook](effects) != 1 || countOf[ExpireBook](effects) != 0 {
		t.Fatalf("open of a torn book gave %v, want one AdoptBook and no ExpireBook", effects)
	}
	return s, f
}

func bookOf(s State) Book { return s.Config().(Configured).Book }

// The book does not expire before its adoption ends well: an expiry that
// was due at the open does not fire on the result of the adoption. A good
// adoption then expires the book exactly once.
func TestBookExpiresOnceAfterTheAdoption(t *testing.T) {
	for _, c := range []struct {
		name string
		next time.Time
	}{
		{"expiry due before the open", t0.Add(-time.Minute)},
		{"expiry after the open", t0.Add(time.Hour)},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, f := openTorn(t, c.next)
			failed, effects := Step(s, BookAdopted{At: t0.Add(time.Millisecond), Err: errLoad})
			if n := countOf[ExpireBook](effects); n != 0 {
				t.Errorf("failed adoption gave %v with the book %T, want no ExpireBook", effects, bookOf(failed))
			}
			if at, ok := NextWake(failed); ok && !at.After(t0) {
				t.Errorf("NextWake = %v after a failed adoption, want no wake for the book", at)
			}
			loaded, effects := Step(s, BookAdopted{At: t0, Facts: f})
			if n := countOf[ExpireBook](effects); n != 1 {
				t.Errorf("good adoption gave %v, want one ExpireBook", effects)
			}
			if _, ok := bookOf(loaded).(BookLoaded); !ok {
				t.Errorf("book after a good adoption = %T, want BookLoaded", bookOf(loaded))
			}
		})
	}
}

// A failed adoption keeps the adoption owed: the next pass adopts again
// with the open book, and does not open it again. An open again would
// find the book repaired, and would not adopt.
func TestFailedAdoptionIsRetriedOnTheNextPass(t *testing.T) {
	s, f := openTorn(t, time.Time{})
	s, _ = Step(s, BookAdopted{At: t0, Err: errLoad})
	if b, ok := bookOf(s).(BookAdopting); !ok || b.Err == nil {
		t.Fatalf("book after a failed adoption = %#v, want BookAdopting with the error", bookOf(s))
	}
	s, _ = Step(s, Converged{At: t0})
	at := t0.Add(SelfHealInterval)
	s, effects := Step(s, PassStarted{At: at})
	if countOf[AdoptBook](effects) != 1 || countOf[OpenBook](effects) != 0 {
		t.Fatalf("next pass gave %v, want one AdoptBook and no OpenBook", effects)
	}
	s, _ = Step(s, BookAdopted{At: at, Facts: f})
	if _, ok := bookOf(s).(BookLoaded); !ok {
		t.Errorf("book after the retry = %T, want BookLoaded", bookOf(s))
	}
}
