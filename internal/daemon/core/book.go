package core

import (
	"fmt"
	"slices"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/addrstore"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
)

// Book is the state of the address book of a configured daemon: exactly
// one of BookLoading, BookUnloadable, BookAdopting, and BookLoaded. The
// book itself is not in State: the shell holds it exactly while the
// state is BookAdopting or BookLoaded, and Step sees only its facts. The
// shell opens the book only for OpenBook, and closes it only when the
// daemon stops.
//
//sumtype:decl
type Book interface{ isBook() }

// BookLoading: no load of the book was tried yet.
type BookLoading struct{}

// BookUnloadable: the last load of the book failed with Err. Each pass
// tries the load again. The convergence is add-only, and no report gets
// an ack.
type BookUnloadable struct{ Err error }

// BookAdopting: the shell holds the open book, but the book can miss a
// lease that an earlier run acknowledged, and no adoption ended well
// yet (see applyBookOpened). Err is the error of the last adoption, or
// nil while the first one runs. Each pass tries the adoption again. The
// convergence is add-only, no report gets an ack, and the book does not
// expire: an expiry before the adoption could remove an entry that the
// adoption would keep.
type BookAdopting struct {
	// Damage is the damage that the open found, or nil.
	Damage error
	Err    error
}

// BookLoaded: the shell holds the open book, and the book holds each
// lease that an earlier run acknowledged.
type BookLoaded struct {
	Facts addrstore.BookFacts
	// Damage is the damage that the open found (see
	// addrstore.Store.Damage), or nil.
	Damage error
	// expired is the time of the last ExpireBook. An expiry at or before
	// it is not due again: the facts after that expire have the next one.
	expired time.Time
}

func (BookLoading) isBook()    {}
func (BookUnloadable) isBook() {}
func (BookAdopting) isBook()   {}
func (BookLoaded) isBook()     {}

// expiry returns the time of the next expire, and reports whether one is
// due at all.
func (b BookLoaded) expiry() (time.Time, bool) {
	next := b.Facts.NextExpiry
	return next, !next.IsZero() && next.After(b.expired)
}

// OpenBook opens the book with the retain. Its result is a BookOpened.
type OpenBook struct{ Retain time.Duration }

// AdoptBook adopts the learned-looking kernel entries of the policies
// that the book does not hold, and commits them. The host addresses of
// a good host file read are not adopted: they leave the tables with
// their host entries. Its result is a BookAdopted. After a failure, the
// book stays open: a failed write changes nothing in it.
type AdoptBook struct{ Policies []policy.Policy }

// ExpireBook removes the entries of the book that expired at At. Its
// result is a BookExpired.
type ExpireBook struct{ At time.Time }

// PruneBook removes the entries of each policy that is not in Keep. Its
// result is a BookChanged.
type PruneBook struct{ Keep []policy.Name }

func (OpenBook) isEffect()   {}
func (OpenBook) isSync()     {}
func (AdoptBook) isEffect()  {}
func (AdoptBook) isSync()    {}
func (ExpireBook) isEffect() {}
func (ExpireBook) isSync()   {}
func (PruneBook) isEffect()  {}
func (PruneBook) isSync()    {}

// BookOpened is the result of OpenBook. With a nil Err, the shell holds
// the open book, and the other fields tell what the open found (see
// addrstore.Store.Damage, Torn, and Fresh).
type BookOpened struct {
	At          time.Time
	Facts       addrstore.BookFacts
	Damage      error
	Torn, Fresh bool
	Err         error
}

// BookAdopted is the result of AdoptBook.
type BookAdopted struct {
	At    time.Time
	Facts addrstore.BookFacts
	Err   error
}

// BookExpired is the result of ExpireBook: Removed entries left the
// book. A removal is final also when the delete of a segment fails, so
// the result has no error: the next start removes the segment from disk.
type BookExpired struct {
	At      time.Time
	Removed int
	Facts   addrstore.BookFacts
}

// BookChanged gives the facts of the book after a write that is not a
// book effect of Step: a commit of the report path, or a prune.
type BookChanged struct {
	At    time.Time
	Facts addrstore.BookFacts
}

func (e BookOpened) at() time.Time  { return e.At }
func (e BookAdopted) at() time.Time { return e.At }
func (e BookExpired) at() time.Time { return e.At }
func (e BookChanged) at() time.Time { return e.At }

// loadedBook returns the book of a configured state when it is loaded.
func (s State) loadedBook() (BookLoaded, bool) {
	c, ok := s.Config().(Configured)
	if !ok {
		return BookLoaded{}, false
	}
	b, ok := c.Book.(BookLoaded)
	return b, ok
}

// withBook returns s with the book state b. It changes nothing in a
// state without a configuration.
func (s State) withBook(b Book) State {
	if c, ok := s.Config().(Configured); ok {
		c.Book = b
		s.config = c
	}
	return s
}

// setFacts takes the new facts of a loaded book, and reports whether the
// book is loaded.
func (s State) setFacts(f addrstore.BookFacts) (State, bool) {
	b, ok := s.loadedBook()
	if ok {
		b.Facts = f
		s = s.withBook(b)
	}
	return s, ok
}

// wantBook opens the book of a configured state when the shell does not
// hold it, and adopts again when an adoption is still owed.
func (s State) wantBook(out []Effect) (State, []Effect) {
	c, ok := s.Config().(Configured)
	if !ok {
		return s, out
	}
	switch c.Book.(type) {
	case BookLoading, BookUnloadable:
		return s, append(out, OpenBook{Retain: s.retain})
	case BookAdopting:
		return s, append(out, AdoptBook{Policies: c.Active.Config.Policies})
	case BookLoaded:
	}
	return s, out
}

// applyBookOpened takes the result of the open. A book that can miss a
// lease that an earlier run acknowledged makes the shell adopt the
// learned-looking entries of the kernel tables that the book does not
// hold, and commit them first: a book with damage, a torn book, and a
// fresh book without an address of a configured policy. Those addresses
// then stay blocked for one retain period instead of being unblocked. A
// book that this version wrote holds each acknowledged lease, because
// each lease is durable before its ack; an adoption would only keep the
// entries that the tables hold without a lease, such as the host
// addresses of a host file entry that went away. A fresh book with an
// address of a configured policy comes from the JSON snapshot of an
// earlier version, which also held each acknowledged address.
//
// The test of a fresh book looks at the configured policies only, so it
// also adopts when the snapshot holds addresses only of policies that
// the configuration removed. Adoption reads every table, also the table
// of a removed policy: its removal may not be installed yet, and a
// revert must find its addresses. The convergence prunes them after the
// install. It fails closed: adoption adds entries that the tables
// already hold, and each one expires after one retain period. Entries
// that expired while the daemon was down leave the book after the open.
func (s State) applyBookOpened(ev BookOpened, out []Effect) (State, []Effect) {
	c, ok := s.Config().(Configured)
	if !ok {
		return s, out
	}
	if ev.Err != nil {
		return s.withBook(BookUnloadable{Err: fmt.Errorf("loading the address book: %w", ev.Err)}), out
	}
	hasConfigured := slices.ContainsFunc(c.Active.Config.Policies, func(p policy.Policy) bool { return ev.Facts.Counts[p.Name] > 0 })
	if ev.Damage != nil || ev.Torn || ev.Fresh && !hasConfigured {
		return s.withBook(BookAdopting{Damage: ev.Damage}), append(out, AdoptBook{Policies: c.Active.Config.Policies})
	}
	return s.load(ev.Facts, ev.Damage, out)
}

// applyBookAdopted takes the result of the adoption. After a failure the
// adoption is still owed: the open can have repaired the book on disk,
// so a later open would not report what made the adoption owed.
func (s State) applyBookAdopted(ev BookAdopted, out []Effect) (State, []Effect) {
	c, ok := s.Config().(Configured)
	if !ok {
		return s, out
	}
	b, ok := c.Book.(BookAdopting)
	if !ok {
		return s, out
	}
	if ev.Err != nil {
		b.Err = ev.Err
		return s.withBook(b), out
	}
	return s.load(ev.Facts, b.Damage, out)
}

// load makes the book loaded, and removes the entries that expired while
// the daemon was down. That expire is the first one of the book, so no
// timer of the book fires before it.
func (s State) load(f addrstore.BookFacts, damage error, out []Effect) (State, []Effect) {
	return s.withBook(BookLoaded{Facts: f, Damage: damage, expired: s.now}), append(out, ExpireBook{At: s.now})
}

// bookProblem returns the Problem of a book that the open found damaged.
// The daemon adopted the kernel entries, but a lease that only a
// suspended VM still holds can be lost. The Problem does not void the
// enforcement, and it stays while this book is open: the damage stays in
// the book until its segment expires.
func bookProblem(b BookLoaded) (reconcile.Problem, bool) {
	if b.Damage == nil {
		return reconcile.Problem{}, false
	}
	places := []error{b.Damage}
	if j, ok := b.Damage.(interface{ Unwrap() []error }); ok {
		places = j.Unwrap()
	}
	return reconcile.Problem{Text: fmt.Sprintf(
		"the address book is damaged (places: %d); the kernel entries were adopted, and a lease outside them can be lost; first: %v",
		len(places), places[0])}, true
}
