package daemon

import (
	"context"
	"fmt"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/addrstore"
	"github.com/Nagato-Yuzuru/ifbound/internal/blockable"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
)

// addrBook is the address book as the loop uses it. *addrstore.Store
// implements it; a test wraps it to fail its writes.
type addrBook interface {
	Addrs(name policy.Name) []blockable.Addr
	Touch(names []policy.Name, addrs []blockable.Addr, ttl time.Duration, at time.Time) (addrstore.Pending, error)
	Commit(ctx context.Context, p addrstore.Pending) error
	Apply(ctx context.Context, op addrstore.Op) (int, error)
	Facts() <-chan addrstore.BookFacts
	Damage() error
	Fresh() bool
	Torn() bool
	Close() error
}

// emptyBook is the address source of an add-only convergence, while the
// address book does not open. It has no address.
type emptyBook struct{}

func (emptyBook) Addrs(policy.Name) []blockable.Addr { return nil }

// openBookFunc opens the address book at path, as addrstore.Open does.
type openBookFunc func(path, legacy string, retain time.Duration) (addrBook, error)

func openStore(path, legacy string, retain time.Duration) (addrBook, error) {
	s, err := addrstore.Open(path, legacy, retain)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// bookFacts returns the latest facts of b. The loop calls the book
// synchronously, and the book sends its facts before a call returns, so
// the value is never older than the last call.
func (l *loop) bookFacts(b addrBook) addrstore.BookFacts {
	select {
	case f := <-b.Facts():
		l.facts = f
	default:
	}
	return l.facts
}

// closeBook closes the book. Each acknowledged lease is already durable,
// so the close has nothing to write.
func (l *loop) closeBook() {
	m, ok := l.mode.(runningMode)
	if !ok {
		return
	}
	_ = m.book.Close() //nolint:errcheck // nothing is left to write, so a close error loses nothing
}

// bookProblem returns the Problem of a book that Open found damaged. The
// daemon adopted the kernel entries, but a lease that only a suspended
// VM still holds can be lost. The Problem does not void the enforcement,
// and it stays while this book is open: the damage stays in the book
// until its segment expires.
func bookProblem(b addrBook) (reconcile.Problem, bool) {
	if b == nil {
		return reconcile.Problem{}, false
	}
	err := b.Damage()
	if err == nil {
		return reconcile.Problem{}, false
	}
	places := []error{err}
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		places = j.Unwrap()
	}
	return reconcile.Problem{Text: fmt.Sprintf(
		"the address book is damaged (places: %d); the kernel entries were adopted, and a lease outside them can be lost; first: %v",
		len(places), places[0])}, true
}
