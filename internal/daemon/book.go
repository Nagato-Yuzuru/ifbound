package daemon

import (
	"context"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/addrstore"
	"github.com/Nagato-Yuzuru/ifbound/internal/blockable"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
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
