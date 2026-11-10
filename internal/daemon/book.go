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

// closeBook writes the refreshes of the book that are only in memory, and
// closes the book. ctx can be done: the flush does not end with it.
func (l *loop) closeBook(ctx context.Context) {
	m, ok := l.mode.(runningMode)
	if !ok {
		return
	}
	// A failed flush loses at most the refreshes inside the save slack,
	// as a crash does; the persist rule allows it.
	_, _ = m.book.Apply(context.WithoutCancel(ctx), addrstore.Flush{}) //nolint:errcheck // see above
	_ = m.book.Close()                                                 //nolint:errcheck // the flush above is the last write; a close error loses nothing
}
