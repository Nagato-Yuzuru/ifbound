package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/addrstore"
	"github.com/Nagato-Yuzuru/ifbound/internal/blockable"
	"github.com/Nagato-Yuzuru/ifbound/internal/daemon/core"
	"github.com/Nagato-Yuzuru/ifbound/internal/logattr"
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

// latestFacts returns the latest facts of the open book. The loop calls
// the book synchronously, and the book sends its facts before a call
// returns, so the value is never older than the last call.
func (l *loop) latestFacts() addrstore.BookFacts {
	select {
	case f := <-l.book.Facts():
		l.facts = f
	default:
	}
	return l.facts
}

// openBookNow runs e. After a good open, the loop holds the book.
func (l *loop) openBookNow(ctx context.Context, e core.OpenBook) core.BookOpened {
	b, err := l.openBook(l.addrStore, l.snapshot, e.Retain)
	if err != nil {
		return core.BookOpened{At: time.Now(), Err: err}
	}
	if err := b.Damage(); err != nil {
		// The leases in the damaged places are lost; the adoption keeps
		// those that the tables hold.
		l.log.WarnContext(ctx, "address book damaged",
			slog.String(logattr.ErrorType, logattr.ErrorTypeSnapshot), slog.String(logattr.ExceptionMessage, err.Error()))
	}
	l.book = b
	return core.BookOpened{At: time.Now(), Facts: l.latestFacts(), Damage: b.Damage(), Torn: b.Torn(), Fresh: b.Fresh()}
}

// adoptBook runs e. After a good read of the host file, the host
// addresses are not adopted: the file is their source of truth, not the
// book. Before a good read, they are adopted. TTL 0: each entry gets a
// fresh retain period. After a failure, the book stays open: core owns
// its state, and the next pass adopts again.
func (l *loop) adoptBook(ctx context.Context, e core.AdoptBook) core.BookAdopted {
	found, err := l.rec.Adoptable(ctx, e.Policies)
	if err != nil {
		return core.BookAdopted{At: time.Now(), Err: fmt.Errorf("adopting kernel entries: %w", err)}
	}
	if a, ok := l.active(); ok {
		if _, read := l.core.HostFile(); read {
			hosts := l.hostAddrs(ctx, a)
			for name, addrs := range found {
				sorted := hosts[name]
				found[name] = slices.DeleteFunc(addrs, func(a blockable.Addr) bool {
					_, found := slices.BinarySearchFunc(sorted, a, blockable.Addr.Compare)
					return found
				})
			}
		}
	}
	if _, err := l.book.Apply(ctx, addrstore.Adopt{Found: found, At: time.Now()}); err != nil {
		return core.BookAdopted{At: time.Now(), Err: fmt.Errorf("saving adopted entries: %w", err)}
	}
	return core.BookAdopted{At: time.Now(), Facts: l.latestFacts()}
}

// expireBook runs e. A removal is final also when its delete fails, so a
// failed delete does not make the expiry come again at once; the next
// start removes the entries from disk.
func (l *loop) expireBook(ctx context.Context, e core.ExpireBook) core.BookExpired {
	n, _ := l.book.Apply(ctx, addrstore.Expire{At: e.At}) //nolint:errcheck // see above
	return core.BookExpired{At: time.Now(), Removed: n, Facts: l.latestFacts()}
}

// pruneBook runs e. A failed delete keeps the entries on disk only; the
// next Prune after a start removes them again.
func (l *loop) pruneBook(ctx context.Context, e core.PruneBook) core.BookChanged {
	_, _ = l.book.Apply(ctx, addrstore.Prune{Keep: e.Keep}) //nolint:errcheck // see above
	return core.BookChanged{At: time.Now(), Facts: l.latestFacts()}
}

// closeBook closes the open book when the daemon stops. Each
// acknowledged lease is already durable, so the close has nothing to
// write.
func (l *loop) closeBook() {
	if l.book == nil {
		return
	}
	_ = l.book.Close() //nolint:errcheck // nothing is left to write, so a close error loses nothing
	l.book = nil
}

// bookError returns the error that keeps the book from loading, or nil.
func bookError(b core.Book) error {
	switch b := b.(type) {
	case core.BookUnloadable:
		return b.Err
	case core.BookAdopting:
		return b.Err
	case core.BookLoading, core.BookLoaded:
	}
	return nil
}
