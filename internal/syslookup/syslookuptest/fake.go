// Package syslookuptest provides a fake of syslookup.Resolver for tests.
package syslookuptest

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"sync"

	"github.com/Nagato-Yuzuru/ifbound/internal/syslookup"
)

// Fake gives, for each name, one of the outcomes that syslookup.Resolver
// can give: addresses, ErrNotFound, ErrUnavailable, or another failure.
// A name with no stored outcome gives syslookup.ErrNotFound. A done
// context gives an error that wraps ctx.Err(). Fake records each name
// that Resolve gets, and it matches names exactly. The zero value is
// ready to use, and the methods are safe for concurrent use.
type Fake struct {
	mu       sync.Mutex
	outcomes map[string]outcome
	names    []string
}

// outcome holds either a non-empty address list or an error.
type outcome struct {
	addrs []netip.Addr
	err   error
}

// Found makes Resolve give addrs for name, in the form of
// syslookup.Normalize. It panics when addrs is empty: Resolve never
// gives an empty success.
func (f *Fake) Found(name string, addrs ...netip.Addr) {
	if len(addrs) == 0 {
		panic("syslookuptest: Found needs at least one address")
	}
	f.set(name, outcome{addrs: syslookup.Normalize(addrs)})
}

// Unavailable makes Resolve give syslookup.ErrUnavailable for name.
func (f *Fake) Unavailable(name string) {
	f.set(name, outcome{err: fmt.Errorf("resolve %s: %w", name, syslookup.ErrUnavailable)})
}

// Fail makes Resolve give an error that wraps err for name. It panics
// when err is nil.
func (f *Fake) Fail(name string, err error) {
	if err == nil {
		panic("syslookuptest: Fail needs an error")
	}
	f.set(name, outcome{err: fmt.Errorf("resolve %s: %w", name, err)})
}

func (f *Fake) set(name string, o outcome) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.outcomes == nil {
		f.outcomes = make(map[string]outcome)
	}
	f.outcomes[name] = o
}

// Resolve records name and gives its stored outcome.
func (f *Fake) Resolve(ctx context.Context, name string) ([]netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.names = append(f.names, name)
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("resolve %s: %w", name, err)
	}
	o, ok := f.outcomes[name]
	if !ok {
		return nil, fmt.Errorf("resolve %s: %w", name, syslookup.ErrNotFound)
	}
	if o.err != nil {
		return nil, o.err
	}
	return slices.Clone(o.addrs), nil
}

// Names returns the names that Resolve got, in call order.
func (f *Fake) Names() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.names)
}
