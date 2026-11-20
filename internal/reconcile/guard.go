package reconcile

import (
	"context"
	"net/netip"

	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

// Adder is the part of a Backend that a DNS report uses. Several reports
// use it at the same time. Adding entries never makes a table block less,
// so no report can make the check of another report wrong.
type Adder interface {
	// LoadedID returns the ID of the loaded ruleset, or "" when none is
	// loaded. It is the cheap part of Read: the daemon calls it for every
	// report that matches a policy.
	LoadedID(ctx context.Context) (string, error)
	// AddEntries adds entries to the table of a policy. It creates the
	// table when it is missing.
	AddEntries(ctx context.Context, table policy.Name, entries []netip.Prefix) error
}

// Guard gives the Backend to reports and to convergences. Reports get
// shared use of the Adder part. A convergence gets exclusive use of the
// whole Backend. Build one with NewGuard.
//
// The epoch counts the calls of Load, RemoveEntries, and DropTable. A
// call that fails counts too: it can have changed the kernel. These are
// the calls that can make an address that a report checked go out of a
// table, or replace the ruleset that a report checked. A report that
// finds the epoch of its gate inside its shared section thus knows that
// no such call came between the convergence of the gate and its check.
//
// The Guard counts the calls itself. A convergence cannot forget to
// tell it about a write.
//
// The lock is made of channels, not of a sync.RWMutex: a goroutine that
// waits on a channel is durably blocked in a testing/synctest bubble,
// and one that waits on a mutex is not. A report that sleeps in its
// shared section would else stop the fake clock while a convergence
// waits. As sync.RWMutex does, a waiting Exclusive call stops new
// Shared calls, so the reports cannot starve a convergence.
type Guard struct {
	b Backend
	// turn is held by an Exclusive call from its start to its end. Each
	// Shared call passes it first.
	turn chan struct{}
	// held is held by the Exclusive call that runs, or by the Shared
	// calls that run, as a group.
	held chan struct{}
	// mu guards readers.
	mu      chan struct{}
	readers int
	epoch   uint64 // written only while an Exclusive call holds held
}

// NewGuard returns a Guard for b with epoch 0. Every use of b must then
// go through the Guard.
func NewGuard(b Backend) *Guard {
	return &Guard{b: b, turn: make(chan struct{}, 1), held: make(chan struct{}, 1), mu: make(chan struct{}, 1)}
}

// Shared calls f with the Adder part of the Backend. Other calls of
// Shared run at the same time. No call of Exclusive runs while f runs.
// When ctx ends before f can start, Shared returns ctx.Err() and does
// not call f: a report does not wait for a slow convergence after its
// caller left.
func (g *Guard) Shared(ctx context.Context, f func(Adder) error) error {
	select {
	case g.turn <- struct{}{}:
		<-g.turn
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case g.mu <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	if g.readers == 0 {
		select {
		case g.held <- struct{}{}:
		case <-ctx.Done():
			<-g.mu
			return ctx.Err()
		}
	}
	g.readers++
	<-g.mu
	defer func() {
		g.mu <- struct{}{}
		g.readers--
		if g.readers == 0 {
			<-g.held
		}
		<-g.mu
	}()
	return f(g.b)
}

// Exclusive calls f with the Backend. No other call of Shared or
// Exclusive runs while f runs. It returns the epoch after f.
//
// The Backend that f gets is valid only until f returns. A use after
// that panics.
func (g *Guard) Exclusive(f func(Backend)) uint64 {
	g.turn <- struct{}{}
	g.held <- struct{}{}
	defer func() {
		<-g.held
		<-g.turn
	}()
	w := &counted{g: g}
	defer func() { w.g = nil }()
	f(w)
	return g.epoch
}

// counted is the Backend of one Exclusive call. It moves the epoch
// before each call that can remove an entry or replace the ruleset.
type counted struct {
	g *Guard // nil after the Exclusive call returned
}

func (c *counted) backend() Backend {
	if c.g == nil {
		panic("reconcile: Backend used after Guard.Exclusive returned")
	}
	return c.g.b
}

func (c *counted) write() Backend {
	b := c.backend()
	c.g.epoch++
	return b
}

func (c *counted) Read(ctx context.Context) (BackendState, error) {
	return c.backend().Read(ctx)
}

func (c *counted) LoadedID(ctx context.Context) (string, error) {
	return c.backend().LoadedID(ctx)
}

func (c *counted) AddEntries(ctx context.Context, table policy.Name, entries []netip.Prefix) error {
	return c.backend().AddEntries(ctx, table, entries)
}

func (c *counted) Load(ctx context.Context, rs Ruleset) error {
	return c.write().Load(ctx, rs)
}

func (c *counted) RemoveEntries(ctx context.Context, table policy.Name, entries []netip.Prefix) error {
	return c.write().RemoveEntries(ctx, table, entries)
}

func (c *counted) DropTable(ctx context.Context, table policy.Name) error {
	return c.write().DropTable(ctx, table)
}
