package reconcile

import (
	"context"
	"fmt"
	"net/netip"
	"sync"

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
	// seen guards expected and known. Exclusive writes them, and so does
	// Changed in a shared section. The lock is held only for the
	// compare, never across a call of the Backend.
	seen sync.Mutex
	// expected is the last digest that ifbound read or wrote, when known
	// is true.
	expected Digest
	known    bool
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
	if err := g.lockShared(ctx); err != nil {
		return err
	}
	defer g.unlockShared()
	return f(g.b)
}

// lockShared starts a shared section. It returns ctx.Err() when ctx ends
// before the section can start.
func (g *Guard) lockShared(ctx context.Context) error {
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
	return nil
}

// unlockShared ends a shared section that lockShared started.
func (g *Guard) unlockShared() {
	g.mu <- struct{}{}
	g.readers--
	if g.readers == 0 {
		<-g.held
	}
	<-g.mu
}

// Exclusive calls f with the Backend. No other call of Shared,
// Exclusive, or Changed runs while f runs. It returns the epoch after f.
//
// After each write of f (Load, RemoveEntries, DropTable), and before f
// goes on, the Backend of f reads Backend.Digest and keeps it as the
// expected digest (see Changed). So the writes of ifbound never look like
// a change to the watcher. When the read fails, the expected digest is
// unknown, and the next call of Changed reports a change. A call that
// writes nothing keeps the expected digest.
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

// Changed reads Backend.Digest in a shared section and compares it with
// the expected digest. It reports true when they differ, or when the
// expected digest is unknown. It then keeps the new digest as the
// expected one, so it reports each change once. It is for a watcher that
// finds the changes that another program makes.
//
// The expected digest is the one that the Guard read after the last
// write of ifbound, or the one that the last call of Changed read.
// Changed never runs in an Exclusive section, so a write of ifbound never
// looks like a change. The cost is a short gap: when another program
// changes the kernel during a write of ifbound, after the last step of
// the write that reads the state, the digest after the write includes
// that change, and Changed does not report it. The next convergence (the
// self-heal) reads the state and finds it.
//
// When ctx ends before the shared section can start, Changed returns
// ctx.Err(). When the read fails, it returns the error, and the expected
// digest does not change.
func (g *Guard) Changed(ctx context.Context) (bool, error) {
	if err := g.lockShared(ctx); err != nil {
		return false, err
	}
	defer g.unlockShared()
	d, err := g.b.Digest(ctx)
	if err != nil {
		return false, fmt.Errorf("reading the digest: %w", err)
	}
	g.seen.Lock()
	defer g.seen.Unlock()
	changed := !g.known || d != g.expected
	g.expected, g.known = d, true
	return changed, nil
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

func (c *counted) Digest(ctx context.Context) (Digest, error) {
	return c.backend().Digest(ctx)
}

func (c *counted) LoadedID(ctx context.Context) (string, error) {
	return c.backend().LoadedID(ctx)
}

func (c *counted) AddEntries(ctx context.Context, table policy.Name, entries []netip.Prefix) error {
	return c.backend().AddEntries(ctx, table, entries)
}

func (c *counted) Load(ctx context.Context, rs Ruleset) error {
	defer c.expect(ctx)
	return c.write().Load(ctx, rs)
}

func (c *counted) RemoveEntries(ctx context.Context, table policy.Name, entries []netip.Prefix) error {
	defer c.expect(ctx)
	return c.write().RemoveEntries(ctx, table, entries)
}

func (c *counted) DropTable(ctx context.Context, table policy.Name) error {
	defer c.expect(ctx)
	return c.write().DropTable(ctx, table)
}

// expect reads the digest after a write and keeps it as the expected
// digest. It reads right after the write, not at the end of the
// Exclusive call: a change by another program after the write then
// shows to Changed, also while the convergence goes on. A write that
// failed can have changed the kernel too, so expect reads after it as
// well.
func (c *counted) expect(ctx context.Context) {
	d, err := c.backend().Digest(ctx)
	c.g.seen.Lock()
	c.g.expected, c.g.known = d, err == nil
	c.g.seen.Unlock()
}
