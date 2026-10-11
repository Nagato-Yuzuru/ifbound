// Package reconciletest provides in-memory fakes of the reconcile platform
// interfaces.
//
// A World holds the fake kernel and resolver state. It outlives a daemon,
// as the real kernel state outlives a crashed process, so a test can stop
// one daemon and start the next on the same World. Hooks around each
// write let a test inject a fault at write N and check an invariant after
// every write.
package reconciletest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"sync"

	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
)

// ErrInjected is a fault that a test injects. The fakes never return it
// on their own.
var ErrInjected = errors.New("reconciletest: injected fault")

// World is the fake kernel and resolver state. It is safe for concurrent
// use: the daemon goroutine writes while the test goroutine reads.
type World struct {
	mu       sync.Mutex
	ruleset  reconcile.Ruleset
	tables   map[policy.Name]map[netip.Prefix]struct{}
	resolver map[policy.Domain]netip.AddrPort
	// applied are the resolver entries that the fake system uses now.
	applied map[policy.Domain]netip.AddrPort
	// pending holds the entries that a Write changed since the system
	// applied the entries last.
	pending  map[policy.Domain]struct{}
	delay    bool
	bproblem []reconcile.Problem
	rproblem []reconcile.Problem
	writes   int
	before   func(n int) error
	after    func()
}

// NewWorld returns an empty World: no ruleset, no tables, no resolver
// entries.
func NewWorld() *World {
	return &World{
		tables:   make(map[policy.Name]map[netip.Prefix]struct{}),
		resolver: make(map[policy.Domain]netip.AddrPort),
		applied:  make(map[policy.Domain]netip.AddrPort),
		pending:  make(map[policy.Domain]struct{}),
	}
}

// Backend returns the Backend face of the World.
func (w *World) Backend() *Backend { return &Backend{w: w} }

// Resolver returns the SysResolver face of the World.
func (w *World) Resolver() *Resolver { return &Resolver{w: w} }

// SetBeforeWrite sets a hook that runs before each write, without the
// World lock. N counts every write call on the World from 1. A non-nil
// error fails the write, and the World does not change. The hook may
// block.
func (w *World) SetBeforeWrite(f func(n int) error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.before = f
}

// SetAfterWrite sets a hook that runs after each write that changed the
// World, without the World lock.
func (w *World) SetAfterWrite(f func()) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.after = f
}

// SetProblems sets the external problems that the Backend and the
// Resolver report.
func (w *World) SetProblems(backend, resolver []reconcile.Problem) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.bproblem, w.rproblem = slices.Clone(backend), slices.Clone(resolver)
}

// SetResolverDelay selects how the fake system applies resolver changes.
// When on is false (the default), the system applies each Write and
// Remove at once. When on is true, it applies them only at
// SettleResolver, all together, as a platform that applies changes after
// a delay does. An entry that a Write changed is not active until then.
func (w *World) SetResolverDelay(on bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.delay = on
}

// SettleResolver applies every resolver change, as the end of the
// platform delay does. It is not a write: no hook runs.
func (w *World) SettleResolver() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.settleLocked()
}

func (w *World) settleLocked() {
	w.applied = maps.Clone(w.resolver)
	clear(w.pending)
}

// AppliedResolverEntries returns the resolver entries that the fake
// system uses now, sorted by domain. With a delay, they can differ from
// ResolverEntries.
func (w *World) AppliedResolverEntries() []reconcile.ResolverEntry {
	w.mu.Lock()
	defer w.mu.Unlock()
	return sortedEntries(w.applied)
}

// Writes returns the number of write calls so far, failed ones included.
func (w *World) Writes() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writes
}

// Ruleset returns the loaded ruleset.
func (w *World) Ruleset() reconcile.Ruleset {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.ruleset
}

// Referenced returns the policies whose table the loaded ruleset refers
// to. It reads a ruleset that Compiler built.
func (w *World) Referenced() []policy.Name {
	var out []policy.Name
	for line := range bytes.Lines(w.Ruleset().Body()) {
		if rest, ok := strings.CutPrefix(string(line), "table "); ok {
			name, _, _ := strings.Cut(rest, " ")
			out = append(out, policy.Name(name))
		}
	}
	return out
}

// Tables returns a copy of every table, entries sorted.
func (w *World) Tables() map[policy.Name][]netip.Prefix {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.tablesLocked()
}

func (w *World) tablesLocked() map[policy.Name][]netip.Prefix {
	out := make(map[policy.Name][]netip.Prefix, len(w.tables))
	for name, t := range w.tables {
		out[name] = slices.SortedFunc(maps.Keys(t), netip.Prefix.Compare)
	}
	return out
}

// ResolverEntries returns the resolver entries sorted by domain.
func (w *World) ResolverEntries() []reconcile.ResolverEntry {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.resolverLocked()
}

func (w *World) resolverLocked() []reconcile.ResolverEntry {
	return sortedEntries(w.resolver)
}

func sortedEntries(m map[policy.Domain]netip.AddrPort) []reconcile.ResolverEntry {
	out := make([]reconcile.ResolverEntry, 0, len(m))
	for d, s := range m {
		out = append(out, reconcile.ResolverEntry{Domain: d, Server: s})
	}
	slices.SortFunc(out, func(a, b reconcile.ResolverEntry) int {
		return strings.Compare(a.Domain.String(), b.Domain.String())
	})
	return out
}

// FlushTable empties a table, as an external pfctl call would. It is not
// a write: no hook runs.
func (w *World) FlushTable(name policy.Name) {
	w.mu.Lock()
	defer w.mu.Unlock()
	clear(w.tables[name])
}

// FlushAll removes the ruleset and every table, as an external
// "pfctl -a <anchor> -F all" would. It is not a write: no hook runs.
func (w *World) FlushAll() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.ruleset = reconcile.Ruleset{}
	clear(w.tables)
}

// ExternalLoad loads a ruleset with the given body, as another tool that
// writes into the anchor would. It is not a write: no hook runs.
func (w *World) ExternalLoad(body []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.ruleset = reconcile.NewRuleset(body)
}

// RemoveResolverEntry deletes a resolver entry, as an external tool
// would. It is not a write: no hook runs. The system applies it as it
// applies a Remove.
func (w *World) RemoveResolverEntry(d policy.Domain) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.removeLocked(d)
}

func (w *World) removeLocked(d policy.Domain) {
	delete(w.resolver, d)
	delete(w.pending, d)
	if !w.delay {
		delete(w.applied, d)
	}
}

// write runs one write call: the before hook, apply, the after hook.
func (w *World) write(apply func()) error {
	w.mu.Lock()
	w.writes++
	n, before := w.writes, w.before
	w.mu.Unlock()
	if before != nil {
		if err := before(n); err != nil {
			return err
		}
	}
	w.mu.Lock()
	apply()
	after := w.after
	w.mu.Unlock()
	if after != nil {
		after()
	}
	return nil
}

// Backend is the reconcile.Backend face of a World. Load never changes a
// table, as the interface contract demands.
type Backend struct{ w *World }

var _ reconcile.Backend = (*Backend)(nil)

// Read implements reconcile.Backend.
func (b *Backend) Read(context.Context) (reconcile.BackendState, error) {
	b.w.mu.Lock()
	defer b.w.mu.Unlock()
	return reconcile.BackendState{
		Ruleset:  b.w.ruleset.ID(),
		Tables:   b.w.tablesLocked(),
		Problems: slices.Clone(b.w.bproblem),
	}, nil
}

// LoadedID implements reconcile.Backend.
func (b *Backend) LoadedID(context.Context) (string, error) {
	return b.w.Ruleset().ID(), nil
}

// Load implements reconcile.Backend.
func (b *Backend) Load(_ context.Context, rs reconcile.Ruleset) error {
	return b.w.write(func() { b.w.ruleset = rs })
}

// AddEntries implements reconcile.Backend.
func (b *Backend) AddEntries(_ context.Context, table policy.Name, entries []netip.Prefix) error {
	return b.w.write(func() {
		t := b.w.tables[table]
		if t == nil {
			t = make(map[netip.Prefix]struct{})
			b.w.tables[table] = t
		}
		for _, e := range entries {
			t[e] = struct{}{}
		}
	})
}

// RemoveEntries implements reconcile.Backend.
func (b *Backend) RemoveEntries(_ context.Context, table policy.Name, entries []netip.Prefix) error {
	return b.w.write(func() {
		for _, e := range entries {
			delete(b.w.tables[table], e)
		}
	})
}

// DropTable implements reconcile.Backend.
func (b *Backend) DropTable(_ context.Context, table policy.Name) error {
	return b.w.write(func() { delete(b.w.tables, table) })
}

// Resolver is the reconcile.SysResolver face of a World.
type Resolver struct{ w *World }

var _ reconcile.SysResolver = (*Resolver)(nil)

// Read implements reconcile.SysResolver.
func (r *Resolver) Read(context.Context) (reconcile.ResolverState, error) {
	r.w.mu.Lock()
	defer r.w.mu.Unlock()
	entries := r.w.resolverLocked()
	out := make([]reconcile.ManagedEntry, len(entries))
	for i, e := range entries {
		_, pending := r.w.pending[e.Domain]
		out[i] = reconcile.ManagedEntry{ResolverEntry: e, Active: !pending}
	}
	return reconcile.ResolverState{
		Entries:  out,
		Problems: slices.Clone(r.w.rproblem),
	}, nil
}

// Write implements reconcile.SysResolver. With a delay, each Write makes
// the entry not active until SettleResolver, also when its content does
// not change.
func (r *Resolver) Write(_ context.Context, e reconcile.ResolverEntry) error {
	return r.w.write(func() {
		r.w.resolver[e.Domain] = e.Server
		if r.w.delay {
			r.w.pending[e.Domain] = struct{}{}
		} else {
			r.w.applied[e.Domain] = e.Server
		}
	})
}

// Remove implements reconcile.SysResolver.
func (r *Resolver) Remove(_ context.Context, d policy.Domain) error {
	return r.w.write(func() { r.w.removeLocked(d) })
}

// Compiler is a fake reconcile.Compiler. Its ruleset text has one
// "table <name> <constraint>" line per policy and one "iface" line per
// interface, so any change of constraint, policy set, or interfaces gives
// a new ID.
type Compiler struct{}

var _ reconcile.Compiler = Compiler{}

// Compile implements reconcile.Compiler.
func (Compiler) Compile(policies []policy.Policy, ifaces []reconcile.Interface) (reconcile.Ruleset, error) {
	var b []byte
	for _, p := range policies {
		b = fmt.Appendf(b, "table %s %#v\n", p.Name, p.Constraint)
	}
	for _, i := range ifaces {
		b = fmt.Appendf(b, "iface %s %s\n", i.Name, i.Class)
	}
	return reconcile.NewRuleset(b), nil
}

// Inventory is a fake reconcile.IfInventory.
type Inventory struct {
	mu      sync.Mutex
	ifaces  []reconcile.Interface
	changes chan struct{}
}

var _ reconcile.IfInventory = (*Inventory)(nil)

// NewInventory returns an inventory with the given interfaces.
func NewInventory(ifaces ...reconcile.Interface) *Inventory {
	return &Inventory{ifaces: slices.Clone(ifaces), changes: make(chan struct{}, 1)}
}

// Set replaces the interfaces and signals a change. Signals that nobody
// has received yet merge into one.
func (i *Inventory) Set(ifaces ...reconcile.Interface) {
	i.mu.Lock()
	i.ifaces = slices.Clone(ifaces)
	i.mu.Unlock()
	select {
	case i.changes <- struct{}{}:
	default:
	}
}

// Interfaces implements reconcile.IfInventory.
func (i *Inventory) Interfaces(context.Context) ([]reconcile.Interface, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	return slices.Clone(i.ifaces), nil
}

// Changes implements reconcile.IfInventory.
func (i *Inventory) Changes() <-chan struct{} { return i.changes }
