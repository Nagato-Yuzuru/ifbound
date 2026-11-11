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

// DisabledText is the text of the Problem that the Backend reports
// while the firewall is disabled. The Problem voids enforcement.
const DisabledText = "the firewall is disabled"

// World is the fake kernel and resolver state. It is safe for concurrent
// use: the daemon goroutine writes while the test goroutine reads.
type World struct {
	mu      sync.Mutex
	ruleset reconcile.Ruleset
	tables  map[policy.Name]map[netip.Prefix]struct{}
	// negated are the negated entries of each table (see AddNegated).
	negated  map[policy.Name][]netip.Prefix
	resolver map[policy.Domain]netip.AddrPort
	// applied are the resolver entries that the fake system uses now.
	applied  map[policy.Domain]netip.AddrPort
	delay    bool
	disabled bool
	refuse   bool
	bproblem []reconcile.Problem
	rproblem []reconcile.Problem
	writes   int
	ended    []netip.Prefix
	before   func(n int) error
	after    func()
}

// NewWorld returns an empty World: no ruleset, no tables, no resolver
// entries.
func NewWorld() *World {
	return &World{
		tables:   make(map[policy.Name]map[netip.Prefix]struct{}),
		negated:  make(map[policy.Name][]netip.Prefix),
		resolver: make(map[policy.Domain]netip.AddrPort),
		applied:  make(map[policy.Domain]netip.AddrPort),
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
// Resolver report. They stay until the next SetProblems: no write
// repairs them. DisableFirewall gives the Problem of a disabled firewall.
func (w *World) SetProblems(backend, resolver []reconcile.Problem) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.bproblem, w.rproblem = slices.Clone(backend), slices.Clone(resolver)
}

// SetEnableRefused selects whether a Load can enable the firewall. When
// on is true, a Load while the firewall is disabled fails with
// ErrInjected and changes nothing, as the real Backend refuses an enable
// within its rate limit. A Load while the firewall is enabled is not an
// enable, so it is not refused.
func (w *World) SetEnableRefused(on bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.refuse = on
}

// SetResolverDelay selects how the fake system applies resolver changes.
// When on is false (the default), the system applies each Write and
// Remove at once. When on is true, it applies them only at
// SettleResolver, all together, as a platform that applies changes after
// a delay does.
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

// EndedStates returns, in call order, each entry whose states a Load or
// an AddEntries ended. Load ends the states to every entry of every
// table, tables in name order; AddEntries ends the states to the entries
// that it gets. A failed write ends no state.
func (w *World) EndedStates() []netip.Prefix {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.ended)
}

// Ruleset returns the ruleset in the anchor, also while the firewall is
// disabled.
func (w *World) Ruleset() reconcile.Ruleset {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.ruleset
}

// FirewallDisabled reports whether the firewall is disabled.
func (w *World) FirewallDisabled() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.disabled
}

// Referenced returns the policies whose table the rules in effect refer
// to: none while the firewall is disabled. It reads a ruleset that
// Compiler built. It reads the World, not the Backend, so a test can use
// it to check what the Backend reports.
func (w *World) Referenced() []policy.Name {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.disabled {
		return nil
	}
	return declared(w.ruleset)
}

// declared returns the tables that a ruleset of Compiler declares.
func declared(rs reconcile.Ruleset) []policy.Name {
	var out []policy.Name
	for line := range bytes.Lines(rs.Body()) {
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
	delete(w.negated, name)
}

// FlushAll removes the ruleset and every table, as an external
// "pfctl -a <anchor> -F all" would. It is not a write: no hook runs.
func (w *World) FlushAll() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.ruleset = reconcile.Ruleset{}
	clear(w.tables)
	clear(w.negated)
}

// AddNegated adds the negated entry !n to a table, as an external pfctl
// call would. It is not a write: no hook runs. Tables does not show it.
// As in pf, a negated entry inside an entry of its table exempts its
// addresses from that entry. Read then reports a Problem that voids the
// enforcement, and it leaves that entry out of Tables. AddEntries deletes
// each negated entry inside a prefix that it adds, so a table write can
// repair this Problem without a Load.
func (w *World) AddNegated(table policy.Name, n netip.Prefix) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.negated[table] = append(w.negated[table], n)
}

// inside reports whether the prefix n is inside the prefix p and longer,
// so that pf matches n first for the addresses of n.
func inside(n, p netip.Prefix) bool {
	return p.Bits() < n.Bits() && p.Contains(n.Addr())
}

// ExternalLoad loads a ruleset with the given body, as another tool that
// writes into the anchor would. It is not a write: no hook runs.
func (w *World) ExternalLoad(body []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.ruleset = reconcile.NewRuleset(body)
}

// DisableFirewall disables the firewall, as an external "pfctl -d"
// would. It is not a write: no hook runs. The ruleset and the tables
// stay, but the Backend reports no loaded ruleset until a Load enables
// the firewall again.
func (w *World) DisableFirewall() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.disabled = true
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
	if !w.delay {
		delete(w.applied, d)
	}
}

// write runs one write call: the before hook, apply, the after hook. When
// apply fails, the World must not have changed, and the after hook does
// not run.
func (w *World) write(apply func() error) error {
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
	err := apply()
	after := w.after
	w.mu.Unlock()
	if err != nil {
		return err
	}
	if after != nil {
		after()
	}
	return nil
}

// Backend is the reconcile.Backend face of a World. Load creates the
// missing tables that the ruleset declares and never changes a table, as
// the interface contract demands.
type Backend struct{ w *World }

var _ reconcile.Backend = (*Backend)(nil)

// Read implements reconcile.Backend. While the firewall is disabled, the
// ruleset ID is "" and a Problem voids the enforcement. A negated entry
// inside an entry of its table also gives a Problem that voids the
// enforcement, and Tables does not have that entry (see AddNegated).
func (b *Backend) Read(context.Context) (reconcile.BackendState, error) {
	b.w.mu.Lock()
	defer b.w.mu.Unlock()
	problems := slices.Clone(b.w.bproblem)
	if b.w.disabled {
		problems = append(problems, reconcile.Problem{Text: DisabledText, Voids: true})
	}
	tables := b.w.tablesLocked()
	for _, name := range slices.Sorted(maps.Keys(b.w.negated)) {
		entries, neg := tables[name], b.w.negated[name]
		for _, n := range neg {
			if slices.ContainsFunc(entries, func(e netip.Prefix) bool { return inside(n, e) }) {
				problems = append(problems, reconcile.Problem{Text: fmt.Sprintf("the table %s holds the negated entry !%s", name, n), Voids: true})
			}
		}
		if entries != nil {
			tables[name] = slices.DeleteFunc(entries, func(e netip.Prefix) bool {
				return slices.ContainsFunc(neg, func(n netip.Prefix) bool { return inside(n, e) })
			})
		}
	}
	return reconcile.BackendState{
		Ruleset:  b.w.loadedIDLocked(),
		Tables:   tables,
		Problems: problems,
	}, nil
}

// LoadedID implements reconcile.Backend.
func (b *Backend) LoadedID(context.Context) (string, error) {
	b.w.mu.Lock()
	defer b.w.mu.Unlock()
	return b.w.loadedIDLocked(), nil
}

// loadedIDLocked returns the ID of the loaded ruleset, or "" while the
// firewall is disabled: no rule is in effect then.
func (w *World) loadedIDLocked() string {
	if w.disabled {
		return ""
	}
	return w.ruleset.ID()
}

// Load implements reconcile.Backend. It enables the firewall, or fails
// when SetEnableRefused refuses the enable.
func (b *Backend) Load(_ context.Context, rs reconcile.Ruleset) error {
	return b.w.write(func() error {
		if b.w.disabled && b.w.refuse {
			return fmt.Errorf("enabling the firewall: %w", ErrInjected)
		}
		b.w.ruleset, b.w.disabled = rs, false
		for _, name := range declared(rs) {
			if b.w.tables[name] == nil {
				b.w.tables[name] = make(map[netip.Prefix]struct{})
			}
		}
		tables := b.w.tablesLocked()
		for _, name := range slices.Sorted(maps.Keys(tables)) {
			b.w.ended = append(b.w.ended, tables[name]...)
		}
		return nil
	})
}

// errEntry is the error of a write with an invalid entry. The real
// Backend refuses such a batch too, so a test cannot pass on an entry
// that the kernel never gets.
var errEntry = errors.New("reconciletest: invalid table entry")

// checkEntries returns errEntry when entries holds an invalid entry.
func checkEntries(entries []netip.Prefix) error {
	if i := slices.IndexFunc(entries, func(e netip.Prefix) bool { return !e.IsValid() }); i >= 0 {
		return fmt.Errorf("%w: %v", errEntry, entries[i])
	}
	return nil
}

// AddEntries implements reconcile.Backend. It refuses a batch with an
// invalid entry and then changes nothing. It deletes each negated entry
// inside a prefix that it adds, as the pf Backend does.
func (b *Backend) AddEntries(_ context.Context, table policy.Name, entries []netip.Prefix) error {
	return b.w.write(func() error {
		if err := checkEntries(entries); err != nil {
			return err
		}
		t := b.w.tables[table]
		if t == nil {
			t = make(map[netip.Prefix]struct{})
			b.w.tables[table] = t
		}
		for _, e := range entries {
			t[e] = struct{}{}
		}
		b.w.negated[table] = slices.DeleteFunc(b.w.negated[table], func(n netip.Prefix) bool {
			return slices.ContainsFunc(entries, func(e netip.Prefix) bool { return inside(n, e) })
		})
		b.w.ended = append(b.w.ended, entries...)
		return nil
	})
}

// RemoveEntries implements reconcile.Backend. It refuses a batch with an
// invalid entry, as AddEntries does.
func (b *Backend) RemoveEntries(_ context.Context, table policy.Name, entries []netip.Prefix) error {
	return b.w.write(func() error {
		if err := checkEntries(entries); err != nil {
			return err
		}
		for _, e := range entries {
			delete(b.w.tables[table], e)
		}
		return nil
	})
}

// DropTable implements reconcile.Backend.
func (b *Backend) DropTable(_ context.Context, table policy.Name) error {
	return b.w.write(func() error {
		delete(b.w.tables, table)
		delete(b.w.negated, table)
		return nil
	})
}

// Resolver is the reconcile.SysResolver face of a World.
type Resolver struct{ w *World }

var _ reconcile.SysResolver = (*Resolver)(nil)

// Read implements reconcile.SysResolver.
func (r *Resolver) Read(context.Context) (reconcile.ResolverState, error) {
	r.w.mu.Lock()
	defer r.w.mu.Unlock()
	return reconcile.ResolverState{
		Entries:  r.w.resolverLocked(),
		Problems: slices.Clone(r.w.rproblem),
	}, nil
}

// Write implements reconcile.SysResolver. With a delay, the fake system
// uses the entry only after SettleResolver.
func (r *Resolver) Write(_ context.Context, e reconcile.ResolverEntry) error {
	return r.w.write(func() error {
		r.w.resolver[e.Domain] = e.Server
		if !r.w.delay {
			r.w.applied[e.Domain] = e.Server
		}
		return nil
	})
}

// Remove implements reconcile.SysResolver.
func (r *Resolver) Remove(_ context.Context, d policy.Domain) error {
	return r.w.write(func() error {
		r.w.removeLocked(d)
		return nil
	})
}

// Compiler is a fake reconcile.Compiler. Its ruleset text has one
// "table <name> <constraint> <scope>" line per policy and one "iface"
// line per interface, so any change of constraint, scope, policy set, or
// interfaces gives a new ID. It ignores the accounts.
type Compiler struct{}

var _ reconcile.Compiler = Compiler{}

// Compile implements reconcile.Compiler.
func (Compiler) Compile(policies []policy.Policy, ifaces []reconcile.Interface, _ reconcile.Accounts) (reconcile.Ruleset, error) {
	var b []byte
	for _, p := range policies {
		b = fmt.Appendf(b, "table %s %#v %#v\n", p.Name, p.Constraint, p.Scope)
	}
	for _, i := range ifaces {
		b = fmt.Appendf(b, "iface %s %s %v\n", i.Name, i.Class, i.Possible())
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
