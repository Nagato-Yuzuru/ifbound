// Package reconcile makes the kernel enforcement and the system resolver
// entries equal to the desired state.
//
// The desired state comes from the policies, the current interfaces, and
// the learned addresses. Each convergence reads the actual state from the
// platform and writes only the difference, so it repairs any drift: a
// crash halfway through an earlier pass, an external flush, or a
// configuration change. A second pass with the same inputs writes
// nothing.
//
// The write order is fail-closed. An address that a loaded rule blocks
// stays in its table until it expires or its policy leaves the loaded
// ruleset. See Reconciler.Converge.
//
// This package defines the platform interfaces. The platform packages
// implement them; the reconciletest package has fakes.
package reconcile

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

// AddrSource gives the learned addresses of a policy.
// *addrbook.AddrBook implements it.
type AddrSource interface {
	Addrs(name policy.Name) []netip.Addr
}

// Inputs is everything that the desired state depends on, apart from the
// interfaces, which the Reconciler reads from its IfInventory.
type Inputs struct {
	Policies []policy.Policy
	// Book gives the learned addresses of each policy.
	Book AddrSource
	// Apexes are the domains that get a resolver entry: the apex list of
	// the Matcher for Policies. The canary domain of Firefox also gets an
	// entry, but only when another entry exists. See Reconciler.Converge.
	Apexes []policy.Domain
	// Listen is the server address of every resolver entry.
	Listen netip.AddrPort
	// Accounts resolves the account names of a scope. With the zero
	// Accounts, the Compiler knows no account and drops every scope, so
	// each scoped policy applies to all traffic.
	Accounts Accounts
}

// Report describes one convergence.
type Report struct {
	// Writes is the number of platform writes that succeeded.
	Writes int
	// Installed is the ID of the ruleset that the Backend part loaded or
	// found loaded, when that part completed without error. It is empty
	// otherwise. A non-empty Installed means: the ruleset for the inputs
	// is loaded, and every table it refers to holds its desired entries.
	Installed string
	// Problems lists the external problems that the Compiler, the Backend,
	// and the SysResolver reported, in that order.
	Problems []Problem
}

// Reconciler converges the platform state. All fields are required. It
// keeps no state between calls, but the platform parts are not safe for
// concurrent use: call it from one goroutine.
type Reconciler struct {
	Compiler  Compiler
	Backend   Backend
	Resolver  SysResolver
	Inventory IfInventory
}

// Converge makes the actual state equal to the desired state for in.
//
// The Backend part runs in this order, and it stops at its first error:
//
//  1. Add the missing table entries. A new policy gets a full table
//     before any rule refers to it.
//  2. Load the compiled ruleset if its ID differs from the loaded one.
//  3. Remove the entries that are no longer desired, then drop the tables
//     of removed policies. The loaded ruleset no longer refers to them.
//
// The SysResolver part runs after it, also when the Backend part failed.
// The desired entries are:
//
//   - one entry for each apex;
//   - one entry for the Firefox canary domain (use-application-dns.net),
//     when there is at least one other entry. An answer from ifbound-dns
//     for the canary can then turn off the DNS-over-HTTPS of Firefox,
//     which does not use the system resolver.
//
// The part writes the new and changed entries, then removes the old ones.
// It does not write an entry that is present with the desired server,
// also when the system has not applied it yet: each write can flush the
// whole DNS cache of the system and restart the delay of a platform. A failed
// write does not stop the others. The part keeps an old entry when the
// write of a desired entry on the same label path failed: at or below the
// old entry, because the old entry still covers that domain; at or above
// it, because the failed entry was to cover the names of the old entry.
//
// The error joins the errors of both parts. The Report holds what was
// done and seen; the next call continues from there.
func (r Reconciler) Converge(ctx context.Context, in Inputs) (Report, error) {
	var rep Report
	berr := r.convergeBackend(ctx, in, &rep)
	rerr := r.convergeResolver(ctx, in, &rep)
	return rep, errors.Join(berr, rerr)
}

// AddObserved adds the addresses to the table of one policy. It is the
// fast path for a DNS report: it neither reads the actual state nor
// recompiles. A nil error means the Backend holds every address in the
// table.
func (r Reconciler) AddObserved(ctx context.Context, name policy.Name, addrs []netip.Addr) error {
	if len(addrs) == 0 {
		return nil
	}
	entries := make([]netip.Prefix, len(addrs))
	for i, a := range addrs {
		entries[i] = host(a)
	}
	if err := r.Backend.AddEntries(ctx, name, entries); err != nil {
		return fmt.Errorf("adding to table %s: %w", name, err)
	}
	return nil
}

func (r Reconciler) convergeBackend(ctx context.Context, in Inputs, rep *Report) error {
	ifaces, err := r.Inventory.Interfaces(ctx)
	if err != nil {
		return fmt.Errorf("reading interfaces: %w", err)
	}
	rs, err := r.Compiler.Compile(in.Policies, ifaces, in.Accounts)
	if err != nil {
		return fmt.Errorf("compiling ruleset: %w", err)
	}
	rep.Problems = append(rep.Problems, rs.Problems()...)
	actual, err := r.Backend.Read(ctx)
	if err != nil {
		return fmt.Errorf("reading backend: %w", err)
	}
	rep.Problems = append(rep.Problems, actual.Problems...)
	want := desiredTables(in)
	have := make(map[policy.Name]prefixSet, len(actual.Tables))
	for name, entries := range actual.Tables {
		have[name] = newPrefixSet(entries)
	}
	if err := r.addMissing(ctx, in.Policies, want, have, rep); err != nil {
		return err
	}
	if actual.Ruleset != rs.ID() {
		if err := r.Backend.Load(ctx, rs); err != nil {
			return fmt.Errorf("loading ruleset: %w", err)
		}
		rep.Writes++
	}
	if err := r.removeUndesired(ctx, in.Policies, want, have, rep); err != nil {
		return err
	}
	rep.Installed = rs.ID()
	return nil
}

// Adoptable returns the addresses in the kernel tables of the policies
// that look learned: host entries that are not an IP destination of the
// policy. A daemon that starts without a snapshot adopts them, so a lost
// snapshot keeps addresses blocked instead of unblocking them all.
func (r Reconciler) Adoptable(ctx context.Context, policies []policy.Policy) (map[policy.Name][]netip.Addr, error) {
	actual, err := r.Backend.Read(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading backend: %w", err)
	}
	out := make(map[policy.Name][]netip.Addr)
	for _, p := range policies {
		static := staticEntries(p)
		for _, e := range actual.Tables[p.Name] {
			if _, ok := static[e]; ok || !e.IsSingleIP() {
				continue
			}
			out[p.Name] = append(out[p.Name], e.Addr())
		}
	}
	return out, nil
}

func (r Reconciler) addMissing(ctx context.Context, policies []policy.Policy, want, have map[policy.Name]prefixSet, rep *Report) error {
	for _, p := range policies {
		add := want[p.Name].minus(have[p.Name])
		if len(add) == 0 {
			continue
		}
		if err := r.Backend.AddEntries(ctx, p.Name, add); err != nil {
			return fmt.Errorf("adding to table %s: %w", p.Name, err)
		}
		rep.Writes++
	}
	return nil
}

// removeUndesired runs only after the desired ruleset is loaded.
func (r Reconciler) removeUndesired(ctx context.Context, policies []policy.Policy, want, have map[policy.Name]prefixSet, rep *Report) error {
	for _, p := range policies {
		extra := have[p.Name].minus(want[p.Name])
		if len(extra) == 0 {
			continue
		}
		if err := r.Backend.RemoveEntries(ctx, p.Name, extra); err != nil {
			return fmt.Errorf("removing from table %s: %w", p.Name, err)
		}
		rep.Writes++
	}
	stale := make([]policy.Name, 0, len(have))
	for name := range have {
		if _, ok := want[name]; !ok {
			stale = append(stale, name)
		}
	}
	slices.Sort(stale)
	for _, name := range stale {
		if err := r.Backend.DropTable(ctx, name); err != nil {
			return fmt.Errorf("dropping table %s: %w", name, err)
		}
		rep.Writes++
	}
	return nil
}

func (r Reconciler) convergeResolver(ctx context.Context, in Inputs, rep *Report) error {
	actual, err := r.Resolver.Read(ctx)
	if err != nil {
		return fmt.Errorf("reading resolver entries: %w", err)
	}
	rep.Problems = append(rep.Problems, actual.Problems...)
	have := make(map[policy.Domain]netip.AddrPort, len(actual.Entries))
	for _, e := range actual.Entries {
		have[e.Domain] = e.Server
	}
	domains := desiredDomains(in)
	want := make(map[policy.Domain]bool, len(domains))
	var errs []error
	var failed []policy.Domain
	for _, d := range domains {
		want[d] = true
		if s, ok := have[d]; ok && s == in.Listen {
			continue
		}
		if err := r.Resolver.Write(ctx, ResolverEntry{Domain: d, Server: in.Listen}); err != nil {
			errs = append(errs, fmt.Errorf("writing resolver entry %s: %w", d, err))
			failed = append(failed, d)
			continue
		}
		rep.Writes++
	}
	var old []policy.Domain
	for d := range have {
		if !want[d] {
			old = append(old, d)
		}
	}
	slices.SortFunc(old, compareDomains)
	for _, d := range old {
		if slices.ContainsFunc(failed, func(f policy.Domain) bool { return atOrBelow(f, d) || atOrBelow(d, f) }) {
			continue
		}
		if err := r.Resolver.Remove(ctx, d); err != nil {
			errs = append(errs, fmt.Errorf("removing resolver entry %s: %w", d, err))
			continue
		}
		rep.Writes++
	}
	return errors.Join(errs...)
}

// firefoxCanary is the canary domain of Firefox. Firefox turns off its
// DNS-over-HTTPS when the system resolver answers this name with no
// address.
const firefoxCanary = "use-application-dns.net"

// canaryDomain returns firefoxCanary as a domain.
func canaryDomain() policy.Domain {
	d, err := policy.ParseDomain(firefoxCanary)
	if err != nil {
		panic("reconcile: invalid canary domain: " + err.Error())
	}
	return d
}

// desiredDomains returns the domains that get a resolver entry: the
// apexes, then the canary when it is not an apex.
func desiredDomains(in Inputs) []policy.Domain {
	if len(in.Apexes) == 0 {
		return nil
	}
	out := slices.Clone(in.Apexes)
	if canary := canaryDomain(); !slices.Contains(out, canary) {
		out = append(out, canary)
	}
	return out
}

// atOrBelow reports whether d is equal to apex or below it. It compares
// whole labels, so "badexample.com" is not below "example.com".
func atOrBelow(d, apex policy.Domain) bool {
	dl := strings.Split(d.String(), ".")
	al := strings.Split(apex.String(), ".")
	return len(dl) >= len(al) && slices.Equal(dl[len(dl)-len(al):], al)
}

func compareDomains(a, b policy.Domain) int { return strings.Compare(a.String(), b.String()) }

// desiredTables has a key for every policy, also when its table is empty:
// a missing key marks a table to drop.
func desiredTables(in Inputs) map[policy.Name]prefixSet {
	out := make(map[policy.Name]prefixSet, len(in.Policies))
	for _, p := range in.Policies {
		s := staticEntries(p)
		for _, a := range in.Book.Addrs(p.Name) {
			s[host(a)] = struct{}{}
		}
		out[p.Name] = s
	}
	return out
}

// staticEntries are the table entries that the configuration gives.
func staticEntries(p policy.Policy) prefixSet {
	s := prefixSet{}
	for _, dest := range p.To {
		switch d := dest.(type) {
		case policy.IPAddr:
			s[host(d.Addr())] = struct{}{}
		case policy.CIDR:
			s[d.Prefix()] = struct{}{}
		case policy.ExactDomain, policy.DomainSuffix:
			// The book holds the addresses that DNS gave for these.
		}
	}
	return s
}

// host is the table entry for one address.
func host(a netip.Addr) netip.Prefix {
	return netip.PrefixFrom(a, a.BitLen())
}

type prefixSet map[netip.Prefix]struct{}

func newPrefixSet(entries []netip.Prefix) prefixSet {
	s := make(prefixSet, len(entries))
	for _, e := range entries {
		s[e] = struct{}{}
	}
	return s
}

// minus returns the members of s that are not in t, sorted.
func (s prefixSet) minus(t prefixSet) []netip.Prefix {
	var out []netip.Prefix
	for p := range s {
		if _, ok := t[p]; !ok {
			out = append(out, p)
		}
	}
	slices.SortFunc(out, netip.Prefix.Compare)
	return out
}
