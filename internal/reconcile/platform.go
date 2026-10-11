package reconcile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/netip"

	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

// The platform contract. A Compiler and a Backend come as a pair from one
// platform package: they share the mapping from a policy name to a kernel
// table, so a table that AddEntries creates is the table that the rules
// of a compiled ruleset refer to.
//
// Every call that takes a context honors it and finishes in bounded time.
// The daemon calls them from one goroutine and waits for each one.

// Interface is one network interface in an inventory snapshot.
type Interface struct {
	Name string
	// Class is the zero Class when the interface is in no known class.
	Class policy.Class
}

// Ruleset is a compiled ruleset. Its body is in the format of one Backend,
// and the Reconciler never reads it. The Reconciler compares rulesets by
// ID only. Build one with NewRuleset.
type Ruleset struct {
	id   string
	body []byte
}

// NewRuleset returns a ruleset with an ID that is a digest of body. Equal
// bodies get equal IDs, so a Backend can derive the ID of the loaded
// ruleset from the kernel and the Reconciler can skip a load that changes
// nothing.
func NewRuleset(body []byte) Ruleset {
	sum := sha256.Sum256(body)
	return Ruleset{id: hex.EncodeToString(sum[:]), body: bytes.Clone(body)}
}

// ID identifies the ruleset. The zero Ruleset has the empty ID, which is
// also the ID that a Backend reports when no ruleset is loaded.
func (r Ruleset) ID() string { return r.id }

// Body returns a copy of the ruleset text.
func (r Ruleset) Body() []byte { return bytes.Clone(r.body) }

// Compiler turns policies and interfaces into a ruleset.
//
// Contract:
//   - Compile is a pure function: equal inputs give equal rulesets. If
//     the result depends on the order of ifaces, Compile sorts them first.
//   - The ruleset refers to exactly one table per policy, through the
//     table-name mapping that the paired Backend uses.
//   - A selector that depends on the inventory (a glob or a class) fails
//     closed for an interface that is not in ifaces, where the platform
//     can express it. Where it cannot, a deny_via constraint does not
//     apply to such an interface until the next convergence. That window
//     is accepted.
type Compiler interface {
	Compile(policies []policy.Policy, ifaces []Interface) (Ruleset, error)
}

// Problem is an external fault that ifbound cannot repair.
type Problem struct {
	// Text is one line for the operator.
	Text string
	// Voids is true when the fault makes the installed enforcement block
	// nothing, for example "pf is disabled" or "the anchor is not
	// evaluated". The daemon then acknowledges no report.
	Voids bool
}

// BackendState is the enforcement that the kernel holds now.
type BackendState struct {
	// Ruleset is the ID of the loaded ruleset, or "" when none is loaded.
	// The Backend derives it from the kernel content, as LoadedID does.
	Ruleset string
	// Tables holds every table that ifbound manages, keyed by policy name.
	// A key with no entries is a table that exists and is empty.
	Tables   map[policy.Name][]netip.Prefix
	Problems []Problem
}

// Backend installs enforcement in the kernel.
//
// Contract:
//   - Load replaces the ruleset atomically. It never creates, drops, or
//     fills a table, and never changes the content of one.
//   - Tables persist: they stay when no loaded rule refers to them, and
//     only DropTable removes one.
//   - A rule that refers to a table that does not exist yet blocks
//     nothing extra. A later AddEntries creates that same table, and the
//     rule then uses it.
//   - After Load or AddEntries, existing connection states obey the new
//     enforcement: the Backend ends the states that the new rules block.
//   - The rules of ifbound are evaluated before any rule of the main
//     ruleset that can match the same traffic and end the evaluation. If
//     the Backend sees that this does not hold (the anchor is not
//     referenced, or a quick rule comes first), it reports a Problem with
//     Voids set. A disabled firewall is also such a Problem.
//   - Read and LoadedID derive the ruleset ID from the kernel content,
//     never from a cache. After any external change to the ruleset they
//     report "" or an ID that differs from the loaded one.
//   - The write methods are idempotent: adding an entry that is present,
//     removing one that is absent, and dropping a table that is missing
//     all succeed. A nil error from a write means the kernel holds the
//     result.
type Backend interface {
	// Read returns the actual state. It writes nothing.
	Read(ctx context.Context) (BackendState, error)
	// LoadedID returns the ID of the loaded ruleset, or "" when none is
	// loaded. It is the cheap part of Read: the daemon calls it for every
	// report that matches a policy.
	LoadedID(ctx context.Context) (string, error)
	// Load installs the ruleset.
	Load(ctx context.Context, rs Ruleset) error
	// AddEntries adds entries to the table of a policy. It creates the
	// table when it is missing.
	AddEntries(ctx context.Context, table policy.Name, entries []netip.Prefix) error
	// RemoveEntries removes entries from the table of a policy.
	RemoveEntries(ctx context.Context, table policy.Name, entries []netip.Prefix) error
	// DropTable removes the table of a policy and all its entries.
	DropTable(ctx context.Context, table policy.Name) error
}

// ResolverEntry sends the queries for a domain and every name below it to
// Server.
type ResolverEntry struct {
	Domain policy.Domain
	Server netip.AddrPort
}

// ManagedEntry is a resolver entry that ifbound manages, as the
// SysResolver reads it.
type ManagedEntry struct {
	ResolverEntry
	// Active is true when the system now sends the queries for Domain to
	// Server. An entry that is not active yet is present, but the system
	// can still send its queries to another resolver.
	Active bool
}

// ResolverState is the set of resolver entries that ifbound manages now.
type ResolverState struct {
	Entries []ManagedEntry // at most one entry per domain
	// Problems are conflicts with entries that ifbound does not manage.
	Problems []Problem
}

// SysResolver manages the system resolver entries of ifbound. It never
// touches an entry that ifbound does not manage.
//
// Contract:
//   - The write methods are idempotent in the same way as the Backend
//     ones.
//   - The system applies the changes in call order. A platform that
//     applies changes after a delay never applies a Remove before an
//     earlier Write. So an entry that a Write adds keeps its domain covered
//     while the system still applies a later Remove of a broader entry.
//   - Read reports for each entry whether it is active. The platform
//     decides this by its own rule, and it derives the answer from the
//     system state, never from a cache. For example, a platform that
//     applies a new entry after a delay compares the modification time
//     of the entry with a settle time. A platform that applies an entry
//     at once reports it as active after a successful Write.
//   - Each Write, also of unchanged content, can make the system flush
//     its whole DNS cache (macOS does this), and it can make an active
//     entry not active again until the system applies it.
type SysResolver interface {
	// Read returns the managed entries. It writes nothing.
	Read(ctx context.Context) (ResolverState, error)
	// Write creates the entry for e.Domain or replaces it.
	Write(ctx context.Context, e ResolverEntry) error
	// Remove deletes the entry for a domain.
	Remove(ctx context.Context, domain policy.Domain) error
}

// IfInventory reports the network interfaces of the host.
type IfInventory interface {
	// Interfaces returns a snapshot of the current interfaces, in a
	// stable order, or the Compiler sorts them.
	Interfaces(ctx context.Context) ([]Interface, error)
	// Changes receives a value after the interfaces change. The value
	// carries no data: take a new snapshot. The inventory may merge
	// several changes into one value.
	Changes() <-chan struct{}
}
