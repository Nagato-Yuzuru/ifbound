package reconcile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"slices"

	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

// The platform contract. A Compiler and a Backend come as a pair from one
// platform package: they share the mapping from a policy name to a kernel
// table, so a table that AddEntries creates is the table that the rules
// of a compiled ruleset refer to.
//
// Every call that takes a context honors it and finishes in bounded time.
// The daemon calls them from one goroutine and waits for each one.

// Interface is one network interface in an inventory snapshot. Its class
// is certain, uncertain, or absent:
//
//   - Class holds a class that is certain.
//   - Uncertain makes an interface whose properties do not show its
//     class. The interface can have one of the possible classes, or no
//     class. Possible returns them.
//   - The zero Class without possible classes means no class.
//
// A Compiler uses an uncertain class in the safe direction of each
// constraint: a class in deny_via selects an interface that can have the
// class, and a class in only_via selects only an interface that has the
// class for certain.
type Interface struct {
	Name string
	// Class is the zero Class when the class is not certain.
	Class policy.Class
	// possible is used only while Class is zero, so a certain class
	// never has possible classes next to it.
	possible classSet
}

// Uncertain returns an interface that can have each of classes, or no
// class. It ignores the zero Class, which is not a class.
func Uncertain(name string, classes ...policy.Class) Interface {
	var s classSet
	for _, c := range classes {
		s |= 1 << c
	}
	return Interface{Name: name, possible: s &^ 1}
}

// Possible returns the possible classes of i in ascending order. It
// returns nil when i has a certain class or no class.
func (i Interface) Possible() []policy.Class {
	if i.Class != 0 {
		return nil
	}
	var out []policy.Class
	for c := range policy.Class(64) {
		if i.possible&(1<<c) != 0 {
			out = append(out, c)
		}
	}
	return out
}

// classSet holds class c as bit c. Every known class is below 64. A
// larger value is not a class, and its shift sets no bit.
type classSet uint64

// Accounts is a snapshot of the user and group accounts of the host. A
// platform reader fills it. The zero Accounts knows no account.
type Accounts struct {
	Users  map[string]uint32 // user name to uid
	Groups map[string]uint32 // group name to gid
}

// Ruleset is a compiled ruleset. Its body is in the format of one Backend,
// and the Reconciler never reads it. The Reconciler compares rulesets by
// ID only. Build one with NewRuleset.
type Ruleset struct {
	id       string
	body     []byte
	problems []Problem
}

// NewRuleset returns a ruleset with an ID that is a digest of body. Equal
// bodies get equal IDs, so a Backend can derive the ID of the loaded
// ruleset from the kernel and the Reconciler can skip a load that changes
// nothing. problems are the faults that the Compiler worked around; they
// do not change the ID.
func NewRuleset(body []byte, problems ...Problem) Ruleset {
	sum := sha256.Sum256(body)
	return Ruleset{id: hex.EncodeToString(sum[:]), body: bytes.Clone(body), problems: slices.Clone(problems)}
}

// ID identifies the ruleset. The zero Ruleset has the empty ID, which is
// also the ID that a Backend reports when no ruleset is loaded.
func (r Ruleset) ID() string { return r.id }

// Body returns a copy of the ruleset text.
func (r Ruleset) Body() []byte { return bytes.Clone(r.body) }

// Problems returns a copy of the faults that the Compiler worked around,
// for example a scope that it dropped because an account is unknown.
func (r Ruleset) Problems() []Problem { return slices.Clone(r.problems) }

// Compiler turns policies, interfaces, and accounts into a ruleset.
//
// Contract:
//   - Compile is a pure function: equal inputs give equal rulesets. If
//     the result depends on the order of ifaces, Compile sorts them first.
//     It does not change accounts.
//   - The ruleset refers to exactly one table per policy, through the
//     table-name mapping that the paired Backend uses.
//   - A selector that depends on the inventory (a glob or a class) does
//     not select an interface that is not in ifaces. So only_via fails
//     closed for a new interface, and deny_via fails open for it until
//     the next convergence compiles it in. That window is accepted.
//   - When the Compiler cannot make a part of a policy hold as written,
//     it either fails, or it writes a stricter rule and reports the fault
//     in Ruleset.Problems. It never writes a weaker rule. An uncertain
//     class is not such a fault: the Compiler writes the stricter rule
//     that the Interface documentation gives and reports no Problem,
//     because the class of such an interface stays uncertain for as
//     long as the interface exists.
type Compiler interface {
	// Compile uses accounts for the account names in a scope.
	Compile(policies []policy.Policy, ifaces []Interface, accounts Accounts) (Ruleset, error)
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
//   - Load replaces the ruleset atomically. It creates each table that the
//     ruleset declares and that is missing, empty. It never drops or fills
//     a table, and never changes the content of one.
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
//     report "" or an ID that differs from the loaded one. A rule that
//     another tool adds below the ruleset (for example in a sub-anchor
//     that a rule of the ruleset refers to) is such a change, and Load
//     removes it.
//   - While the firewall is disabled, Read and LoadedID report "": no
//     rule is in effect. Load enables the firewall again.
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

// ResolverState is the set of resolver entries that ifbound manages now.
type ResolverState struct {
	Entries []ResolverEntry // at most one entry per domain
	// Problems are conflicts with entries that ifbound does not manage.
	Problems []Problem
	// Shadowed lists the domain of each resolver that ifbound does not
	// manage and that is at or below the domain of an entry, most
	// specific first (most labels first, then by name), without
	// duplicates. Such a resolver can take the names of the entry, and
	// only a probe below its domain can show where those names go. Each
	// one also has a Problem.
	Shadowed []policy.Domain
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
//   - Read derives the entries from the system state, never from a
//     cache. An entry that Read reports is present, but a platform can
//     apply it after a delay; only a probe below its domain shows where
//     its names go.
//   - Each Write, also of unchanged content, can make the system flush
//     its whole DNS cache (macOS does this), and it can make the system
//     apply the entry again after a delay.
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
