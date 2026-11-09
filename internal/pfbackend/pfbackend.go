// Package pfbackend implements reconcile.Backend with pfctl and with ioctl
// calls on /dev/pf on macOS. It is the only part of ifbound that writes pf.
//
// pf is a shared resource. The Backend changes only the ifbound anchor
// Anchor, its tables, and its sub-anchors. It reads the main ruleset and
// the other anchors, and it reports what voids the ifbound rules there.
//
// Load replaces the rules of the anchor in one transaction with
// "pfctl -a <anchor> -f -". The ruleset of pfrules declares each table
// "persist" and without addresses, so a reload keeps the entries of the
// tables. The table entries change only through AddEntries,
// RemoveEntries, and DropTable.
//
// The ID of the loaded ruleset is in the label of a sentinel rule that
// Load adds at the end of the ruleset. Read and LoadedID read the label
// from the kernel at each call. They report no ruleset ("") when the
// label is missing, when the anchor holds a rule that the ruleset of
// ifbound does not write (a rule in a sub-anchor, which pf evaluates for
// the packets that the anchor rule matches, a filter rule at the top
// level that is not a block or an anchor rule, or a rule of another kind,
// for example a NAT rule), or when pf is disabled. pf
// replaces the rules of an anchor only as a whole, so another tool that
// loads or flushes the anchor also removes the label. Load then repairs
// the state: it loads the rules, flushes the rules of every sub-anchor,
// and enables pf.
//
// They also report no ruleset after a Load or an AddEntries that did not
// finish, for example when the end of the states failed. The Reconciler
// then loads again, and that Load ends the states. This mark is in
// memory: a restart loses it.
//
// pf keeps a sub-anchor after the rule that refers to it goes away, and
// a flush does not remove it. The sub-anchor of a removed policy thus
// stays. It is not evaluated, and Load keeps it empty.
//
// The Backend never disables pf. Each Load takes a pf reference through
// the Device and gives back the references that ifbound held before, so
// ifbound holds one reference also when another tool enabled pf first.
// Each reference that ifbound holds goes into the label of a token rule.
// A pf reference outlives the process, so a restarted Backend reads its
// references from these labels. Unload gives the references back and
// flushes the anchor.
//
// pf gives a released token value again, also to another process at
// once. So the label holds the token value, the creation time that the
// kernel keeps (in whole seconds), and the pid of the process that took
// the reference. The Backend gives back a reference only when the kernel
// lists one with the same three. Else the value names the reference of
// another process, and the Backend leaves it. The ifboundd process takes
// the references itself, so its pid differs from the pid of a pfctl
// process that takes a reference in the same second. A reference that
// the Backend fails to give back stays in the labels, and the next Load
// or Unload tries again.
//
// Every pfctl call goes through a Runner, and every ioctl call goes
// through a Device, so the logic runs without pf and without root.
package pfbackend

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/logattr"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
	"github.com/Nagato-Yuzuru/ifbound/pf"
)

const (
	// Anchor is the ifbound anchor. pf evaluates the anchors below
	// com.apple in byte order of the name, and "000.ifbound" comes before
	// the anchors of macOS.
	Anchor = "com.apple/000.ifbound"
	// appleAnchor is the parent of Anchor. The main ruleset of macOS
	// refers to its children with the rule `anchor "com.apple/*"`.
	appleAnchor = "com.apple"
	// EnableInterval is the minimum time between two enables of a
	// disabled pf. It stops a fight with another tool that disables pf
	// again and again.
	EnableInterval = 10 * time.Second
	// cleanupWait bounds Unload. It does not use the context of the
	// caller.
	cleanupWait = 10 * time.Second
)

var (
	errPfctl     = errors.New("pfctl failed")
	errRulesetID = errors.New("ruleset ID is not a digest")
	errEntry     = errors.New("invalid table entry")
	errConflict  = errors.New("a negated entry for the same address stays in the table")
	errDisabled  = errors.New("pf is disabled")
	errNoRef     = errors.New("the kernel does not list the new pf reference")
)

// noTable is the message of pfctl for a table that does not exist.
const noTable = "Table does not exist."

// Device is the part of /dev/pf that the Backend uses through ioctl.
// *pf.Handle implements it.
type Device interface {
	Status() (pf.Status, error)
	Rules(rs pf.Ruleset) ([]pf.Rule, error)
	Anchors(anchor string) ([]string, error)
	CreateTable(t pf.Table) error
	AddAddrs(t pf.Table, addrs []pf.Addr) ([]pf.Feedback, error)
	DeleteAddrs(t pf.Table, addrs []pf.Addr) ([]pf.Feedback, error)
	Addrs(t pf.Table) ([]pf.Addr, error)
	KillStates(dst netip.Prefix) error
	StartRef() (uint64, error)
	StopRef(token uint64) error
	Refs() ([]pf.Ref, error)
}

var _ Device = (*pf.Handle)(nil)

// Backend implements reconcile.Backend with pfctl and with ioctl calls
// on /dev/pf. It is not safe for concurrent use. Build one with New.
type Backend struct {
	run Runner
	dev Device
	now func() time.Time
	log *slog.Logger
	// tokens are the pf references that ifbound holds, or none when it
	// holds none or does not know them yet.
	tokens []token
	// enabledAt is the time of the last enable of a disabled pf.
	enabledAt time.Time
	// unfinished is true from the start of a Load until it finishes, and
	// after an AddEntries that did not end the states.
	unfinished bool
}

var _ reconcile.Backend = (*Backend)(nil)

// New returns a Backend that runs pfctl through run (Exec{Path: Path} on
// macOS) and calls ioctl through dev (a handle from pf.Open on macOS). Now
// is the clock of the rate limit of the enable. Log gets a warning each
// time the Backend enables pf.
func New(run Runner, dev Device, now func() time.Time, log *slog.Logger) *Backend {
	return &Backend{run: run, dev: dev, now: now, log: log}
}

// Read implements reconcile.Backend. Tables holds every table of the
// anchor with its entries. A negated entry is not in Tables. pf uses the
// longest match, so a negated entry inside an entry of its table exempts
// its addresses from that entry. Read then reports a Problem that voids
// the enforcement, and it leaves the entry out of Tables: the Reconciler
// adds the entry again, and AddEntries deletes the negated entry.
func (b *Backend) Read(ctx context.Context) (reconcile.BackendState, error) {
	enabled, id, err := b.loaded()
	if err != nil {
		return reconcile.BackendState{}, err
	}
	tables, negated, err := b.tables(ctx)
	if err != nil {
		return reconcile.BackendState{}, err
	}
	problems, err := b.problems(ctx, enabled, tables, negated)
	if err != nil {
		return reconcile.BackendState{}, err
	}
	for name, neg := range negated {
		tables[name] = slices.DeleteFunc(tables[name], func(e netip.Prefix) bool {
			return slices.ContainsFunc(neg, func(n netip.Prefix) bool { return inside(n, e) })
		})
	}
	return reconcile.BackendState{Ruleset: id, Tables: tables, Problems: problems}, nil
}

// LoadedID implements reconcile.Backend. It starts no pfctl process: it
// reads the pf status and the rules through ioctl.
func (b *Backend) LoadedID(context.Context) (string, error) {
	_, id, err := b.loaded()
	return id, err
}

// loaded reads whether pf is enabled and the ID of the loaded ruleset.
// The ID is "" when pf is disabled: no rule is in effect then. When the
// Backend knows no token, it takes the tokens from the anchor, where an
// earlier process of ifbound wrote them.
func (b *Backend) loaded() (enabled bool, id string, err error) {
	enabled, err = b.enabled()
	if err != nil || !enabled {
		return false, "", err
	}
	id, tokens, err := b.readAnchor()
	if err != nil {
		return true, "", err
	}
	if len(b.tokens) == 0 {
		b.tokens = tokens
	}
	if b.unfinished {
		return true, "", nil
	}
	return true, id, nil
}

// otherKinds returns the rulesets besides the filter rules that Load
// replaces in the anchor ("pfctl -f" loads them all). The ruleset of
// ifbound writes none of them. The main ruleset of macOS evaluates them
// through its nat-anchor, rdr-anchor, and scrub-anchor rules.
func otherKinds() []pf.RulesetKind {
	return []pf.RulesetKind{pf.RulesetScrub, pf.RulesetNAT, pf.RulesetBINAT, pf.RulesetRDR}
}

// subKinds returns the rulesets that Load flushes in each sub-anchor
// ("pfctl -F rules" flushes them). The anchor holds no nat-anchor or
// rdr-anchor rule, so pf never evaluates the other rulesets of a
// sub-anchor.
func subKinds() []pf.RulesetKind {
	return []pf.RulesetKind{pf.RulesetFilter, pf.RulesetScrub}
}

// readAnchor reads the rules of the anchor and of every anchor below it.
// It returns the ruleset ID and the tokens, as parseRules does. The ID is
// also "" when the anchor holds a rule of another kind than filter, or
// when an anchor below holds a filter or scrub rule. An anchor below
// counts also when no rule calls it: Load flushes each one, so a rule
// there comes from another tool.
//
// The check sees only the changes that Load repairs. Else LoadedID gives
// "" after each Load, and the Reconciler loads again and again.
//
// A missing anchor holds no ruleset. A ruleset that changes during the
// read is an error: the caller tries again later.
func (b *Backend) readAnchor() (string, []token, error) {
	rules, err := b.dev.Rules(pf.Ruleset{Anchor: Anchor})
	if errors.Is(err, pf.ErrNotFound) {
		return "", nil, nil
	}
	if err != nil {
		return "", nil, fmt.Errorf("reading the rules of the anchor: %w", err)
	}
	id, tokens, foreign := parseRules(rules)
	if !foreign {
		foreign, err = b.holdsRules(Anchor, otherKinds())
	}
	if err == nil && !foreign {
		foreign, err = b.belowHoldsRules(Anchor)
	}
	if err != nil {
		return "", tokens, err
	}
	if foreign {
		return "", tokens, nil
	}
	return id, tokens, nil
}

// holdsRules reports whether a ruleset of one of the kinds in the anchor
// holds a rule.
func (b *Backend) holdsRules(anchor string, kinds []pf.RulesetKind) (bool, error) {
	for _, k := range kinds {
		rs := pf.Ruleset{Anchor: anchor, Kind: k}
		rules, err := b.dev.Rules(rs)
		if err != nil {
			return false, fmt.Errorf("reading the %s: %w", rs, err)
		}
		if len(rules) > 0 {
			return true, nil
		}
	}
	return false, nil
}

// belowHoldsRules reports whether an anchor below the anchor holds a rule
// of the kinds in subKinds.
func (b *Backend) belowHoldsRules(anchor string) (bool, error) {
	children, err := b.dev.Anchors(anchor)
	if err != nil {
		return false, fmt.Errorf("listing the anchors below %s: %w", anchor, err)
	}
	for _, c := range children {
		path := anchor + "/" + c
		if held, err := b.holdsRules(path, subKinds()); err != nil || held {
			return held, err
		}
		if held, err := b.belowHoldsRules(path); err != nil || held {
			return held, err
		}
	}
	return false, nil
}

func (b *Backend) enabled() (bool, error) {
	s, err := b.dev.Status()
	if err != nil {
		return false, fmt.Errorf("reading the pf status: %w", err)
	}
	return s.Running, nil
}

// Load implements reconcile.Backend. It takes a new pf reference (this
// enables pf when it is disabled), loads the ruleset with the sentinel
// rules, gives back the references that ifbound held before, flushes the
// rules of every sub-anchor, and then ends the states to every entry of
// every table of the anchor. The rate limit can refuse to enable pf: Load
// then fails, and a later Load tries again.
//
// The labels of the loaded ruleset hold the new reference and the old
// ones. So an old reference that Load fails to give back stays in the
// labels. When the load of the anchor fails, no label holds the new
// reference, and Load gives it back at once.
func (b *Backend) Load(ctx context.Context, rs reconcile.Ruleset) error {
	s, err := sentinel(rs.ID())
	if err != nil {
		return err
	}
	b.unfinished = true
	enabled, _, err := b.loaded()
	if err != nil {
		return err
	}
	tok, err := b.reference(ctx, enabled)
	if err != nil {
		return err
	}
	old := b.tokens
	body := rs.Body()
	if len(body) > 0 && body[len(body)-1] != '\n' {
		body = append(body, '\n')
	}
	body = append(append(body, s...), tokenRule(tok)...)
	for _, t := range old {
		body = append(body, tokenRule(t)...)
	}
	if _, err := b.pfctl(ctx, body, "-a", Anchor, "-f", "-"); err != nil {
		b.abandon(ctx, tok)
		return fmt.Errorf("loading the anchor: %w", err)
	}
	kept, err := b.giveBack(old)
	if err != nil {
		// The new token keeps pf enabled. An old token that stays only
		// keeps pf enabled after uninstall, and its label keeps it known,
		// so Load goes on.
		b.log.WarnContext(ctx, "cannot give back an old pf token",
			slog.String(logattr.ErrorType, logattr.ErrorTypePFToken), slog.String(logattr.ExceptionMessage, err.Error()))
	}
	b.tokens = append([]token{tok}, kept...)
	if err := b.flushSubAnchors(ctx); err != nil {
		return err
	}
	tables, _, err := b.tables(ctx)
	if err != nil {
		return err
	}
	if err := b.killStates(slices.Concat(slices.Collect(maps.Values(tables))...)); err != nil {
		return err
	}
	b.unfinished = false
	return nil
}

// flushSubAnchors removes the rules of each anchor below the ifbound
// anchor. A rule there comes from another tool.
func (b *Backend) flushSubAnchors(ctx context.Context) error {
	out, err := b.pfctl(ctx, nil, "-a", Anchor, "-sA", "-v")
	if err != nil {
		return err
	}
	for _, sub := range parseNames(out.Stdout) {
		if _, err := b.pfctl(ctx, nil, "-a", sub, "-F", "rules"); err != nil {
			return fmt.Errorf("flushing sub-anchor %s: %w", sub, err)
		}
	}
	return nil
}

// reference takes a new pf reference and returns its token. pf stays
// enabled while any reference exists, so ifbound needs its own: without
// it, pf stops when another tool gives back the reference that enabled
// pf. A new reference at each Load also replaces a reference that pf no
// longer holds (after "pfctl -d" and an enable by another tool).
//
// On a disabled pf the call enables pf, at most once in EnableInterval,
// and logs a warning. A disabled pf has dropped every reference, so the
// Backend forgets its old tokens then.
func (b *Backend) reference(ctx context.Context, enabled bool) (token, error) {
	if !enabled {
		now := b.now()
		if !b.enabledAt.IsZero() && now.Sub(b.enabledAt) < EnableInterval {
			return token{}, fmt.Errorf("%w: the last enable was less than %s ago", errDisabled, EnableInterval)
		}
		b.enabledAt = now
		b.tokens = nil
	}
	value, err := b.dev.StartRef()
	if err != nil {
		return token{}, fmt.Errorf("enabling pf: %w", err)
	}
	tok, err := b.identify(value)
	if err != nil {
		// Without its creation time and pid no label can name the
		// reference, so it goes back at once. The value is still the
		// reference of this process: nothing gave it back.
		if serr := b.dev.StopRef(value); serr != nil {
			return token{}, errors.Join(err, serr)
		}
		return token{}, err
	}
	if !enabled {
		b.log.WarnContext(ctx, "pf was disabled; ifbound enabled it", slog.String(logattr.PFAnchor, Anchor))
	}
	return tok, nil
}

// identify reads the creation time and the pid of the reference with the
// token value from the kernel.
func (b *Backend) identify(value uint64) (token, error) {
	refs, err := b.dev.Refs()
	if err != nil {
		return token{}, fmt.Errorf("reading the pf references: %w", err)
	}
	i := slices.IndexFunc(refs, func(r pf.Ref) bool { return r.Token == value })
	if i < 0 {
		return token{}, fmt.Errorf("%w: %d", errNoRef, value)
	}
	return token{value: value, created: refs[i].Created.Unix(), pid: refs[i].PID}, nil
}

// abandon gives back the reference of a token that no label holds. When
// the give-back fails, the Backend keeps the token, and the next Load
// writes it into a label.
func (b *Backend) abandon(ctx context.Context, t token) {
	kept, err := b.giveBack([]token{t})
	if err != nil {
		b.log.WarnContext(ctx, "cannot give back a new pf token",
			slog.String(logattr.ErrorType, logattr.ErrorTypePFToken), slog.String(logattr.ExceptionMessage, err.Error()))
	}
	b.tokens = append(b.tokens, kept...)
}

// Unload removes the enforcement of ifbound from pf. It is for
// uninstall. It gives back the pf references of ifbound, then flushes
// the rules and the tables of the anchor. It never disables pf and never
// flushes all of the anchor, so pf stays enabled while other references
// exist.
//
// The references go back first. Their labels are in the rules of the
// anchor, so after a stop between the two steps the labels stay, and a
// second Unload, also in a new process, reads the tokens from them. The
// kernel then lists no reference that matches a label exactly, and the
// second Unload only removes the rules. When the Backend knows no token,
// Unload reads them from the anchor first. A token that pf no longer
// holds counts as given back. Thus Unload is idempotent.
//
// Unload uses a new context with a timeout of cleanupWait, so a canceled
// caller still removes the enforcement.
func (b *Backend) Unload(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupWait)
	defer cancel()
	if _, _, err := b.loaded(); err != nil {
		return err
	}
	if err := b.release(); err != nil {
		return err
	}
	if _, err := b.pfctl(ctx, nil, "-a", Anchor, "-F", "rules"); err != nil {
		return fmt.Errorf("flushing the rules of the anchor: %w", err)
	}
	if _, err := b.pfctl(ctx, nil, "-a", Anchor, "-F", "Tables"); err != nil {
		return fmt.Errorf("flushing the tables of the anchor: %w", err)
	}
	return nil
}

// release gives back the pf references of ifbound, so pf stays enabled
// only while other references exist. With no token it does nothing. A
// token that fails to go back stays known.
func (b *Backend) release() error {
	kept, err := b.giveBack(b.tokens)
	b.tokens = kept
	return err
}

// giveBack gives back each token that pf still holds as the same
// reference: the kernel lists a reference with its value, its creation
// time, and its pid. A token that pf no longer holds (pf was disabled,
// which drops every reference, or another process holds the value now)
// counts as given back. It returns the tokens that did not go back.
func (b *Backend) giveBack(tokens []token) ([]token, error) {
	if len(tokens) == 0 {
		return nil, nil
	}
	refs, err := b.dev.Refs()
	if err != nil {
		return tokens, fmt.Errorf("reading the pf references: %w", err)
	}
	var kept []token
	var errs []error
	for _, t := range tokens {
		if !slices.ContainsFunc(refs, t.is) {
			continue
		}
		// pf.ErrNotFound: "pfctl -d" dropped the reference after the read.
		if err := b.dev.StopRef(t.value); err != nil && !errors.Is(err, pf.ErrNotFound) {
			kept = append(kept, t)
			errs = append(errs, err)
		}
	}
	return kept, errors.Join(errs...)
}

// AddEntries implements reconcile.Backend. It starts no pfctl process.
// It creates the table when it is missing. An entry whose address the
// table holds as a negated entry is not added; AddEntries then deletes the
// negated entry and adds the entry again. It also deletes each negated
// entry inside an added prefix, also when the table holds the prefix
// already: pf uses the longest match, so that entry exempts its addresses
// from the prefix. At the end it ends the states to the entries.
func (b *Backend) AddEntries(_ context.Context, table policy.Name, entries []netip.Prefix) (err error) {
	addrs, err := tableAddrs(entries, false)
	if err != nil {
		return err
	}
	t := pf.Table{Anchor: Anchor, Name: string(table)}
	conflicts, err := b.add(t, addrs)
	if err != nil {
		return err
	}
	// The table holds new entries now. If a later step fails, the states
	// to them can stay, and the Reconciler does not add them again: mark
	// the work as not finished, so that a Load follows.
	defer func() {
		if err != nil {
			b.unfinished = true
		}
	}()
	if len(conflicts) > 0 {
		negated, _ := tableAddrs(conflicts, true) //nolint:errcheck // the entries are valid: they passed tableAddrs before
		if _, err := b.dev.DeleteAddrs(t, negated); err != nil {
			return fmt.Errorf("deleting negated entries of table %s: %w", table, err)
		}
		again, _ := tableAddrs(conflicts, false) //nolint:errcheck // as above
		left, err := b.add(t, again)
		if err != nil {
			return err
		}
		if len(left) > 0 {
			return fmt.Errorf("adding to table %s: %w: %v", table, errConflict, left)
		}
	}
	if err := b.deleteHoles(t, entries); err != nil {
		return err
	}
	return b.killStates(entries)
}

// tableAddrs turns entries into table addresses, all negated or none.
func tableAddrs(entries []netip.Prefix, negated bool) ([]pf.Addr, error) {
	addrs := make([]pf.Addr, 0, len(entries))
	for _, e := range entries {
		if !e.IsValid() {
			return nil, fmt.Errorf("%w: %v", errEntry, e)
		}
		addrs = append(addrs, pf.Addr{Prefix: e.Masked(), Negated: negated})
	}
	return addrs, nil
}

// deleteHoles deletes the negated entries of the table t that are inside
// a prefix of entries. A host entry holds no other entry, so a call with
// host entries only reads nothing.
func (b *Backend) deleteHoles(t pf.Table, entries []netip.Prefix) error {
	if !slices.ContainsFunc(entries, func(e netip.Prefix) bool { return !e.IsSingleIP() }) {
		return nil
	}
	addrs, err := b.dev.Addrs(t)
	if err != nil {
		return fmt.Errorf("reading table %s: %w", t.Name, err)
	}
	var holes []pf.Addr
	for _, a := range addrs {
		if a.Negated && slices.ContainsFunc(entries, func(e netip.Prefix) bool { return inside(a.Prefix, e) }) {
			holes = append(holes, a)
		}
	}
	if len(holes) == 0 {
		return nil
	}
	if _, err := b.dev.DeleteAddrs(t, holes); err != nil {
		return fmt.Errorf("deleting negated entries of table %s: %w", t.Name, err)
	}
	return nil
}

// inside reports whether the prefix n is inside the prefix p and longer,
// so that pf matches n first for the addresses of n.
func inside(n, p netip.Prefix) bool {
	p = p.Masked()
	return p.Bits() < n.Bits() && p.Contains(n.Addr())
}

// add adds addrs to the table t, and creates t when it is missing, as
// "pfctl -T add" does. It returns the prefixes that the table holds with
// the other negation.
func (b *Backend) add(t pf.Table, addrs []pf.Addr) ([]netip.Prefix, error) {
	fb, err := b.dev.AddAddrs(t, addrs)
	if errors.Is(err, pf.ErrNotFound) {
		if err := b.dev.CreateTable(t); err != nil {
			return nil, fmt.Errorf("creating table %s: %w", t.Name, err)
		}
		fb, err = b.dev.AddAddrs(t, addrs)
	}
	if err != nil {
		return nil, fmt.Errorf("adding to table %s: %w", t.Name, err)
	}
	var conflicts []netip.Prefix
	for i, f := range fb {
		if f == pf.FeedbackConflict {
			conflicts = append(conflicts, addrs[i].Prefix)
		}
	}
	return conflicts, nil
}

// RemoveEntries implements reconcile.Backend. A missing table holds no
// entry, so it is not an error.
func (b *Backend) RemoveEntries(ctx context.Context, table policy.Name, entries []netip.Prefix) error {
	if len(entries) == 0 {
		return nil
	}
	in, err := entryLines(entries)
	if err != nil {
		return err
	}
	out, err := b.run.Run(ctx, in, "-a", Anchor, "-t", string(table), "-T", "delete", "-f", "-")
	if err != nil && !strings.Contains(string(out.Stderr), noTable) {
		return fmt.Errorf("removing from table %s: %w: %v: %s", table, errPfctl, err, stderrText(out.Stderr))
	}
	return nil
}

// DropTable implements reconcile.Backend. "pfctl -T kill" succeeds for a
// missing table.
func (b *Backend) DropTable(ctx context.Context, table policy.Name) error {
	if _, err := b.pfctl(ctx, nil, "-a", Anchor, "-t", string(table), "-T", "kill"); err != nil {
		return fmt.Errorf("dropping table %s: %w", table, err)
	}
	return nil
}

// killStates ends every state to an address in entries, from any source.
// ifbound keeps no state, but a state that another rule keeps lets the
// packets of a connection skip the rules.
//
// It ends the states to each entry with one ioctl. It does not read the
// state table first: one ioctl costs microseconds. The caller changed the
// rules or the tables first, so a new state to an entry can come only
// from a rule that pf evaluates before the ifbound rules, which Read
// reports as a voiding Problem.
func (b *Backend) killStates(entries []netip.Prefix) error {
	for _, e := range entries {
		if err := b.dev.KillStates(e.Masked()); err != nil {
			return fmt.Errorf("ending the states to %s: %w", e, err)
		}
	}
	return nil
}

// tables reads every table of the anchor and its entries.
func (b *Backend) tables(ctx context.Context) (map[policy.Name][]netip.Prefix, map[policy.Name][]netip.Prefix, error) {
	out, err := b.pfctl(ctx, nil, "-a", Anchor, "-sT")
	if err != nil {
		return nil, nil, err
	}
	tables := make(map[policy.Name][]netip.Prefix)
	negated := make(map[policy.Name][]netip.Prefix)
	for _, name := range parseNames(out.Stdout) {
		show, err := b.pfctl(ctx, nil, "-a", Anchor, "-t", name, "-T", "show")
		if err != nil {
			return nil, nil, fmt.Errorf("reading table %s: %w", name, err)
		}
		entries, neg, err := parseEntries(show.Stdout)
		if err != nil {
			return nil, nil, fmt.Errorf("reading table %s: %w", name, err)
		}
		tables[policy.Name(name)] = entries
		if len(neg) > 0 {
			negated[policy.Name(name)] = neg
		}
	}
	return tables, negated, nil
}

// pfctl runs pfctl and wraps a failure with the stderr of the command.
func (b *Backend) pfctl(ctx context.Context, stdin []byte, args ...string) (Output, error) {
	out, err := b.run.Run(ctx, stdin, args...)
	if err != nil {
		return out, fmt.Errorf("%w: pfctl %s: %v: %s", errPfctl, strings.Join(args, " "), err, stderrText(out.Stderr))
	}
	return out, nil
}

// entryLines writes one entry per line, for "pfctl -T ... -f -".
func entryLines(entries []netip.Prefix) ([]byte, error) {
	in := []byte{}
	for _, e := range entries {
		if !e.IsValid() {
			return nil, fmt.Errorf("%w: %v", errEntry, e)
		}
		in = append(in, e.Masked().String()+"\n"...)
	}
	return in, nil
}
