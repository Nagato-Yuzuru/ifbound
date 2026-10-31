// Package pfbackend implements reconcile.Backend with pfctl on macOS. It
// is the only part of ifbound that writes pf.
//
// pf is a shared resource. The Backend changes only the ifbound anchor
// Anchor, its tables, and its sub-anchors. It reads the main ruleset and
// the other anchors, and it reports what voids the ifbound rules there.
//
// Load replaces the rules of the anchor in one transaction with
// "pfctl -a <anchor> -f -". The ruleset of pfrules declares each table
// "persist" and without addresses, so a reload keeps the entries of the
// tables. The table entries change only with "-T add", "-T delete", and
// "-T kill".
//
// The ID of the loaded ruleset is in the label of a sentinel rule that
// Load adds at the end of the ruleset. Read and LoadedID read the label
// from the kernel at each call. They report no ruleset ("") when the
// label is missing, when the anchor holds a rule that the ruleset of
// ifbound does not write (a rule in a sub-anchor, which pf evaluates for
// the packets that the anchor rule matches, or a rule at the top level
// that is not a block or an anchor rule), or when pf is disabled. pf
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
// The Backend never runs "pfctl -d". Each Load takes a pf reference with
// "pfctl -E" and gives back the references that ifbound held before, so
// ifbound holds one reference also when another tool enabled pf first.
// The token of each reference that ifbound holds goes into the label of
// a token rule. A pf token outlives the process, so a restarted Backend
// reads its tokens from these labels. Unload gives the tokens back and
// flushes the anchor.
//
// pf gives a released token value again, also to another process. So a
// token is the value together with the time when pf created it, and the
// Backend gives back a token only when "pfctl -s References" shows the
// same pair. Else the value names the reference of another process, and
// the Backend leaves it. A token that the Backend fails to give back
// stays in the labels, and the next Load or Unload tries again.
//
// Every pfctl call goes through a Runner, so the logic runs without pf
// and without root.
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

	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
)

const (
	// Anchor is the ifbound anchor. pf evaluates the anchors below
	// com.apple in byte order of the name, and "000.ifbound" comes before
	// the anchors of macOS.
	Anchor = "com.apple/000.ifbound"
	// appleAnchor is the parent of Anchor. The main ruleset of macOS
	// refers to its children with the rule `anchor "com.apple/*"`.
	appleAnchor = "com.apple"
	// EnableInterval is the minimum time between two "pfctl -E" calls. It
	// stops a fight with another tool that disables pf again and again.
	EnableInterval = 10 * time.Second
	// cleanupWait bounds Unload and the give-back of a token that no
	// label holds. They do not use the context of the caller.
	cleanupWait = 10 * time.Second
)

var (
	errPfctl     = errors.New("pfctl failed")
	errRulesetID = errors.New("ruleset ID is not a digest")
	errEntry     = errors.New("invalid table entry")
	errConflict  = errors.New("a negated entry for the same address stays in the table")
	errDisabled  = errors.New("pf is disabled")
)

// noTable is the message of pfctl for a table that does not exist.
const noTable = "Table does not exist."

// Backend implements reconcile.Backend with pfctl. It is not safe for
// concurrent use. Build one with New.
type Backend struct {
	run Runner
	now func() time.Time
	log *slog.Logger
	// tokens are the pf references that ifbound holds, or none when it
	// holds none or does not know them yet.
	tokens []token
	// enabledAt is the time of the last "pfctl -E" call on a disabled pf.
	enabledAt time.Time
	// unfinished is true from the start of a Load until it finishes, and
	// after an AddEntries that did not end the states.
	unfinished bool
}

var _ reconcile.Backend = (*Backend)(nil)

// New returns a Backend that runs pfctl through run (Exec{Path: Path} on
// macOS). Now is the clock of the rate limit of "pfctl -E". Log gets a
// warning each time the Backend enables pf.
func New(run Runner, now func() time.Time, log *slog.Logger) *Backend {
	return &Backend{run: run, now: now, log: log}
}

// Read implements reconcile.Backend. Tables holds every table of the
// anchor with its entries. A negated entry is not in Tables. pf uses the
// longest match, so a negated entry inside an entry of its table exempts
// its addresses from that entry. Read then reports a Problem that voids
// the enforcement, and it leaves the entry out of Tables: the Reconciler
// adds the entry again, and AddEntries deletes the negated entry.
func (b *Backend) Read(ctx context.Context) (reconcile.BackendState, error) {
	enabled, id, err := b.loaded(ctx)
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

// LoadedID implements reconcile.Backend. It runs pfctl twice.
func (b *Backend) LoadedID(ctx context.Context) (string, error) {
	_, id, err := b.loaded(ctx)
	return id, err
}

// loaded reads whether pf is enabled and the ID of the loaded ruleset.
// The ID is "" when pf is disabled: no rule is in effect then. When the
// Backend knows no token, it takes the tokens from the anchor, where an
// earlier process of ifbound wrote them.
func (b *Backend) loaded(ctx context.Context) (enabled bool, id string, err error) {
	enabled, err = b.enabled(ctx)
	if err != nil {
		return false, "", err
	}
	out, err := b.pfctl(ctx, nil, "-a", Anchor+"/*", "-sr")
	if err != nil {
		return false, "", err
	}
	if !enabled {
		return false, "", nil
	}
	id, tokens := parseRuleset(out.Stdout)
	if len(b.tokens) == 0 {
		b.tokens = tokens
	}
	// pfctl reports a missing anchor, and a sub-anchor that it cannot
	// read, on stderr and exits with 0. The output can then miss rules.
	if complained(out.Stderr) || b.unfinished {
		return true, "", nil
	}
	return true, id, nil
}

func (b *Backend) enabled(ctx context.Context) (bool, error) {
	out, err := b.pfctl(ctx, nil, "-s", "info")
	if err != nil {
		return false, err
	}
	return parseStatus(out.Stdout)
}

// Load implements reconcile.Backend. It takes a new pf reference (this
// enables pf when it is disabled), loads the ruleset with the sentinel
// rules, gives back the references that ifbound held before, flushes the
// rules of every sub-anchor, and then ends the states to every entry of
// every table of the anchor. The rate limit can refuse to enable pf: Load
// then fails, and a later Load tries again.
//
// The labels of the loaded ruleset hold the new token and the old ones.
// So an old token that Load fails to give back stays in the labels. When
// the load of the anchor fails, no label holds the new token, and Load
// gives it back at once.
func (b *Backend) Load(ctx context.Context, rs reconcile.Ruleset) error {
	s, err := sentinel(rs.ID())
	if err != nil {
		return err
	}
	b.unfinished = true
	enabled, _, err := b.loaded(ctx)
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
	kept, err := b.giveBack(ctx, old)
	if err != nil {
		// The new token keeps pf enabled. An old token that stays only
		// keeps pf enabled after uninstall, and its label keeps it known,
		// so Load goes on.
		b.log.WarnContext(ctx, "cannot give back an old pf token", slog.String("error", err.Error()))
	}
	b.tokens = append([]token{tok}, kept...)
	if err := b.flushSubAnchors(ctx); err != nil {
		return err
	}
	tables, _, err := b.tables(ctx)
	if err != nil {
		return err
	}
	if err := b.killStates(ctx, slices.Concat(slices.Collect(maps.Values(tables))...)); err != nil {
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

// reference takes a new pf reference with "pfctl -E" and returns its
// token. pf stays enabled while any reference exists, so ifbound needs
// its own: without it, pf stops when another tool gives back the
// reference that enabled pf. A new token at each Load also replaces a
// token that pf no longer knows (after "pfctl -d" and an enable by
// another tool).
//
// On a disabled pf the call enables pf, at most once in EnableInterval,
// and logs a warning. A disabled pf has dropped every token, so the
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
	out, err := b.pfctl(ctx, nil, "-E")
	if err != nil {
		return token{}, fmt.Errorf("enabling pf: %w", err)
	}
	value, err := parseToken(out.Stderr)
	if err != nil {
		return token{}, err
	}
	if !enabled {
		b.log.WarnContext(ctx, "pf was disabled; ifbound enabled it", slog.String("anchor", Anchor))
	}
	return token{value: value, created: b.now().Unix()}, nil
}

// abandon gives back the token of a reference that no label holds. It
// uses a new context: the context of the caller can be the cause of the
// failure. When the give-back fails, the Backend keeps the token, and the
// next Load writes it into a label.
func (b *Backend) abandon(ctx context.Context, t token) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupWait)
	defer cancel()
	kept, err := b.giveBack(ctx, []token{t})
	if err != nil {
		b.log.WarnContext(ctx, "cannot give back a new pf token", slog.String("error", err.Error()))
	}
	b.tokens = append(b.tokens, kept...)
}

// Unload removes the enforcement of ifbound from pf. It is for
// uninstall. It gives back the reference tokens of ifbound, then flushes
// the rules and the tables of the anchor. It never disables pf and never
// flushes all of the anchor, so pf stays enabled while other references
// exist.
//
// The tokens go back first. Their labels are in the rules of the anchor,
// so after a stop between the two steps the labels stay, and a second
// Unload, also in a new process, reads the tokens from them. When the
// Backend knows no token, Unload reads them from the anchor first. A
// token that pf no longer holds counts as given back. Thus Unload is
// idempotent.
//
// Unload uses a new context with a timeout of cleanupWait, so a canceled
// caller still gives back the tokens.
func (b *Backend) Unload(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupWait)
	defer cancel()
	if _, _, err := b.loaded(ctx); err != nil {
		return err
	}
	if err := b.release(ctx); err != nil {
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

// release gives back the reference tokens of ifbound, so pf stays
// enabled only while other references exist. With no token it does
// nothing. A token that fails to go back stays known.
func (b *Backend) release(ctx context.Context) error {
	kept, err := b.giveBack(ctx, b.tokens)
	b.tokens = kept
	return err
}

// giveBack gives back each token that pf still holds as the same
// reference: "pfctl -s References" shows its value with its creation
// time. A token that pf no longer holds (pf was disabled, which drops
// every token, or another process holds the value now) counts as given
// back. It returns the tokens that did not go back.
func (b *Backend) giveBack(ctx context.Context, tokens []token) ([]token, error) {
	if len(tokens) == 0 {
		return nil, nil
	}
	out, err := b.pfctl(ctx, nil, "-s", "References")
	if err != nil {
		return tokens, fmt.Errorf("reading the pf references: %w", err)
	}
	held := parseReferences(out.Stdout, b.now())
	var kept []token
	var errs []error
	for _, t := range tokens {
		if !slices.ContainsFunc(held, t.same) {
			continue
		}
		out, err := b.run.Run(ctx, nil, "-X", t.value)
		if err != nil && !tokenGone(out.Stderr) {
			kept = append(kept, t)
			errs = append(errs, fmt.Errorf("%w: pfctl -X: %v: %s", errPfctl, err, stderrText(out.Stderr)))
		}
	}
	return kept, errors.Join(errs...)
}

// AddEntries implements reconcile.Backend. "pfctl -T add" creates the
// table when it is missing. An entry whose address the table holds as a
// negated entry is not added; AddEntries then deletes the negated entry
// and adds the entry again. It also deletes each negated entry inside an
// added prefix, also when the table holds the prefix already: pf uses the
// longest match, so that entry exempts its addresses from the prefix. At
// the end it ends the states to the entries.
func (b *Backend) AddEntries(ctx context.Context, table policy.Name, entries []netip.Prefix) (err error) {
	in, err := entryLines(entries)
	if err != nil {
		return err
	}
	conflicts, err := b.add(ctx, table, in)
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
		var negated []byte
		for _, c := range conflicts {
			negated = append(negated, "!"+c.String()+"\n"...)
		}
		if _, err := b.pfctl(ctx, negated, "-a", Anchor, "-t", string(table), "-T", "delete", "-f", "-"); err != nil {
			return fmt.Errorf("deleting negated entries of table %s: %w", table, err)
		}
		again, _ := entryLines(conflicts) //nolint:errcheck // the entries are valid: the kernel printed them
		left, err := b.add(ctx, table, again)
		if err != nil {
			return err
		}
		if len(left) > 0 {
			return fmt.Errorf("adding to table %s: %w: %v", table, errConflict, left)
		}
	}
	if err := b.deleteHoles(ctx, table, entries); err != nil {
		return err
	}
	return b.killStates(ctx, entries)
}

// deleteHoles deletes the negated entries of table that are inside a
// prefix of entries. A host entry holds no other entry, so a call with
// host entries only reads nothing.
func (b *Backend) deleteHoles(ctx context.Context, table policy.Name, entries []netip.Prefix) error {
	if !slices.ContainsFunc(entries, func(e netip.Prefix) bool { return !e.IsSingleIP() }) {
		return nil
	}
	show, err := b.pfctl(ctx, nil, "-a", Anchor, "-t", string(table), "-T", "show")
	if err != nil {
		return fmt.Errorf("reading table %s: %w", table, err)
	}
	_, negated, err := parseEntries(show.Stdout)
	if err != nil {
		return fmt.Errorf("reading table %s: %w", table, err)
	}
	var holes []byte
	for _, n := range negated {
		if slices.ContainsFunc(entries, func(e netip.Prefix) bool { return inside(n, e) }) {
			holes = append(holes, "!"+n.String()+"\n"...)
		}
	}
	if len(holes) == 0 {
		return nil
	}
	if _, err := b.pfctl(ctx, holes, "-a", Anchor, "-t", string(table), "-T", "delete", "-f", "-"); err != nil {
		return fmt.Errorf("deleting negated entries of table %s: %w", table, err)
	}
	return nil
}

// inside reports whether the prefix n is inside the prefix p and longer,
// so that pf matches n first for the addresses of n.
func inside(n, p netip.Prefix) bool {
	p = p.Masked()
	return p.Bits() < n.Bits() && p.Contains(n.Addr())
}

// add runs "pfctl -v -T add" and returns the conflicting entries.
func (b *Backend) add(ctx context.Context, table policy.Name, in []byte) ([]netip.Prefix, error) {
	out, err := b.pfctl(ctx, in, "-v", "-a", Anchor, "-t", string(table), "-T", "add", "-f", "-")
	if err != nil {
		return nil, fmt.Errorf("adding to table %s: %w", table, err)
	}
	return parseConflicts(out.Stdout)
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
// It reads the state table once and runs one kill for each entry that an
// address of a state is in, so the number of pfctl calls does not grow
// with the number of entries. When a state line does not parse, it runs a
// kill for every entry. The caller changed the rules or the tables first,
// so a new state to an entry can come only from a rule that pf evaluates
// before the ifbound rules, which Read reports as a voiding Problem.
func (b *Backend) killStates(ctx context.Context, entries []netip.Prefix) error {
	if len(entries) == 0 {
		return nil
	}
	out, err := b.pfctl(ctx, nil, "-s", "state")
	if err != nil {
		return fmt.Errorf("reading the states: %w", err)
	}
	addrs, ok := parseStates(out.Stdout)
	for _, e := range entries {
		if ok && !slices.ContainsFunc(addrs, e.Masked().Contains) {
			continue
		}
		from := "0.0.0.0/0"
		if e.Addr().Is6() {
			from = "::/0"
		}
		if _, err := b.pfctl(ctx, nil, "-k", from, "-k", e.Masked().String()); err != nil {
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
