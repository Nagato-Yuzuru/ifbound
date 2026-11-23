package pfbackend_test

// Tests of the entry rule against the kernel model: LoadedID and Read
// report no ruleset when no rule of the main ruleset calls the ifbound
// anchor, Load adds the entry rule then, and Unload removes it. Also the
// Digest.

import (
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/Nagato-Yuzuru/ifbound/internal/pfbackend"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
	"github.com/Nagato-Yuzuru/ifbound/pf"
)

// entryRule is the entry rule as pfctl prints it.
var entryRule = `anchor "` + ifb + `" all label "` + pfbackend.EntryLabel + `"`

// entryRules returns the number of entry rules in the main ruleset.
func (k *kernel) entryRules() int {
	n := 0
	for _, l := range k.filterRules("") {
		if strings.Contains(l, `label "`+pfbackend.EntryLabel+`"`) {
			n++
		}
	}
	return n
}

// flushMain is "pfctl -F rules" of another tool.
func flushMain(t *testing.T, k *kernel) {
	t.Helper()
	if _, err := k.Run(t.Context(), nil, "-F", "rules"); err != nil {
		t.Fatal(err)
	}
}

// Another tool breaks the entry to the anchor: the anchor keeps its rules
// and tables, but no rule of the main ruleset calls it. LoadedID and Read
// report no ruleset, and Load adds the entry rule before the first filter
// rule of the main ruleset. A second Load adds no second entry rule.
func TestLoadRepairsTheEntry(t *testing.T) {
	tests := []struct {
		name   string
		change func(t *testing.T, k *kernel)
	}{
		{"main ruleset flushed", flushMain},
		{"main ruleset replaced", func(_ *testing.T, k *kernel) {
			k.mainRules = []string{"block drop out all", "pass out quick on utun4 all no state"}
		}},
		{"pf disabled and main ruleset flushed", func(t *testing.T, k *kernel) {
			t.Helper()
			k.enabled, k.refs = false, nil // another tool ran pfctl -d
			flushMain(t, k)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRig(t)
			rs := compileRS(t, testPolicies)
			mustLoad(t, r, rs)
			rules := slices.Clone(r.k.rules[ifb])
			tt.change(t, r.k)
			wantNoID(t, r)
			if !slices.Equal(r.k.rules[ifb], rules) {
				t.Fatalf("the change touched the anchor")
			}
			r.clk.t = r.clk.t.Add(pfbackend.EnableInterval)
			for range 2 {
				mustLoad(t, r, rs)
				checkRepaired(t, r, rs)
			}
			if got := r.k.callsWith("DIOCCHANGERULE", "add-head"); len(got) != 1 {
				t.Errorf("two Loads added the entry rule with %v, want one call", got)
			}
		})
	}
}

// checkRepaired checks that the entry rule is the first filter rule of
// the main ruleset and the only one, that LoadedID and Read report the
// ruleset with no voiding Problem, and that the model blocks each
// protected packet.
func checkRepaired(t *testing.T, r *rig, rs reconcile.Ruleset) {
	t.Helper()
	if got := r.k.filterRules(""); len(got) == 0 || got[0] != entryRule {
		t.Errorf("main filter rules after Load = %q, want %q first", got, entryRule)
	}
	if n := r.k.entryRules(); n != 1 {
		t.Errorf("main ruleset holds %d entry rules after Load, want 1", n)
	}
	if got := mustID(t, r); got != rs.ID() {
		t.Errorf("LoadedID after the repair = %q, want %q", got, rs.ID())
	}
	st := mustRead(t, r)
	if st.Ruleset != rs.ID() || len(voiding(st.Problems)) != 0 {
		t.Errorf("Read after the repair = ruleset %q, Problems %+v; want %q and no voiding Problem", st.Ruleset, st.Problems, rs.ID())
	}
	if escapes(t, r.k, onlyVia) {
		t.Error("the model passes a protected packet after the repair")
	}
}

// A rule that another tool adds before the entry rule can pass a
// protected packet. Read reports it, as it does for the stock main
// ruleset.
func TestRuleBeforeTheEntryVoids(t *testing.T) {
	r := newRig(t)
	rs := compileRS(t, testPolicies)
	flushMain(t, r.k)
	mustLoad(t, r, rs)
	r.k.mainRules = slices.Insert(r.k.mainRules, 0, "pass out quick all no state")
	if !escapes(t, r.k, onlyVia) {
		t.Fatal("the model does not pass a protected packet with a pass quick rule first")
	}
	got := voiding(mustRead(t, r).Problems)
	if !slices.ContainsFunc(got, func(p reconcile.Problem) bool { return strings.Contains(p.Text, "comes before the ifbound anchor") }) {
		t.Errorf("voiding Problems = %+v, want one for the rule before the entry rule", got)
	}
}

// A main ruleset that calls the anchor gets no entry rule: Load writes
// nothing into it.
func TestLoadAddsNoEntryWhenTheMainRulesetCallsTheAnchor(t *testing.T) {
	tests := []struct {
		name string
		main []string
	}{
		{"macOS default", nil},
		{"absolute call", []string{`anchor "/com.apple/*" all`}},
		{"call of the anchor itself", []string{`anchor "/` + ifb + `" all`}},
		{"call after another rule", []string{"block drop out all", `anchor "com.apple/*" all`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRig(t)
			if tt.main != nil {
				r.k.mainRules = tt.main
			}
			before := slices.Clone(r.k.mainRules)
			rs := compileRS(t, testPolicies)
			mustLoad(t, r, rs)
			if got := r.k.callsWith("DIOCCHANGERULE"); len(got) != 0 {
				t.Errorf("Load changed the main ruleset: %v", got)
			}
			if !slices.Equal(r.k.mainRules, before) {
				t.Errorf("main ruleset after Load = %v, want %v", r.k.mainRules, before)
			}
			if got := mustID(t, r); got != rs.ID() {
				t.Errorf("LoadedID = %q, want %q", got, rs.ID())
			}
		})
	}
}

// LoadedID runs on each protected ack. It reads the rules of the main
// ruleset only when its version changed since the last read that saw a
// call of the anchor.
func TestLoadedIDReadsTheMainRulesOnlyAfterAChange(t *testing.T) {
	r := newRig(t)
	rs := compileRS(t, testPolicies)
	mustLoad(t, r, rs)
	mainReads := func(from int) (versions, rules int) {
		for _, c := range r.k.calls[from:] {
			switch {
			case slices.Equal(c, []string{"DIOCGETRULES", "", "filter"}):
				versions++
			case slices.Equal(c, []string{"DIOCGETRULE", "", "filter"}):
				rules++
			}
		}
		return versions, rules
	}
	check := func(wantRules bool) {
		t.Helper()
		from := len(r.k.calls)
		if got := mustID(t, r); got != rs.ID() {
			t.Fatalf("LoadedID = %q, want %q", got, rs.ID())
		}
		versions, rules := mainReads(from)
		if versions == 0 || (rules > 0) != wantRules {
			t.Errorf("LoadedID read the main ruleset %d times and %d of its rules; want a rule read: %v", versions, rules, wantRules)
		}
	}
	check(false)
	check(false)
	r.k.mainRules = append(r.k.mainRules, "pass out all no state") // another tool
	check(true)
	check(false)
	r.k.gen[""]++ // pfctl -f of the same main ruleset gives a new version
	check(true)
}

// readHook runs a function before the first read of the rules of the
// main ruleset.
type readHook struct {
	*kernel
	before func()
}

func (d *readHook) Rules(rs pf.Ruleset) ([]pf.Rule, error) {
	if f := d.before; rs.Anchor == "" && f != nil {
		d.before = nil
		f()
	}
	return d.kernel.Rules(rs)
}

// The rules that LoadedID reads can be of a later version than the
// version that it read before them. LoadedID then keeps no version: the
// main ruleset can come back to the old version without a call, as pf
// can give an old ticket again.
func TestLoadedIDKeepsNoVersionThatChangedDuringTheRead(t *testing.T) {
	r := newRig(t)
	rs := compileRS(t, testPolicies)
	mustLoad(t, r, rs)
	stock := slices.Clone(r.k.mainRules)
	flushMain(t, r.k)
	dev := &readHook{kernel: r.k, before: func() { r.k.mainRules = stock }}
	b := pfbackend.New(r.k, dev, r.clk.now, slog.New(slog.DiscardHandler))
	if id, err := b.LoadedID(t.Context()); err != nil || id != rs.ID() {
		t.Fatalf("LoadedID while another tool restores the main ruleset = (%q, %v), want %q", id, err, rs.ID())
	}
	r.k.mainRules = nil // the version before the read, with no call
	if id, err := b.LoadedID(t.Context()); err != nil || id != "" {
		t.Errorf("LoadedID at the old version without a call = (%q, %v), want \"\"", id, err)
	}
}

// When pf refuses the entry rule, for example because another tool
// changed the main ruleset at the same time, Load fails, and the next
// Load adds it.
func TestLoadFailsWhenTheEntryCannotBeAdded(t *testing.T) {
	r := newRig(t)
	rs := compileRS(t, testPolicies)
	flushMain(t, r.k)
	r.k.fail = func(args []string) bool { return args[0] == "DIOCCHANGERULE" }
	if err := r.b.Load(t.Context(), rs); err == nil {
		t.Fatal("Load with a failing DIOCCHANGERULE = nil, want an error")
	}
	wantNoID(t, r)
	r.k.fail = nil
	mustLoad(t, r, rs)
	if got := mustID(t, r); got != rs.ID() || r.k.entryRules() != 1 {
		t.Errorf("after the second Load: LoadedID %q, %d entry rules; want %q and 1", got, r.k.entryRules(), rs.ID())
	}
}

// Unload removes the entry rule by its label, and no other rule of the
// main ruleset.
func TestUnloadRemovesTheEntry(t *testing.T) {
	r := newRig(t)
	flushMain(t, r.k)
	r.k.mainRules = []string{"block drop out all"} // another tool
	mustLoad(t, r, compileRS(t, testPolicies))
	if r.k.entryRules() != 1 {
		t.Fatalf("main ruleset after Load = %v, want the entry rule", r.k.mainRules)
	}
	if err := r.b.Unload(t.Context()); err != nil {
		t.Fatalf("Unload: %v", err)
	}
	if want := []string{"block drop out all"}; !slices.Equal(r.k.mainRules, want) {
		t.Errorf("main ruleset after Unload = %v, want %v", r.k.mainRules, want)
	}
	if err := r.b.Unload(t.Context()); err != nil {
		t.Errorf("a second Unload = %v, want nil", err)
	}
}

// Digest reads the pf status and two versions, and no rule.
func TestDigestReadsNoRule(t *testing.T) {
	r := newRig(t)
	mustLoad(t, r, compileRS(t, testPolicies))
	from := len(r.k.calls)
	if _, err := r.b.Digest(t.Context()); err != nil {
		t.Fatalf("Digest: %v", err)
	}
	want := [][]string{{"DIOCGETSTATUS"}, {"DIOCGETRULES", "", "filter"}, {"DIOCGETRULES", ifb, "filter"}}
	if got := r.k.calls[from:]; !slices.EqualFunc(got, want, slices.Equal) {
		t.Errorf("Digest called %v, want %v", got, want)
	}
}

// The Digest changes when another tool changes the main ruleset or the
// anchor, and not when a table changes.
func TestDigestSeesExternalChanges(t *testing.T) {
	tests := []struct {
		name    string
		change  func(t *testing.T, k *kernel)
		changes bool
	}{
		{"main ruleset flushed", flushMain, true},
		{"main ruleset loaded again", func(_ *testing.T, k *kernel) { k.gen[""]++ }, true},
		{"anchor flushed", func(_ *testing.T, k *kernel) { k.rules[ifb] = nil }, true},
		{"pf disabled", func(_ *testing.T, k *kernel) { k.enabled, k.refs = false, nil }, true},
		{"table entry added", func(_ *testing.T, k *kernel) { k.setEntries(ifb, "doh", "9.9.9.9/32") }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRig(t)
			mustLoad(t, r, compileRS(t, testPolicies))
			before, err := r.b.Digest(t.Context())
			if err != nil {
				t.Fatalf("Digest: %v", err)
			}
			tt.change(t, r.k)
			after, err := r.b.Digest(t.Context())
			if err != nil {
				t.Fatalf("Digest: %v", err)
			}
			if got := after != before; got != tt.changes {
				t.Errorf("Digest changed: %v, want %v", got, tt.changes)
			}
		})
	}
}

// Before the first Load the anchor does not exist. Digest reports it as
// a state of its own.
func TestDigestWithoutTheAnchor(t *testing.T) {
	r := newRig(t)
	before, err := r.b.Digest(t.Context())
	if err != nil {
		t.Fatalf("Digest without the anchor: %v", err)
	}
	mustLoad(t, r, compileRS(t, testPolicies))
	if after, err := r.b.Digest(t.Context()); err != nil || after == before {
		t.Errorf("Digest after the first Load = (%v, %v), want a change", after, err)
	}
}

// One convergence of the real Reconciler repairs a broken entry: Read
// reports no ruleset, so the Reconciler loads, and Load adds the entry
// rule.
func TestConvergenceRepairsTheEntry(t *testing.T) {
	r := newRig(t)
	first := converge(t, r)
	if first.Installed == "" || hasVoiding(first.Problems) {
		t.Fatalf("first convergence = %+v, want an installed ruleset and no voiding Problem", first)
	}
	flushMain(t, r.k)
	r.clk.t = r.clk.t.Add(pfbackend.EnableInterval)
	rep := converge(t, r)
	if rep.Installed != first.Installed || hasVoiding(rep.Problems) || rep.Writes == 0 {
		t.Errorf("convergence after the flush = %+v, want a Load of %s and no voiding Problem", rep, first.Installed)
	}
	if r.k.entryRules() != 1 || mustID(t, r) != first.Installed {
		t.Errorf("after the convergence: main %v, LoadedID %q; want the entry rule and %q", r.k.mainRules, mustID(t, r), first.Installed)
	}
}
