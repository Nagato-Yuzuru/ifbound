package pfbackend_test

// Tests of the changes that another tool makes to pf, and of the repair
// through the real Reconciler. Each table has a near miss that differs in
// one factor.

import (
	"log/slog"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/pfbackend"
	"github.com/Nagato-Yuzuru/ifbound/internal/pfrules"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile/reconciletest"
)

type emptyBook struct{}

func (emptyBook) Addrs(policy.Name) []netip.Addr { return nil }

// converge runs one convergence of the real Reconciler with this Backend.
func converge(t *testing.T, r *rig) reconcile.Report {
	t.Helper()
	cfg, err := policy.ParseBytes([]byte("[dns]\nupstream = [\"tls://1.1.1.1@a.example\"]\n" + testPolicies))
	if err != nil {
		t.Fatal(err)
	}
	rec := reconcile.Reconciler{
		Compiler:  pfrules.Compiler{},
		Backend:   r.b,
		Resolver:  reconciletest.NewWorld().Resolver(),
		Inventory: reconciletest.NewInventory(modelIfaces...),
	}
	// Callers inject pfctl faults on purpose and judge the loaded state.
	rep, _ := rec.Converge(t.Context(), reconcile.Inputs{ //nolint:errcheck // the injected fault makes it fail
		Policies: cfg.Policies,
		Book:     emptyBook{},
		Listen:   netip.MustParseAddrPort("127.0.0.1:10053"),
	})
	return rep
}

func hasVoiding(ps []reconcile.Problem) bool { return len(voiding(ps)) > 0 }

// A "nat pass" or "binat pass" rule skips the filter rules (pf.conf(5):
// "packets matching the translation rule are passed without inspecting
// the filter rules"), so it voids the ifbound rules wherever it is.
func TestNatPassVoidsEnforcement(t *testing.T) {
	natPass := "nat pass on en0 inet from any to 192.0.2.10 -> (en0)"
	tests := []struct {
		name   string
		change func(k *kernel)
		voids  bool
	}{
		{"nat pass in an anchor that sorts after", func(k *kernel) { k.load("com.apple/zzz.tool", []byte(natPass+"\n")) }, true},
		{"nat pass in the main ruleset", func(k *kernel) { k.mainNat = append([]string{natPass}, k.mainNat...) }, true},
		{"binat pass in an anchor that sorts before", func(k *kernel) {
			k.load("com.apple/000.aaa", []byte("binat pass on en0 from 192.168.64.14 to any -> 192.168.64.99\n"))
		}, true},
		{"near miss: nat without pass", func(k *kernel) {
			k.load("com.apple/zzz.tool", []byte("nat on en0 inet from any to 192.0.2.10 -> (en0)\n"))
		}, false},
		{"near miss: rdr pass", func(k *kernel) {
			k.load("com.apple/zzz.tool", []byte("rdr pass on en0 inet proto tcp from any to any port 80 -> 127.0.0.1 port 8080\n"))
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRig(t)
			mustLoad(t, r, compileRS(t, testPolicies))
			tt.change(r.k)
			st := mustRead(t, r)
			if got := hasVoiding(st.Problems); got != tt.voids {
				t.Errorf("voiding Problem = %v, want %v; Problems = %+v", got, tt.voids, st.Problems)
			}
		})
	}
}

// A read-modify-write of the ifbound anchor that adds a rule at the top
// level keeps the sentinel label. It is still a change of the ruleset.
func TestTopLevelForeignRuleIsAChange(t *testing.T) {
	tests := []struct {
		name string
		rule string
		same bool
	}{
		{"pass rule", "pass out quick all no state", false},
		{"near miss: block rule, which only blocks more", "block drop out quick to 192.0.2.77", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRig(t)
			rs := compileRS(t, testPolicies)
			mustLoad(t, r, rs)
			// ( echo "<rule>"; pfctl -a A -sr ) | pfctl -a A -f -
			r.k.rules[ifb] = append([]string{tt.rule}, r.k.rules[ifb]...)
			if got := mustID(t, r) == rs.ID(); got != tt.same {
				t.Fatalf("LoadedID is the loaded ID: %v, want %v", got, tt.same)
			}
			converge(t, r)
			if tt.same {
				return
			}
			if slices.Contains(r.k.rules[ifb], tt.rule) {
				t.Errorf("after a convergence the foreign rule is still in the anchor")
			}
			if got := mustID(t, r); got != rs.ID() {
				t.Errorf("LoadedID after the repair = %q, want %q", got, rs.ID())
			}
		})
	}
}

// When another holder keeps pf enabled, ifbound takes a reference of its
// own, so the "pfctl -X" of that holder does not disable pf.
func TestLoadTakesAReferenceWhenPfIsEnabled(t *testing.T) {
	r := newRig(t)
	if _, err := r.k.enableRef(); err != nil { // tool A: pfctl -E
		t.Fatal(err)
	}
	other := r.k.refs[0]
	mustLoad(t, r, compileRS(t, testPolicies))
	if _, err := r.k.releaseRef(other); err != nil { // tool A: pfctl -X <token A>
		t.Fatal(err)
	}
	if !r.k.enabled {
		t.Errorf("pf is disabled after the other holder released its token; refs %v", r.k.refs)
	}
	if r.log.count(slog.LevelWarn) != 0 {
		t.Errorf("warnings = %d, want none: pf was enabled", r.log.count(slog.LevelWarn))
	}
	// A second Load renews the reference: ifbound holds one at a time.
	r.clk.t = r.clk.t.Add(time.Second)
	mustLoad(t, r, compileRS(t, testPolicies))
	if len(r.k.refs) != 1 {
		t.Errorf("references after a second Load = %v, want one of ifbound", r.k.refs)
	}
}

// A failed state kill after the commit of Load is tried again: the
// Backend reports no ruleset until a Load finishes.
func TestFailedStateKillIsRetried(t *testing.T) {
	for _, fault := range []bool{true, false} {
		name := "first kill fails"
		if !fault {
			name = "near miss: no fault"
		}
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.k.setEntries(ifb, "doh", "1.1.1.1/32")
			r.k.states = []netip.Addr{netip.MustParseAddr("1.1.1.1")}
			failed := !fault
			r.k.fail = func(args []string) bool {
				if !failed && slices.Contains(args, "1.1.1.1/32") && slices.Contains(args, "-k") {
					failed = true
					return true
				}
				return false
			}
			converge(t, r)
			if fault && mustID(t, r) != "" {
				t.Errorf("LoadedID after the failed kill is not \"\"")
			}
			converge(t, r)
			if r.k.hasState("1.1.1.1") {
				t.Errorf("a state to the protected 1.1.1.1 survives")
			}
		})
	}
}

// AddEntries also marks a failed state kill, so a Load follows.
func TestFailedStateKillOfAddEntriesGivesNoRuleset(t *testing.T) {
	r := newRig(t)
	rs := compileRS(t, testPolicies)
	mustLoad(t, r, rs)
	r.k.states = []netip.Addr{netip.MustParseAddr("198.51.100.3")}
	r.k.fail = func(args []string) bool { return slices.Contains(args, "-k") }
	if err := r.b.AddEntries(t.Context(), "bing", pfx("198.51.100.3/32")); err == nil {
		t.Fatal("AddEntries with a failing kill = nil, want an error")
	}
	if got := mustID(t, r); got != "" {
		t.Errorf("LoadedID = %q, want \"\" until a Load ends the states", got)
	}
	r.k.fail = nil
	mustLoad(t, r, rs)
	if r.k.hasState("198.51.100.3") || mustID(t, r) != rs.ID() {
		t.Errorf("after the Load: state %v, LoadedID %q; want no state and %q", r.k.hasState("198.51.100.3"), mustID(t, r), rs.ID())
	}
}

// A reference to com.apple/* with parameters evaluates the ifbound
// anchor only for the packets that it matches (pf.conf(5)).
func TestRestrictedAnchorReferenceVoids(t *testing.T) {
	tests := []struct {
		rule  string
		voids bool
	}{
		{`anchor "com.apple/*" in all`, true},
		{`anchor "com.apple/*" on lo0 all`, true},
		{`anchor "com.apple/*" all`, false}, // near miss
	}
	for _, tt := range tests {
		t.Run(tt.rule, func(t *testing.T) {
			r := newRig(t)
			mustLoad(t, r, compileRS(t, testPolicies))
			r.k.mainRules = []string{`scrub-anchor "com.apple/*" all fragment reassemble`, tt.rule}
			st := mustRead(t, r)
			if got := hasVoiding(st.Problems); got != tt.voids {
				t.Errorf("voiding Problem = %v, want %v; Problems = %+v", got, tt.voids, st.Problems)
			}
		})
	}
}

// A negated entry voids only when it exempts addresses from an entry of
// its table. Read then leaves that entry out of Tables, so the Reconciler
// adds it again, and AddEntries deletes each negated entry inside a
// prefix that it adds. One convergence repairs each change.
func TestNegatedEntries(t *testing.T) {
	held := netip.MustParsePrefix("203.0.113.0/24")
	tests := []struct {
		name   string
		change func(bing map[netip.Prefix]bool)
		voids  bool
	}{
		{"negated entry inside the held prefix", func(bing map[netip.Prefix]bool) {
			bing[netip.MustParsePrefix("203.0.113.9/32")] = true
		}, true},
		{"near miss: negated entry of an address that ifbound does not add", func(bing map[netip.Prefix]bool) {
			bing[netip.MustParsePrefix("10.9.9.9/32")] = true
		}, false},
		{"negated entry in place of a desired prefix", func(bing map[netip.Prefix]bool) {
			bing[held] = true
		}, false},
		{"negated entry inside a desired prefix that is missing", func(bing map[netip.Prefix]bool) {
			delete(bing, held)
			bing[netip.MustParsePrefix("203.0.113.9/32")] = true
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRig(t)
			converge(t, r)
			tt.change(r.k.tables[ifb]["bing"])
			before := mustRead(t, r)
			if got := hasVoiding(before.Problems); got != tt.voids {
				t.Errorf("voiding Problem before the repair = %v, want %v; Problems = %+v", got, tt.voids, before.Problems)
			}
			if tt.voids && slices.Contains(before.Tables["bing"], held) {
				t.Errorf("Read.Tables[bing] = %v holds %v, which a negated entry voids", before.Tables["bing"], held)
			}

			converge(t, r)
			checkHeld(t, r, held)
		})
	}
}

// checkHeld checks that table bing holds p with no negated entry inside
// it, and that Read reports p and no Problem.
func checkHeld(t *testing.T, r *rig, p netip.Prefix) {
	t.Helper()
	st := mustRead(t, r)
	if len(st.Problems) != 0 {
		t.Errorf("Read reports %+v, want no Problem", st.Problems)
	}
	if !slices.Contains(st.Tables["bing"], p) {
		t.Errorf("Read.Tables[bing] = %v, want %v", st.Tables["bing"], p)
	}
	for e, neg := range r.k.tables[ifb]["bing"] {
		if neg && p.Contains(e.Addr()) {
			t.Errorf("table bing holds the negated entry !%v", e)
		}
	}
}

// Release gives back the reference of ifbound also after a restart: the
// token is in the anchor, and a new Backend reads it.
func TestReleaseAfterRestart(t *testing.T) {
	for _, load := range []bool{true, false} {
		name := "the restarted daemon loads"
		if !load {
			name = "the restarted daemon only reads"
		}
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			mustLoad(t, r, compileRS(t, testPolicies)) // the first ifboundd enables pf
			again := pfbackend.New(r.k, r.clk.now, slog.New(slog.DiscardHandler))
			r.clk.t = r.clk.t.Add(time.Minute)
			if load {
				if err := again.Load(t.Context(), compileRS(t, testPolicies)); err != nil {
					t.Fatal(err)
				}
			} else if _, err := again.Read(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := again.Release(t.Context()); err != nil {
				t.Fatalf("Release: %v", err)
			}
			if r.k.enabled {
				t.Errorf("pf is still enabled after uninstall by the restarted daemon; references left %v", r.k.refs)
			}
		})
	}
}

// After "pfctl -d" and an enable by another tool, the token of ifbound is
// stale. Release counts it as given back and keeps the other reference.
func TestReleaseOfAStaleToken(t *testing.T) {
	r := newRig(t)
	mustLoad(t, r, compileRS(t, testPolicies))
	r.k.enabled, r.k.refs = false, nil         // pfctl -d by someone
	if _, err := r.k.enableRef(); err != nil { // another tool: pfctl -E
		t.Fatal(err)
	}
	first := r.b.Release(t.Context())
	second := r.b.Release(t.Context())
	if first != nil || second != nil {
		t.Errorf("Release with a stale token = (%v, %v), want success: the token is already gone", first, second)
	}
	if !r.k.enabled || len(r.k.refs) != 1 {
		t.Errorf("the other tool's reference is gone: enabled %v refs %v", r.k.enabled, r.k.refs)
	}
}

// Load reads the state table once and kills only the states that it
// finds, so the number of pfctl calls does not grow with the entries.
func TestStateKillCallsDoNotGrowWithEntries(t *testing.T) {
	count := func(n int) int {
		r := newRig(t)
		es := make([]string, 0, n)
		for i := range n {
			es = append(es, netip.AddrFrom4([4]byte{198, 18, byte(i / 256), byte(i % 256)}).String()+"/32")
		}
		r.k.setEntries(ifb, "bing", es...)
		r.k.states = []netip.Addr{netip.MustParseAddr("198.18.0.7"), netip.MustParseAddr("8.8.8.8")}
		mustLoad(t, r, compileRS(t, testPolicies))
		if r.k.hasState("198.18.0.7") != (n <= 7) {
			t.Errorf("with %d entries: state to 198.18.0.7 = %v", n, r.k.hasState("198.18.0.7"))
		}
		if !r.k.hasState("8.8.8.8") {
			t.Errorf("with %d entries: the state to 8.8.8.8 is gone", n)
		}
		return len(r.k.calls)
	}
	if small, big := count(0), count(3000); big-small > 2 {
		t.Errorf("pfctl calls per Load: %d with 0 entries, %d with 3000 entries", small, big)
	}
}

func TestNegatedEntryInsideAnAddedPrefixIsDeleted(t *testing.T) {
	r := newRig(t)
	mustLoad(t, r, compileRS(t, testPolicies))
	r.k.setEntries(ifb, "bing", "!203.0.113.9/32", "!198.51.100.1/32")
	if err := r.b.AddEntries(t.Context(), "bing", pfx("203.0.113.0/24")); err != nil {
		t.Fatal(err)
	}
	got := r.k.tables[ifb]["bing"]
	if _, ok := got[netip.MustParsePrefix("203.0.113.9/32")]; ok {
		t.Errorf("table bing = %v: the hole in 203.0.113.0/24 stays", got)
	}
	if neg, ok := got[netip.MustParsePrefix("198.51.100.1/32")]; !ok || !neg {
		t.Errorf("table bing = %v: AddEntries changed a negated entry outside the added prefix", got)
	}
}
