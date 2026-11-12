package pfbackend_test

// Tests of the changes that another tool makes to pf, and of the repair
// through the real Reconciler. Each table has a near miss that differs in
// one factor.

import (
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/blockable"
	"github.com/Nagato-Yuzuru/ifbound/internal/pfbackend"
	"github.com/Nagato-Yuzuru/ifbound/internal/pfrules"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile/reconciletest"
)

type emptyBook struct{}

func (emptyBook) Addrs(policy.Name) []blockable.Addr { return nil }

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
		// The ruleset of ifbound calls only the sub-anchors directly below
		// the anchor. A call out of it can reach a rule that passes.
		{"anchor rule that calls out of the anchor", `anchor "/vpn" quick all`, false},
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
				if !failed && args[0] == "DIOCKILLSTATES" && slices.Contains(args, "1.1.1.1/32") {
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
	r.k.fail = func(args []string) bool { return args[0] == "DIOCKILLSTATES" }
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

// escapes reports whether the kernel model lets a protected packet leave
// on an interface that its policy does not allow: a packet to the table
// bing (only_via utun4) on en0, or a packet to the table doh (only_via
// empty) on any interface. An inbound packet comes first on each
// interface: pf keeps the match flag of each anchor across packets, so
// an earlier packet can change how pf decides a later one.
func escapes(t *testing.T, k *kernel) bool {
	t.Helper()
	for _, from := range []string{"en0", "utun4"} {
		if err := k.receive(from); err != nil {
			t.Fatal(err)
		}
		bing, err := k.send("bing", from)
		if err != nil {
			t.Fatal(err)
		}
		doh, err := k.send("doh", from)
		if err != nil {
			t.Fatal(err)
		}
		if slices.Contains(bing, "en0") || len(doh) > 0 {
			return true
		}
	}
	return false
}

// A rule of another tool that decides a packet before the ifbound rules,
// or that routes a packet to another interface, voids the ifbound rules.
// pf finds the rules through the anchor calls: absolute, relative, and
// wildcard calls, and also calls out of the subtree of an anchor. The
// kernel model evaluates each case, so each case shows that pf passes a
// protected packet, or that it does not.
func TestRulesAroundTheAnchorVoid(t *testing.T) {
	const passQuick, pass = "pass out quick all no state", "pass out all no state"
	tests := []struct {
		name    string
		change  func(k *kernel)
		escapes bool   // the model passes a protected packet
		want    string // a part of the text of a voiding Problem; "" for none
	}{
		{"quick anchor in the main ruleset before the com.apple anchor", func(k *kernel) {
			k.mainRules = slices.Insert(k.mainRules, 0, `anchor "vpn" quick all`)
			k.rules["vpn"] = []string{pass}
		}, true, `"anchor \"vpn\" quick all" in the main pf ruleset`},
		{"quick anchor in an earlier com.apple anchor", func(k *kernel) {
			k.rules["com.apple/000.aaa"] = []string{`anchor "vpn" quick all`}
			k.rules["com.apple/000.aaa/vpn"] = []string{pass}
		}, true, `"anchor \"vpn\" quick all" in the anchor com.apple/000.aaa`},
		{"quick wildcard anchor in an earlier com.apple anchor", func(k *kernel) {
			k.rules["com.apple/000.aaa"] = []string{`anchor "vpn/*" quick all`}
			k.rules["com.apple/000.aaa/vpn/x"] = []string{pass}
		}, true, `"anchor \"vpn/*\" quick all" in the anchor com.apple/000.aaa`},
		{"absolute call out of an earlier com.apple anchor", func(k *kernel) {
			k.rules["com.apple/000.aaa"] = []string{`anchor "/vpn" all`}
			k.rules["vpn"] = []string{passQuick}
		}, true, `"pass out quick all no state" in the anchor vpn`},
		{"relative call out of an earlier com.apple anchor", func(k *kernel) {
			k.rules["com.apple/000.aaa"] = []string{`anchor "../zzz" all`}
			k.rules["com.apple/zzz"] = []string{passQuick}
		}, true, `"pass out quick all no state" in the anchor com.apple/zzz`},
		// pfctl prints this call as "..//*" (pf_anchor_copyout).
		{"wildcard call of the parent from an earlier com.apple anchor", func(k *kernel) {
			k.rules["com.apple/000.aaa"] = []string{`anchor "x" all`}
			k.rules["com.apple/000.aaa/x"] = []string{`anchor "../*" all`}
			k.rules["com.apple/000.aaa/y"] = []string{passQuick}
		}, true, `"pass out quick all no state" in the anchor com.apple/000.aaa/y`},
		// The inbound packet matches the block rule, so the wildcard call
		// "*" sets the match flag of x/c. The protected packet matches no
		// rule in x/c, but the quick wildcard call "x/*" reads the old flag
		// of x/c and ends the evaluation, and pf passes the packet.
		{"quick wildcard anchor and a match flag of an earlier packet", func(k *kernel) {
			k.mainRules = slices.Insert(k.mainRules, 0, `anchor "x/*" quick all`)
			k.rules["x/c"] = []string{`anchor "*" in all`}
			k.rules["x/c/d"] = []string{"block drop in all"}
		}, true, `"anchor \"x/*\" quick all" in the main pf ruleset`},
		// The nested wildcard call sets the match flag of x/c, and the quick
		// wildcard call "x/*" reads it.
		{"quick wildcard anchor and a pass rule below a nested wildcard call", func(k *kernel) {
			k.mainRules = slices.Insert(k.mainRules, 0, `anchor "x/*" quick all`)
			k.rules["x/c"] = []string{`anchor "*" all`}
			k.rules["x/c/d"] = []string{pass}
		}, true, `"anchor \"x/*\" quick all" in the main pf ruleset`},
		{"call inside the subtree of an earlier com.apple anchor", func(k *kernel) {
			k.rules["com.apple/000.aaa"] = []string{`anchor "inner" all`}
			k.rules["com.apple/000.aaa/inner"] = []string{passQuick}
		}, true, `"pass out quick all no state" in the anchor com.apple/000.aaa/inner`},
		{"route-to in a later com.apple anchor", func(k *kernel) {
			k.rules["com.apple/300.vpn"] = []string{"pass out route-to (en0 192.0.2.1) all"}
		}, true, `"pass out route-to (en0 192.0.2.1) all" in the anchor com.apple/300.vpn`},
		{"route-to in the main ruleset after the com.apple anchor", func(k *kernel) {
			k.mainRules = append(k.mainRules, "pass out route-to (en0 192.0.2.1) all")
		}, true, `"pass out route-to (en0 192.0.2.1) all" in the main pf ruleset`},
		{"dup-to in an anchor that the main ruleset calls after the com.apple anchor", func(k *kernel) {
			k.mainRules = append(k.mainRules, `anchor "late" all`)
			k.rules["late"] = []string{"pass out dup-to (en0 192.0.2.1) all"}
		}, true, `"pass out dup-to (en0 192.0.2.1) all" in the anchor late`},
		// A route rule voids also when the model shows no way around the
		// ifbound rules: the check stays on the safe side.
		{"route-to for inbound packets only", func(k *kernel) {
			k.rules["com.apple/300.vpn"] = []string{"pass in route-to (en0 192.0.2.1) all"}
		}, false, `"pass in route-to (en0 192.0.2.1) all" in the anchor com.apple/300.vpn`},
		{"reply-to", func(k *kernel) {
			k.rules["com.apple/300.vpn"] = []string{"pass out reply-to (en0 192.0.2.1) all"}
		}, false, `"pass out reply-to (en0 192.0.2.1) all" in the anchor com.apple/300.vpn`},
		{"near miss: anchor without quick before the com.apple anchor", func(k *kernel) {
			k.mainRules = slices.Insert(k.mainRules, 0, `anchor "vpn" all`)
			k.rules["vpn"] = []string{pass}
		}, false, ""},
		{"near miss: quick anchor that holds only a block rule", func(k *kernel) {
			k.rules["com.apple/000.aaa"] = []string{`anchor "vpn" quick all`}
			k.rules["com.apple/000.aaa/vpn"] = []string{"block drop out all"}
		}, false, ""},
		{"near miss: quick anchor after the ifbound anchor", func(k *kernel) {
			k.rules["com.apple/300.vpn"] = []string{`anchor "x" quick all`}
			k.rules["com.apple/300.vpn/x"] = []string{pass}
		}, false, ""},
		{"near miss: call out of an earlier anchor to a pass rule without quick", func(k *kernel) {
			k.rules["com.apple/000.aaa"] = []string{`anchor "/vpn" all`}
			k.rules["vpn"] = []string{pass}
		}, false, ""},
		{"near miss: quick pass in a sub-anchor that no rule calls", func(k *kernel) {
			k.rules["com.apple/000.aaa"] = nil
			k.rules["com.apple/000.aaa/x"] = []string{passQuick}
		}, false, ""},
		{"near miss: the word quick in a label before the ifbound anchor", func(k *kernel) {
			k.rules["com.apple/000.aaa"] = []string{`pass out on lo0 all no state label "keep quick dns"`}
		}, false, ""},
		{"near miss: the word route-to in a label", func(k *kernel) {
			k.rules["com.apple/300.vpn"] = []string{`pass out on lo0 all no state label "no route-to here"`}
		}, false, ""},
		{"near miss: an anchor that calls itself", func(k *kernel) {
			k.rules["com.apple/000.aaa"] = []string{`anchor "/com.apple/000.aaa" all`}
		}, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.escapes && tt.want == "" {
				t.Fatal("the model passes a protected packet, so the case must want a voiding Problem")
			}
			r := newRig(t)
			mustLoad(t, r, compileRS(t, testPolicies))
			if escapes(t, r.k) {
				t.Fatal("the model passes a protected packet before the change")
			}
			tt.change(r.k)
			if got := escapes(t, r.k); got != tt.escapes {
				t.Fatalf("the model passes a protected packet: %v, want %v", got, tt.escapes)
			}
			got := voiding(mustRead(t, r).Problems)
			found := slices.ContainsFunc(got, func(p reconcile.Problem) bool { return strings.Contains(p.Text, tt.want) })
			if tt.want == "" && len(got) != 0 || tt.want != "" && !found {
				t.Errorf("voiding Problems = %+v, want one with %q", got, tt.want)
			}
		})
	}
}

// Read follows an anchor call as pfctl prints it, which is the text that
// pf_anchor_copyout gives and not the loaded text. Each call goes to the
// anchor that pf_anchor_setup chose when the rule was loaded.
func TestCallTargetReadsTheCopyoutForm(t *testing.T) {
	for _, from := range []string{"", "x", "com.apple/000.aaa", "a/b/c"} {
		for _, name := range []string{"y", "y/*", "y/z/*", "*", "../y", "../y/*", "../*", "../../*", "../../y", "/abs", "/abs/*", "/a/b/*"} {
			c, ok := setup(from, name)
			if !ok {
				continue
			}
			printed := c.copyout(from)
			path, wildcard := pfbackend.CallTarget(from, printed)
			if path != c.path || wildcard != c.wildcard {
				t.Errorf("in %q, the call %q prints as %q and reads as (%q, wildcard %v), want (%q, wildcard %v)", from, name, printed, path, wildcard, c.path, c.wildcard)
			}
		}
	}
}

// A negated entry voids only when it exempts addresses from an entry of
// its table. Read then leaves that entry out of Tables, so the Reconciler
// adds it again, and AddEntries deletes each negated entry inside a
// prefix that it adds. One convergence repairs each change, and its
// Report has no voiding Problem.
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

			id := mustID(t, r)
			rep := converge(t, r)
			if got := mustID(t, r); got != id {
				t.Fatalf("the repair loaded the ruleset %q; the test needs a repair without a Load", got)
			}
			// The repair writes the table and loads nothing. The Report
			// gets the Problems of a read after that write.
			if rep.Installed != id || hasVoiding(rep.Problems) {
				t.Errorf("Report: installed %q, Problems %+v; want %q and no voiding Problem", rep.Installed, rep.Problems, id)
			}
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

// Unload gives back the reference of ifbound also after a restart: the
// token is in the anchor, and a new Backend reads it.
func TestUnloadAfterRestart(t *testing.T) {
	for _, load := range []bool{true, false} {
		name := "the restarted daemon loads"
		if !load {
			name = "the restarted daemon only reads"
		}
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			mustLoad(t, r, compileRS(t, testPolicies)) // the first ifboundd enables pf
			again := pfbackend.New(r.k, r.k, r.clk.now, slog.New(slog.DiscardHandler))
			r.clk.t = r.clk.t.Add(time.Minute)
			if load {
				if err := again.Load(t.Context(), compileRS(t, testPolicies)); err != nil {
					t.Fatal(err)
				}
			} else if _, err := again.Read(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := again.Unload(t.Context()); err != nil {
				t.Fatalf("Unload: %v", err)
			}
			if r.k.enabled {
				t.Errorf("pf is still enabled after uninstall by the restarted daemon; references left %v", r.k.refs)
			}
		})
	}
}

// After "pfctl -d" and an enable by another tool, the token of ifbound is
// stale. Unload counts it as given back and keeps the other reference.
func TestUnloadOfAStaleToken(t *testing.T) {
	r := newRig(t)
	mustLoad(t, r, compileRS(t, testPolicies))
	r.k.enabled, r.k.refs = false, nil         // pfctl -d by someone
	if _, err := r.k.enableRef(); err != nil { // another tool: pfctl -E
		t.Fatal(err)
	}
	first := r.b.Unload(t.Context())
	second := r.b.Unload(t.Context())
	if first != nil || second != nil {
		t.Errorf("Unload with a stale token = (%v, %v), want success: the token is already gone", first, second)
	}
	if !r.k.enabled || len(r.k.refs) != 1 {
		t.Errorf("the other tool's reference is gone: enabled %v refs %v", r.k.enabled, r.k.refs)
	}
}

// Load ends the states of each entry through ioctl, so the number of
// pfctl processes does not grow with the entries.
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
		procs := 0
		for _, c := range r.k.calls {
			if !strings.HasPrefix(c[0], "DIOC") {
				procs++
			}
		}
		return procs
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
