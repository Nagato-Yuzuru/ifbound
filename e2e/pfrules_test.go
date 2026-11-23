//go:build e2e && darwin

package e2e

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/Nagato-Yuzuru/ifbound/pf"
)

func TestPfRules(t *testing.T) {
	requireE2E(t)
	h := openPf(t)
	const anchor = rulesAnchor
	loadAnchor(t, anchor, ""+
		"block drop out quick inet to 192.0.2.1 label \"e2e-one\"\n"+
		"anchor \"sub\"\n"+
		"pass out inet to 192.0.2.2 label \"e2e-two\"\n")
	loadAnchor(t, anchor+"/sub", "block drop out inet to 192.0.2.3\n")

	rules, err := h.Rules(pf.Ruleset{Anchor: anchor})
	if err != nil {
		t.Fatalf("rules: %v", err)
	}
	want := []pf.Rule{
		{Action: pf.ActionDrop, Label: "e2e-one"},
		{Action: pf.ActionPass, AnchorCall: "sub"},
		{Action: pf.ActionPass, Label: "e2e-two"},
	}
	if !slices.Equal(rules, want) {
		t.Errorf("filter rules = %+v, want %+v (pfctl -sr:\n%s)", rules, want, pfctl(t, "-a", anchor, "-sr"))
	}
}

// TestPfRulesOfEachKind checks that each RulesetKind reads its own
// ruleset: the kernel selects the ruleset from the action of the request.
func TestPfRulesOfEachKind(t *testing.T) {
	requireE2E(t)
	h := openPf(t)
	const anchor = rulesAnchor
	// pfctl wants the rules in this order: scrub, translation, filter.
	loadAnchor(t, anchor, ""+
		"scrub in on lo0 all\n"+
		"nat on lo0 inet from any to 192.0.2.11 -> 127.0.0.1\n"+
		"binat on lo0 inet from 192.0.2.20 to any -> 192.0.2.21\n"+
		"rdr on lo0 inet proto tcp from any to 192.0.2.12 port 80 -> 127.0.0.1 port 8080\n"+
		"dummynet out quick inet proto tcp to 192.0.2.13 pipe 1\n"+
		"block drop out quick inet to 192.0.2.1\n")

	for _, tt := range []struct {
		kind pf.RulesetKind
		want pf.Action
	}{
		{pf.RulesetFilter, pf.ActionDrop},
		{pf.RulesetScrub, pf.ActionScrub},
		{pf.RulesetNAT, pf.ActionNAT},
		{pf.RulesetBINAT, pf.ActionBINAT},
		{pf.RulesetRDR, pf.ActionRDR},
		{pf.RulesetDummynet, pf.ActionDummynet},
	} {
		rules, err := h.Rules(pf.Ruleset{Anchor: anchor, Kind: tt.kind})
		if err != nil || len(rules) != 1 || rules[0].Action != tt.want {
			t.Errorf("%s rules: %+v, %v; want one %s rule", tt.kind, rules, err, tt.want)
		}
	}
}

// TestPfRulesAfterReload checks that Rules reads the active rules: after
// a load, it returns the new rules.
func TestPfRulesAfterReload(t *testing.T) {
	requireE2E(t)
	h := openPf(t)
	rs := pf.Ruleset{Anchor: rulesAnchor}
	loadAnchor(t, rs.Anchor, "block drop out quick inet to 192.0.2.1\nblock drop out quick inet to 192.0.2.2\n")
	if rules, err := h.Rules(rs); err != nil || len(rules) != 2 {
		t.Fatalf("rules: %+v, %v; want two rules", rules, err)
	}

	loadAnchor(t, rs.Anchor, "block drop out quick inet to 192.0.2.1 label \"e2e-one\"\n")
	rules, err := h.Rules(rs)
	if want := []pf.Rule{{Action: pf.ActionDrop, Label: "e2e-one"}}; err != nil || !slices.Equal(rules, want) {
		t.Errorf("rules after reload: %+v, %v; want %+v", rules, err, want)
	}
}

func TestPfAnchors(t *testing.T) {
	requireE2E(t)
	h := openPf(t)
	const anchor = rulesAnchor
	loadAnchor(t, anchor, "anchor \"sub\"\n")
	loadAnchor(t, anchor+"/sub", "block drop out inet to 192.0.2.3\n")

	kids, err := h.Anchors(anchor)
	if err != nil || !slices.Equal(kids, []string{"sub"}) {
		t.Errorf("anchors of %s: %v, %v; want [sub]", anchor, kids, err)
	}
	top, err := h.Anchors("")
	if err != nil || !slices.Contains(top, "com.apple") {
		t.Errorf("anchors of the main ruleset: %v, %v; want com.apple among them", top, err)
	}
	for _, missing := range []string{anchor + "/missing", "ifbound-e2e-missing"} {
		if _, err := h.Rules(pf.Ruleset{Anchor: missing}); !errors.Is(err, pf.ErrNotFound) {
			t.Errorf("rules of %s: %v, want ErrNotFound", missing, err)
		}
		if _, err := h.Anchors(missing); !errors.Is(err, pf.ErrNotFound) {
			t.Errorf("anchors of %s: %v, want ErrNotFound", missing, err)
		}
	}
}

// BenchmarkPfReadRules reads the pf status and the rules of an anchor, as
// pfbackend does to find the loaded ruleset.
func BenchmarkPfReadRules(b *testing.B) {
	h := openPf(b)
	rs := pf.Ruleset{Anchor: rulesAnchor}
	loadAnchor(b, rs.Anchor, "block drop out quick inet to 192.0.2.1 label \"e2e-one\"\nblock drop out inet to 192.0.2.2\n")
	b.Run("ioctl", func(b *testing.B) {
		for b.Loop() {
			if _, err := h.Status(); err != nil {
				b.Fatal(err)
			}
			if _, err := h.Rules(rs); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("pfctl", func(b *testing.B) {
		for b.Loop() {
			pfctl(b, "-s", "info")
			pfctl(b, "-a", rs.Anchor, "-sr")
		}
	})
}

// TestPfInsertAnchorCall adds an anchor call before the rules of an
// anchor, and removes it by its label. pfctl reads the result.
func TestPfInsertAnchorCall(t *testing.T) {
	requireE2E(t)
	h := openPf(t)
	rs := pf.Ruleset{Anchor: rulesAnchor}
	loadAnchor(t, rs.Anchor, "block drop out quick inet to 192.0.2.1 label \"e2e-one\"\n")
	loadAnchor(t, rs.Anchor+"/sub", "block drop out inet to 192.0.2.3\n")
	before, err := h.Version(rs)
	if err != nil {
		t.Fatalf("version: %v", err)
	}

	if err := h.InsertAnchorCall(rs.Anchor, "sub", "e2e-entry"); err != nil {
		t.Fatalf("InsertAnchorCall: %v", err)
	}
	rules, err := h.Rules(rs)
	want := []pf.Rule{
		{Action: pf.ActionPass, Label: "e2e-entry", AnchorCall: "sub"},
		{Action: pf.ActionDrop, Label: "e2e-one"},
	}
	if err != nil || !slices.Equal(rules, want) {
		t.Errorf("rules after the insert: %+v, %v; want %+v", rules, err, want)
	}
	out := pfctl(t, "-a", rs.Anchor, "-sr")
	// The output also holds the ALTQ notes of pfctl, so compare the
	// positions of the two rules.
	call, block := strings.Index(out, `anchor "sub" all label "e2e-entry"`), strings.Index(out, "block drop out quick")
	if call < 0 || block < call {
		t.Errorf("pfctl -sr after the insert does not show the anchor call before the block rule:\n%s", out)
	}
	inserted, err := h.Version(rs)
	if err != nil || inserted == before {
		t.Errorf("version after the insert: %+v, %v; want a change from %+v", inserted, err, before)
	}

	n, err := h.RemoveLabeled(rs.Anchor, "e2e-entry")
	if err != nil || n != 1 {
		t.Fatalf("RemoveLabeled: %d, %v; want 1", n, err)
	}
	rules, err = h.Rules(rs)
	if want := want[1:]; err != nil || !slices.Equal(rules, want) {
		t.Errorf("rules after the removal: %+v, %v; want %+v", rules, err, want)
	}
	if n, err := h.RemoveLabeled(rs.Anchor, "e2e-entry"); err != nil || n != 0 {
		t.Errorf("second RemoveLabeled: %d, %v; want 0", n, err)
	}
	if removed, err := h.Version(rs); err != nil || removed == inserted {
		t.Errorf("version after the removal: %+v, %v; want a change from %+v", removed, err, inserted)
	}
}

// TestPfVersion checks that a load and an insert by another process
// change the Version, and that a missing anchor gives ErrNotFound.
func TestPfVersion(t *testing.T) {
	requireE2E(t)
	h := openPf(t)
	rs := pf.Ruleset{Anchor: rulesAnchor}
	loadAnchor(t, rs.Anchor, "block drop out quick inet to 192.0.2.1\n")
	v1, err := h.Version(rs)
	if err != nil || v1.Count != 1 {
		t.Fatalf("version: %+v, %v; want count 1", v1, err)
	}
	if v, err := h.Version(rs); err != nil || v != v1 {
		t.Errorf("second read: %+v, %v; want %+v", v, err, v1)
	}
	loadAnchor(t, rs.Anchor, "block drop out quick inet to 192.0.2.1\n")
	if v, err := h.Version(rs); err != nil || v == v1 {
		t.Errorf("version after a load of the same rules: %+v, %v; want a change from %+v", v, err, v1)
	}
	if _, err := h.Version(pf.Ruleset{Anchor: rulesAnchor + "/missing"}); !errors.Is(err, pf.ErrNotFound) {
		t.Errorf("version of a missing anchor: %v, want ErrNotFound", err)
	}
	if err := h.InsertAnchorCall(rulesAnchor+"/missing", "sub", "e2e-entry"); !errors.Is(err, pf.ErrNotFound) {
		t.Errorf("insert into a missing anchor: %v, want ErrNotFound", err)
	}
}
