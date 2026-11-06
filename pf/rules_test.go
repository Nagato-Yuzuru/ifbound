package pf

import (
	"errors"
	"testing"
)

// TestRulesetKindAction checks that each kind selects its own ruleset.
// The kernel selects the ruleset from the action, so two kinds with the
// same action read the same rules.
func TestRulesetKindAction(t *testing.T) {
	kinds := []RulesetKind{RulesetFilter, RulesetScrub, RulesetNAT, RulesetBINAT, RulesetRDR, RulesetDummynet}
	seen := map[uint8]RulesetKind{}
	for _, k := range kinds {
		act, err := k.action()
		if err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		if other, ok := seen[act]; ok {
			t.Errorf("kinds %s and %s map to the same action %d", k, other, act)
		}
		seen[act] = k
	}
	if _, err := RulesetKind(len(kinds)).action(); !errors.Is(err, errKind) {
		t.Errorf("an unknown kind: got %v, want errKind", err)
	}
}
