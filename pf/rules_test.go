package pf

import (
	"errors"
	"io/fs"
	"syscall"
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

// TestChangeErr checks the errors of a DIOCCHANGERULE change. A stale
// ticket gives EINVAL, which the e2e tests cannot cause on demand.
func TestChangeErr(t *testing.T) {
	if got := changeErr(syscall.EINVAL); !errors.Is(got, ErrChanged) {
		t.Errorf("changeErr(EINVAL) = %v, want ErrChanged", got)
	}
	if got := changeErr(syscall.EBUSY); !errors.Is(got, ErrChanged) {
		t.Errorf("changeErr(EBUSY) = %v, want ErrChanged", got)
	}
	if got := changeErr(syscall.EPERM); !errors.Is(got, fs.ErrPermission) {
		t.Errorf("changeErr(EPERM) = %v, want fs.ErrPermission", got)
	}
}
