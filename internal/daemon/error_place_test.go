package daemon_test

import (
	"errors"
	"regexp"
	"testing"
	"testing/synctest"

	"github.com/Nagato-Yuzuru/ifbound/internal/daemon"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

// TestApplyErrorIsAFieldErrorWithoutAPlace pins the text of a refused
// configuration. The error stays a *policy.FieldError. Its text has no line
// and column: only the CLI adds them.
func TestApplyErrorIsAFieldErrorWithoutAPlace(t *testing.T) {
	placeRE := regexp.MustCompile(`[0-9]+:[0-9]+`)
	for _, tt := range invalidConfigs {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				h := newHarness(t, configV1)
				h.wantState(daemon.StateReady)

				_, err := h.d.Apply(t.Context(), []byte(tt.text))

				var fe *policy.FieldError
				if !errors.As(err, &fe) {
					t.Fatalf("Apply = %v, want a *policy.FieldError", err)
				}
				if placeRE.MatchString(err.Error()) {
					t.Errorf("error text %q holds a place, want none", err)
				}
				h.stop()
			})
		})
	}
}
