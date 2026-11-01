package configstore

import (
	"errors"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

// placeRE matches a "line:column" place in an error text.
var placeRE = regexp.MustCompile(`[0-9]+:[0-9]+`)

// TestStoreErrorIsAFieldErrorWithoutAPlace pins the text of a rejected
// configuration. The error stays a *policy.FieldError. Its text has no line
// and column: only the CLI adds them.
func TestStoreErrorIsAFieldErrorWithoutAPlace(t *testing.T) {
	tests := []struct{ name, data string }{
		{"syntax error", syntaxError},
		{"unreachable upstream", unreachable},
		{"unknown key on line 3", "[dns]\nupstream = [\"tls://9.9.9.9@dns.quad9.net\"]\ncolour = 1\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")

			_, _, err := Store(path, []byte(tt.data), -1)

			var fe *policy.FieldError
			if !errors.As(err, &fe) {
				t.Fatalf("error = %v, want a *policy.FieldError", err)
			}
			if placeRE.MatchString(err.Error()) {
				t.Errorf("error text %q holds a place, want none", err)
			}
		})
	}
}
