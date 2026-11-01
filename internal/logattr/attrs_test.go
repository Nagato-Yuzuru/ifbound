package logattr_test

import (
	"testing"

	"github.com/Nagato-Yuzuru/ifbound/internal/logattr"
)

// TestNames guards against an accidental rename of these keys. It does not
// detect a hand edit of attrs.go: the generate hook does that. A key is a
// contract with the queries of the operator, so a rename must fail a test
// and not only change the registry.
func TestNames(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{"own attribute", logattr.BackoffMS, "ifbound.backoff_ms"},
		{"own attribute with a dotted key", logattr.ConvergeTrigger, "ifbound.converge.trigger"},
		{"own enum value", logattr.StateReady, "ready"},
		{"semconv reference", logattr.ErrorType, "error.type"},
		{"semconv reference with a service key", logattr.ServiceVersion, "service.version"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("constant = %q, want %q", tt.got, tt.want)
			}
		})
	}
}
