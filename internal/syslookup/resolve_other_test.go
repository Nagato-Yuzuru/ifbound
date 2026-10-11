//go:build !darwin || netgo

package syslookup

import (
	"errors"
	"testing"
)

func TestResolveIsUnsupportedOffDarwin(t *testing.T) {
	addrs, err := Resolver{}.Resolve(t.Context(), "localhost")
	if !errors.Is(err, errors.ErrUnsupported) || addrs != nil {
		t.Fatalf("Resolve = %v, %v; want nil, errors.ErrUnsupported", addrs, err)
	}
}
