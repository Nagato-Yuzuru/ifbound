//go:build !darwin || netgo

package syslookup

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
)

// Resolve fails: only the macOS system resolver fills the cache that
// this package exists for.
func (Resolver) Resolve(_ context.Context, name string) ([]netip.Addr, error) {
	return nil, fmt.Errorf("resolve %s through the system resolver on %s: %w", name, runtime.GOOS, errors.ErrUnsupported)
}
