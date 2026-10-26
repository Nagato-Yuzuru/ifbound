package syslookuptest

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"

	"github.com/Nagato-Yuzuru/ifbound/internal/syslookup"
)

func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}

func TestFoundGivesNormalizedCopy(t *testing.T) {
	var f Fake
	f.Found("cdn.alias.test.", addrs("2001:db8::7", "::ffff:203.0.113.7", "203.0.113.7")...)

	got, err := f.Resolve(t.Context(), "cdn.alias.test.")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	want := addrs("203.0.113.7", "2001:db8::7")
	if !slices.Equal(got, want) {
		t.Fatalf("Resolve = %v, want %v", got, want)
	}
	got[0] = netip.MustParseAddr("192.0.2.1")
	again, err := f.Resolve(t.Context(), "cdn.alias.test.")
	if err != nil {
		t.Fatalf("second Resolve: %v", err)
	}
	if !slices.Equal(again, want) {
		t.Fatalf("a change to a result changed the stored answer: %v", again)
	}
}

func TestFoundWithoutAddressesPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("Found with no addresses did not panic")
		}
	}()
	var f Fake
	f.Found("a.test.")
}

func TestUnknownNameIsNotFound(t *testing.T) {
	var f Fake
	if _, err := f.Resolve(t.Context(), "unknown.test."); !errors.Is(err, syslookup.ErrNotFound) {
		t.Fatalf("Resolve error = %v, want ErrNotFound", err)
	}
}

func TestUnavailableIsNotNotFound(t *testing.T) {
	var f Fake
	f.Unavailable("a.test.")
	_, err := f.Resolve(t.Context(), "a.test.")
	if !errors.Is(err, syslookup.ErrUnavailable) || errors.Is(err, syslookup.ErrNotFound) {
		t.Fatalf("Resolve error = %v, want ErrUnavailable only", err)
	}
}

func TestFailWrapsTheError(t *testing.T) {
	var f Fake
	errBoom := errors.New("boom")
	f.Fail("a.test.", errBoom)
	_, err := f.Resolve(t.Context(), "a.test.")
	if !errors.Is(err, errBoom) || errors.Is(err, syslookup.ErrNotFound) {
		t.Fatalf("Resolve error = %v, want %v and not ErrNotFound", err, errBoom)
	}
}

func TestDoneContextWinsOverStoredOutcome(t *testing.T) {
	var f Fake
	f.Found("a.test.", addrs("192.0.2.1")...)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := f.Resolve(ctx, "a.test."); !errors.Is(err, context.Canceled) {
		t.Fatalf("Resolve error = %v, want context.Canceled", err)
	}
}

func TestNamesInCallOrder(t *testing.T) {
	var f Fake
	if got := f.Names(); len(got) != 0 {
		t.Fatalf("Names before any call = %v, want none", got)
	}
	for _, n := range []string{"b.test.", "a.test.", "b.test."} {
		_, _ = f.Resolve(t.Context(), n) //nolint:errcheck // only the recorded name matters here
	}
	if got, want := f.Names(), []string{"b.test.", "a.test.", "b.test."}; !slices.Equal(got, want) {
		t.Fatalf("Names = %v, want %v", got, want)
	}
}
