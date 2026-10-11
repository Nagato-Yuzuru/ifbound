package syslookup

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"testing"
)

func TestNormalizeGivesDNSPluginForm(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"empty", nil, nil},
		{"one", []string{"192.0.2.1"}, []string{"192.0.2.1"}},
		{"IPv4-mapped becomes IPv4", []string{"::ffff:192.0.2.1"}, []string{"192.0.2.1"}},
		{
			"sorted, IPv4 first",
			[]string{"2001:db8::7", "203.0.113.7", "198.51.100.7"},
			[]string{"198.51.100.7", "203.0.113.7", "2001:db8::7"},
		},
		{
			"duplicates go, also mapped ones",
			[]string{"203.0.113.7", "::ffff:203.0.113.7", "2001:db8::7", "2001:db8::7"},
			[]string{"203.0.113.7", "2001:db8::7"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := parse(tt.in)
			orig := slices.Clone(in)
			got := Normalize(in)
			if want := parse(tt.want); !slices.Equal(got, want) {
				t.Fatalf("Normalize(%v) = %v, want %v", tt.in, got, want)
			}
			if !slices.Equal(in, orig) {
				t.Fatalf("Normalize changed its input to %v", in)
			}
		})
	}
}

func parse(ss []string) []netip.Addr {
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}

func TestAbsNameAddsFinalDot(t *testing.T) {
	tests := []struct{ in, want string }{
		{"cdn.alias.test", "cdn.alias.test."},
		{"cdn.alias.test.", "cdn.alias.test."},
		{"test", "test."},
		{"192.0.2.1", "192.0.2.1."},
		{"::", "::."},
	}
	for _, tt := range tests {
		got, err := absName(tt.in)
		if err != nil || got != tt.want {
			t.Errorf("absName(%q) = %q, %v; want %q", tt.in, got, err, tt.want)
		}
	}
}

func TestAbsNameRejectsRoot(t *testing.T) {
	for _, in := range []string{"", "."} {
		if _, err := absName(in); !errors.Is(err, errInvalidName) {
			t.Errorf("absName(%q) error = %v, want errInvalidName", in, err)
		}
	}
}

func TestClassify(t *testing.T) {
	notFound := &net.DNSError{Err: "no such host", Name: "a.test.", IsNotFound: true}
	other := &net.DNSError{Err: "temporary failure", Name: "a.test.", IsTemporary: true}
	probeOK := func(context.Context) error { return nil }
	errDial := errors.New("dial unix /var/run/mDNSResponder: connection refused")
	probeFails := func(context.Context) error { return errDial }

	tests := []struct {
		name    string
		err     error
		probe   func(context.Context) error
		want    error
		notWant error
	}{
		{"not found with mDNSResponder up", notFound, probeOK, ErrNotFound, ErrUnavailable},
		{"not found with mDNSResponder down", notFound, probeFails, ErrUnavailable, ErrNotFound},
		{"other failure", other, probeOK, errLookup, ErrNotFound},
		{"foreign error", errDial, probeOK, errLookup, ErrNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := classify(t.Context(), "a.test.", tt.err, tt.probe)
			if !errors.Is(err, tt.want) || errors.Is(err, tt.notWant) {
				t.Fatalf("classify = %v, want %v and not %v", err, tt.want, tt.notWant)
			}
		})
	}
}

func TestClassifyDoneContext(t *testing.T) {
	notFound := &net.DNSError{Err: "no such host", IsNotFound: true}
	probeOK := func(context.Context) error { return nil }

	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := classify(canceled, "a.test.", notFound, probeOK); !errors.Is(err, context.Canceled) || errors.Is(err, ErrNotFound) {
		t.Fatalf("classify with canceled ctx = %v, want context.Canceled only", err)
	}

	expired, cancel2 := context.WithTimeout(t.Context(), 0)
	defer cancel2()
	if err := classify(expired, "a.test.", notFound, probeOK); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("classify with expired ctx = %v, want context.DeadlineExceeded", err)
	}
}
