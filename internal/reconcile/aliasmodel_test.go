package reconcile_test

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/Nagato-Yuzuru/ifbound/internal/dnsname"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile/reconciletest"
)

// label63 is a label of the maximum length.
var label63 = strings.Repeat("a", 63)

// name253 is a name of 253 characters, the maximum of the domain
// rules and of dnsname (255 octets in wire form): three labels of 63
// characters, one of 58, and "io".
var name253 = strings.Repeat(label63+".", 3) + strings.Repeat("b", 58) + ".io"

func TestAliasEntryDecisions(t *testing.T) {
	tests := []struct {
		alias string
		want  string // the domain when accepted
		err   error
	}{
		{"cdn.provider.test", "cdn.provider.test", nil},
		{"WWW.Example.COM.", "www.example.com", nil},
		{"_srv.example.com", "_srv.example.com", nil},
		{"shop.co.uk", "shop.co.uk", nil},
		{"user.github.io", "user.github.io", nil},
		{canary, canary, nil},
		{label63 + ".example.com", label63 + ".example.com", nil},
		{name253, name253, nil},
		{`a\032b.test`, "", reconcile.ErrAliasNotDomain},
		{`a/b.test`, "", reconcile.ErrAliasNotDomain},
		{`\046\046`, "", reconcile.ErrAliasNotDomain},
		{`\000.test`, "", reconcile.ErrAliasNotDomain},
		{"192.0.2.1", "", reconcile.ErrAliasNotDomain},
		{"-lead.test", "", reconcile.ErrAliasNotDomain},
		{"com", "", reconcile.ErrAliasPublicSuffix},
		{"co.uk", "", reconcile.ErrAliasPublicSuffix},
		{"github.io", "", reconcile.ErrAliasPublicSuffix},
		{"cdn.cloudflare.net", "", reconcile.ErrAliasPublicSuffix},
		{"local", "", reconcile.ErrAliasPublicSuffix},
		{"test", "", reconcile.ErrAliasPublicSuffix},
		{"arpa", "", reconcile.ErrAliasPublicSuffix},
		{"localhost", "", reconcile.ErrAliasPublicSuffix}, // the implicit "*" rule
	}
	if len(name253) != 253 {
		t.Fatalf("len(name253) = %d", len(name253))
	}
	for _, tt := range tests {
		n, err := dnsname.Parse(tt.alias)
		if err != nil {
			t.Fatalf("Parse(%q): %v", tt.alias, err)
		}
		d, err := reconcile.AliasEntry(n)
		switch {
		case tt.err == nil && (err != nil || d.String() != tt.want):
			t.Errorf("AliasEntry(%q) = %q, %v; want %q", tt.alias, d, err, tt.want)
		case tt.err != nil && !errors.Is(err, tt.err):
			t.Errorf("AliasEntry(%q) error = %v, want %v", tt.alias, err, tt.err)
		}
	}
}

// FuzzAliasEntry compares AliasEntry with a reference built directly on
// policy.ParseDomain and the public suffix list.
func FuzzAliasEntry(f *testing.F) {
	for _, s := range modelAliases {
		f.Add(s)
	}
	for _, s := range []string{
		name253, "x.cdn.cloudflare.net", "a.b.c.bd", "b.bd", "kawasaki.jp", "city.kawasaki.jp",
		"x.city.kawasaki.jp", "blogspot.com", `x\.y.com`, "xn--p1ai", "a.xn--p1ai", "_.com",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		n, err := dnsname.Parse(s)
		if err != nil {
			return
		}
		if err := compareAliasEntry(n); err != nil {
			t.Fatal(err)
		}
	})
}

// compareAliasEntry compares AliasEntry of one name with the
// reference. An accepted domain must also be one path component and name
// the same node as the alias.
func compareAliasEntry(n dnsname.Name) error {
	want, verdict := refAliasEntry(n)
	d, err := reconcile.AliasEntry(n)
	switch verdict {
	case accepted:
		if err != nil || d.String() != want {
			return fmt.Errorf("AliasEntry(%q) = %q, %v; want %q", n, d, err, want)
		}
		if !isPathComponent(d.String()) || len(d.String()) > 255 {
			return fmt.Errorf("AliasEntry(%q) = %q, not a path component", n, d)
		}
		if back, err := dnsname.Parse(d.String()); err != nil || back != n {
			return fmt.Errorf("AliasEntry(%q) = %q, which names %v (%v)", n, d, back, err)
		}
	case notDomain:
		if !errors.Is(err, reconcile.ErrAliasNotDomain) || errors.Is(err, reconcile.ErrAliasPublicSuffix) {
			return fmt.Errorf("AliasEntry(%q) error = %v, want only ErrAliasNotDomain", n, err)
		}
	case publicSuffix:
		if !errors.Is(err, reconcile.ErrAliasPublicSuffix) || errors.Is(err, reconcile.ErrAliasNotDomain) {
			return fmt.Errorf("AliasEntry(%q) error = %v, want only ErrAliasPublicSuffix", n, err)
		}
	}
	return nil
}

// fixedModel returns a model with no random faults and no random settles.
func fixedModel(t *testing.T, delay bool) *resolverModel {
	t.Helper()
	m := newResolverModel(t, 0)
	m.delay = delay
	m.world.SetResolverDelay(delay)
	m.stats = &modelStats{}
	return m
}

func parseNames(t *testing.T, ss ...string) []dnsname.Name {
	t.Helper()
	out := make([]dnsname.Name, len(ss))
	for i, s := range ss {
		n, err := dnsname.Parse(s)
		if err != nil {
			t.Fatalf("Parse(%q): %v", s, err)
		}
		out[i] = n
	}
	return out
}

// An old entry is below a new desired entry, and the old entry itself is
// not desired. The write of the new entry fails. The old domain was
// covered before and the desired state covers it, so it must stay
// covered.
func TestConvergeKeepsOldEntryBelowFailedWrite(t *testing.T) {
	tests := []struct {
		name         string
		apexesBefore []string
		aliasBefore  string
		apexesAfter  []string
		old, failed  string
	}{
		// The configuration widens www.shop.example to *.shop.example.
		{"apex widens", []string{"www.shop.example"}, "", []string{"shop.example"}, "www.shop.example", "shop.example"},
		// The alias expires when its apex arrives.
		{"alias expires", nil, "www.example.com", []string{"example.com"}, "www.example.com", "example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := fixedModel(t, false)
			m.apexes = tt.apexesBefore
			if tt.aliasBefore != "" {
				m.book["p0"] = parseNames(t, tt.aliasBefore)
			}
			m.step(t, 0)
			m.book["p0"] = nil
			m.apexes = tt.apexesAfter
			m.probe.reset(0, 0)
			m.probe.failOn = map[string]bool{tt.failed: true}

			_, err := m.rec.Converge(t.Context(), m.inputs())

			if !errors.Is(err, reconciletest.ErrInjected) {
				t.Fatalf("err = %v, want the injected fault", err)
			}
			if got := entryDomains(m.world.ResolverEntries()); !covered("zz."+tt.old, got) {
				t.Errorf("entries %v after calls %v: zz.%s is not covered", got, m.probe.calls, tt.old)
			}
		})
	}
}

// The keep rule compares whole labels. An old entry stays when the write
// of a desired entry on its label path fails: at or below it, or at or
// above it. A failed entry that only ends with the same text, or is on
// another path, does not keep it.
func TestConvergeKeepsOldEntryOnLabelPathOfFailedWrite(t *testing.T) {
	tests := []struct {
		old, failed string
		kept        bool
	}{
		{"provider.test", "cdn.provider.test", true},
		{"provider.test", "deep.cdn.provider.test", true},
		{"deep.cdn.provider.test", "provider.test", true},
		{"cdn.provider.test", "provider.test", true},
		{"provider.test", "xprovider.test", false},
		{"provider.test", "other.org", false},
		{"cdn.provider.test", "xprovider.test", false},
	}
	for _, tt := range tests {
		t.Run(tt.old+" "+tt.failed, func(t *testing.T) {
			m := fixedModel(t, false)
			m.apexes = []string{tt.old}
			m.step(t, 0)
			m.apexes = nil
			m.book["p0"] = parseNames(t, tt.failed)
			m.probe.failOn = map[string]bool{tt.failed: true}

			m.step(t, 0)

			if got := slices.Contains(entryDomains(m.world.ResolverEntries()), tt.old); got != tt.kept {
				t.Errorf("%s kept = %v, want %v; calls %v", tt.old, got, tt.kept, m.probe.calls)
			}
		})
	}
}
