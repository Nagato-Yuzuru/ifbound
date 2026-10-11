package reconcile_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
)

// canary is the Firefox canary domain, which gets an entry whenever
// another entry exists.
const canary = "use-application-dns.net"

// entriesV1 are the resolver entries of configV1 without aliases.
var entriesV1 = []string{"ads.example", "example.com", "example.net", canary}

func TestConvergeWritesEntryForLearnedAlias(t *testing.T) {
	f := installV1(t)
	f.learn(t, "web", "cdn.provider.test")

	rep := f.converge(t)

	checkResolver(t, f.world, f.cfg.DNS.Listen, "ads.example", "cdn.provider.test", "example.com", "example.net", canary)
	if rep.Writes != 1 {
		t.Errorf("writes = %d, want 1 (the alias entry)", rep.Writes)
	}
}

func TestConvergeAliasOfTwoPoliciesGetsOneEntry(t *testing.T) {
	f := installV1(t)
	f.learn(t, "web", "cdn.provider.test")
	f.learn(t, "ads", "CDN.provider.test.")

	rep := f.converge(t)

	checkResolver(t, f.world, f.cfg.DNS.Listen, "ads.example", "cdn.provider.test", "example.com", "example.net", canary)
	if rep.Writes != 1 {
		t.Errorf("writes = %d, want 1", rep.Writes)
	}
}

func TestConvergeRemovesAliasEntryOnExpiry(t *testing.T) {
	f := newFixture(t, configV1)
	f.learn(t, "web", "old.provider.test")
	f.converge(t)
	f.now = f.now.Add(40 * time.Minute)
	f.learn(t, "web", "new.provider.test")
	f.converge(t)

	f.now = f.now.Add(21 * time.Minute) // 61 minutes after the first answer
	if got := f.book.Expire(); len(got) != 1 || got[0].Alias.String() != "old.provider.test" {
		t.Fatalf("Expire = %v, want only old.provider.test", got)
	}
	rep := f.converge(t)

	checkResolver(t, f.world, f.cfg.DNS.Listen, "ads.example", "example.com", "example.net", "new.provider.test", canary)
	if rep.Writes != 1 {
		t.Errorf("writes = %d, want 1 (the removal)", rep.Writes)
	}
}

func TestConvergeRemovesAliasEntryWhenPolicyIsRemoved(t *testing.T) {
	f := installV1(t)
	f.learn(t, "ads", "track.provider.test")
	f.learn(t, "web", "cdn.provider.test")
	f.converge(t)

	f.reconfigure(t, configV2) // removes ads

	f.converge(t)
	checkResolver(t, f.world, f.cfg.DNS.Listen, "cdn.provider.test", "example.com", "example.net", "mail.example.org", canary)
}

// An alias at or below an apex gets its own entry: the apex can go away
// while the alias stays learned. An alias equal to an apex shares its
// entry.
func TestConvergeGivesEntryToAliasAtOrBelowApex(t *testing.T) {
	f := installV1(t)
	f.learn(t, "web", "example.com", "www.example.com", "a.b.example.net")

	rep := f.converge(t)

	checkResolver(t, f.world, f.cfg.DNS.Listen,
		"a.b.example.net", "ads.example", "example.com", "example.net", canary, "www.example.com")
	if rep.Writes != 2 {
		t.Errorf("writes = %d, want 2 (the two aliases below an apex)", rep.Writes)
	}
}

func TestConvergeGivesNoEntryToRefusedAlias(t *testing.T) {
	for _, alias := range []string{
		`a\032b.test`,        // a space
		`a\.b.test`,          // a dot in a label
		`a/b.test`,           // a path separator
		`\046\046.test`,      // a label ".."
		`\000.test`,          // a NUL byte
		`*.wild.test`,        // a wildcard label
		`-lead.test`,         // a label that starts with "-"
		`192.0.2.1`,          // an address form
		`\195\169.test`,      // non-ASCII
		`com.`,               // a public suffix
		`co.uk`,              // a public suffix of two labels
		`github.io`,          // a public suffix from the private section
		`cdn.cloudflare.net`, // a public suffix from the private section
		`local`,              // the implicit "*" rule
		`test`,               // the implicit "*" rule
		`arpa`,               // a public suffix
		`in-addr.arpa`,       // a public suffix
	} {
		t.Run(alias, func(t *testing.T) {
			f := installV1(t)
			before := f.world.Writes()
			f.learn(t, "web", alias)

			if rep := f.converge(t); rep.Writes != 0 || f.world.Writes() != before {
				t.Errorf("writes: report %d, world %d -> %d, want none", rep.Writes, before, f.world.Writes())
			}
			checkResolver(t, f.world, f.cfg.DNS.Listen, entriesV1...)
		})
	}
}

func TestConvergeSecondPassWithAliasesWritesNothing(t *testing.T) {
	f := installV1(t)
	f.learn(t, "web", "cdn.provider.test", "www.example.com", `bad\032name.test`, "co.uk")
	f.learn(t, "ads", "track.provider.test")
	f.converge(t)
	before := f.world.Writes()

	rep := f.converge(t)

	if rep.Writes != 0 || f.world.Writes() != before {
		t.Errorf("second pass wrote: report %d, world %d -> %d", rep.Writes, before, f.world.Writes())
	}
}

// With no domain to protect, nothing needs Firefox to use the system
// resolver: the canary entry goes too.
func TestConvergeRemovesCanaryWithoutOtherEntries(t *testing.T) {
	f := installV1(t)
	f.reconfigure(t, header+`
[[policy]]
name = "ips"
to = ["192.0.2.10"]
only_via = ["en0"]
`)

	f.converge(t)

	checkResolver(t, f.world, f.cfg.DNS.Listen)
}

// An alias alone, after its policy lost every domain, also brings the
// canary.
func TestConvergeWritesCanaryForAliasOnly(t *testing.T) {
	f := newFixture(t, header+`
[[policy]]
name = "web"
to = ["192.0.2.10"]
only_via = ["en0"]
`)
	f.learn(t, "web", "cdn.provider.test")

	f.converge(t)

	checkResolver(t, f.world, f.cfg.DNS.Listen, "cdn.provider.test", canary)
}

// The canary as an apex and an alias gets one entry.
func TestConvergeCanaryAsApexAndAliasGetsOneEntry(t *testing.T) {
	f := newFixture(t, header+`
[[policy]]
name = "web"
to = ["use-application-dns.net"]
only_via = ["en0"]
`)
	f.learn(t, "web", canary)

	f.converge(t)

	checkResolver(t, f.world, f.cfg.DNS.Listen, canary)
}

func readActive(t *testing.T, f *fixture) map[string]bool {
	t.Helper()
	st, err := f.world.Resolver().Read(t.Context())
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	out := make(map[string]bool, len(st.Entries))
	for _, e := range st.Entries {
		out[e.Domain.String()] = e.Active
	}
	return out
}

func applied(f *fixture) []string {
	return entryDomains(f.world.AppliedResolverEntries())
}

// A platform that applies changes after a delay reports a new entry as
// not active. A convergence before the delay ends does not rewrite it,
// because a rewrite restarts the delay. The system also applies a Remove
// only after the delay.
func TestResolverReportsEntryActiveAfterDelay(t *testing.T) {
	f := installV1(t)
	f.world.SetResolverDelay(true)
	f.learn(t, "web", "cdn.provider.test")
	f.converge(t)

	if got := readActive(t, f); got["cdn.provider.test"] || !got["example.com"] {
		t.Errorf("active before the delay ends = %v, want only the old entries", got)
	}
	if got := applied(f); slices.Contains(got, "cdn.provider.test") {
		t.Errorf("applied before the delay ends = %v, want no alias", got)
	}
	if rep := f.converge(t); rep.Writes != 0 {
		t.Errorf("writes = %d before the delay ends, want 0", rep.Writes)
	}

	f.world.SettleResolver()

	if got := readActive(t, f); !got["cdn.provider.test"] {
		t.Errorf("active after the delay = %v, want the alias entry", got)
	}

	f.reconfigure(t, configV2) // removes the apex ads.example
	f.converge(t)
	if got := applied(f); !slices.Contains(got, "ads.example") {
		t.Errorf("applied before the delay ends = %v, want ads.example still", got)
	}
	f.world.SettleResolver()
	if got := applied(f); slices.Contains(got, "ads.example") {
		t.Errorf("applied after the delay = %v, want no ads.example", got)
	}
}

func TestResolverReportsEntryActiveAtOnceWithoutDelay(t *testing.T) {
	f := installV1(t)
	f.learn(t, "web", "cdn.provider.test")
	f.converge(t)

	if got := readActive(t, f); !got["cdn.provider.test"] {
		t.Errorf("active = %v, want the alias entry", got)
	}
}

// refusingResolver fails every Write for one domain, as a SysResolver
// does that finds an entry it does not manage there.
type refusingResolver struct {
	reconcile.SysResolver
	bad string
}

var errUnmanaged = errors.New("entry is not managed by ifbound")

func (r refusingResolver) Write(ctx context.Context, e reconcile.ResolverEntry) error {
	if e.Domain.String() == r.bad {
		return errUnmanaged
	}
	return r.SysResolver.Write(ctx, e)
}

// One entry whose Write fails does not stop the other writes and
// removals, in any pass. An old entry above the failed entry stays,
// because it still covers the failed domain.
func TestConvergeContinuesAfterFailedResolverWrite(t *testing.T) {
	f := newFixture(t, configV1)
	f.learn(t, "web", "old.provider.test", "vpn.test")
	f.converge(t)
	f.rec.Resolver = refusingResolver{SysResolver: f.world.Resolver(), bad: "corp.vpn.test"}
	f.now = f.now.Add(2 * time.Hour)
	f.book.Expire() // old.provider.test and vpn.test expire
	f.learn(t, "web", "corp.vpn.test", "zzz.provider.test")

	for pass := range 2 {
		if _, err := f.rec.Converge(t.Context(), f.inputs()); !errors.Is(err, errUnmanaged) {
			t.Fatalf("pass %d: err = %v, want errUnmanaged", pass, err)
		}
		checkResolver(t, f.world, f.cfg.DNS.Listen,
			"ads.example", "example.com", "example.net", canary, "vpn.test", "zzz.provider.test")
	}
}

// isPathComponent reports whether s names one entry in a directory.
func isPathComponent(s string) bool {
	return s != "" && s != "." && s != ".." && !strings.ContainsAny(s, "/\\\x00")
}

// Every policy.Domain is a safe file name in one directory, as a resolver
// entry file needs. FuzzAliasEntry checks the same for AliasEntry.
func FuzzDomainIsPathComponent(f *testing.F) {
	for _, s := range []string{
		"example.com", "a.b", ".", "..", "a/b", `a\/b`, "x..", "EXAMPLE.com.", "_srv.x", "1.2.3.4", "a.-b",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if d, err := policy.ParseDomain(s); err == nil && !isPathComponent(d.String()) {
			t.Fatalf("ParseDomain(%q) = %q, not a path component", s, d)
		}
	})
}

// The configuration widens www.shop.example to *.shop.example, and the
// write of shop.example fails. The names below www.shop.example stay
// covered: the old entry stays.
func TestConvergeKeepsNarrowerOldEntryWhenWiderWriteFails(t *testing.T) {
	f := newFixture(t, moveFrom)
	f.converge(t)
	f.rec.Resolver = refusingResolver{SysResolver: f.world.Resolver(), bad: "shop.example"}
	f.reconfigure(t, moveTo)

	if _, err := f.rec.Converge(t.Context(), f.inputs()); !errors.Is(err, errUnmanaged) {
		t.Fatalf("err = %v, want errUnmanaged", err)
	}
	checkResolver(t, f.world, f.cfg.DNS.Listen, "mail.example.org", canary, "www.shop.example")
}
