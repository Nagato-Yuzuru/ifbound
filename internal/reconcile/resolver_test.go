package reconcile_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
)

// canary is the Firefox canary domain, which gets an entry whenever
// another entry exists.
const canary = "use-application-dns.net"

// entriesV1 are the resolver entries of configV1.
var entriesV1 = []string{"ads.example", "example.com", "example.net", canary}

func applied(f *fixture) []string {
	return entryDomains(f.world.AppliedResolverEntries())
}

// A platform that applies changes after a delay does not use a new entry
// before the delay ends. A convergence before the delay ends does not
// rewrite the entry, because a rewrite restarts the delay. The system
// also applies a Remove only after the delay.
func TestConvergeDoesNotRewriteEntryBeforeTheDelayEnds(t *testing.T) {
	f := installV1(t)
	f.world.SetResolverDelay(true)
	f.reconfigure(t, configV2) // adds the apex mail.example.org, removes ads.example
	f.converge(t)

	if got := applied(f); slices.Contains(got, "mail.example.org") || !slices.Contains(got, "ads.example") {
		t.Errorf("applied before the delay ends = %v, want ads.example and no mail.example.org", got)
	}
	if rep := f.converge(t); rep.Writes != 0 {
		t.Errorf("writes = %d before the delay ends, want 0", rep.Writes)
	}
	f.world.SettleResolver()
	if got := applied(f); !slices.Contains(got, "mail.example.org") || slices.Contains(got, "ads.example") {
		t.Errorf("applied after the delay = %v, want mail.example.org and no ads.example", got)
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
	f := newFixture(t, header+`
[[policy]]
name = "web"
to = ["old.provider.test", "vpn.test"]
only_via = ["en0"]
`)
	f.converge(t)
	f.rec.Resolver = refusingResolver{SysResolver: f.world.Resolver(), bad: "corp.vpn.test"}
	f.reconfigure(t, header+`
[[policy]]
name = "web"
to = ["corp.vpn.test", "zzz.provider.test"]
only_via = ["en0"]
`)

	for pass := range 2 {
		if _, err := f.rec.Converge(t.Context(), f.inputs()); !errors.Is(err, errUnmanaged) {
			t.Fatalf("pass %d: err = %v, want errUnmanaged", pass, err)
		}
		checkResolver(t, f.world, f.cfg.DNS.Listen, canary, "vpn.test", "zzz.provider.test")
	}
}

// isPathComponent reports whether s names one entry in a directory.
func isPathComponent(s string) bool {
	return s != "" && s != "." && s != ".." && !strings.ContainsAny(s, "/\\\x00")
}

// Every policy.Domain is a safe file name in one directory, as a resolver
// entry file needs.
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
