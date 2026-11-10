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

// seenResolver wraps a SysResolver. Its Read adds the shadowed domains
// of the test, or fails with errRead when fail is set.
type seenResolver struct {
	reconcile.SysResolver
	shadowed []policy.Domain
	fail     bool
}

var errRead = errors.New("injected read fault")

func (r *seenResolver) Read(ctx context.Context) (reconcile.ResolverState, error) {
	if r.fail {
		return reconcile.ResolverState{}, errRead
	}
	st, err := r.SysResolver.Read(ctx)
	st.Shadowed = slices.Clone(r.shadowed)
	return st, err
}

// Report.Resolver tells what the read of the resolver part saw, and
// whether the part changed an entry. The digest changes exactly when the
// entries, the Problems, or the shadowed domains of the read change. The
// order of the read does not change it. Wrote is set exactly when the
// part wrote or removed an entry.
func TestConvergeReportsWhatTheResolverReadSaw(t *testing.T) {
	f := newFixture(t, configV1)
	r := &seenResolver{SysResolver: f.world.Resolver()}
	f.rec.Resolver = r
	conflict := reconcile.Problem{Text: "foreign entry for example.com"}
	shadowed := []policy.Domain{mustDomain(t, "www.example.com"), mustDomain(t, "a.example.net")}
	noAds := header + `
[[policy]]
name = "web"
to = ["example.com", "*.example.net"]
only_via = ["en0"]
`
	steps := []struct {
		name    string
		do      func(t *testing.T)
		changed bool
		wrote   bool
		wantErr error
	}{
		{"the first pass writes the entries", func(*testing.T) {}, true, true, nil},
		{"the read sees the written entries", func(*testing.T) {}, true, false, nil},
		{"nothing changed", func(*testing.T) {}, false, false, nil},
		{"a resolver Problem appears", func(*testing.T) { f.world.SetProblems(nil, []reconcile.Problem{conflict}) }, true, false, nil},
		{"shadowed domains appear", func(*testing.T) { r.shadowed = shadowed }, true, false, nil},
		{"the same shadowed domains in another order", func(*testing.T) {
			r.shadowed = []policy.Domain{shadowed[1], shadowed[0]}
		}, false, false, nil},
		{"the Problem and the shadowed domains go away", func(*testing.T) {
			f.world.SetProblems(nil, nil)
			r.shadowed = nil
		}, true, false, nil},
		{"an entry goes away outside ifbound", func(t *testing.T) {
			f.world.RemoveResolverEntry(mustDomain(t, "example.com"))
		}, true, true, nil},
		{"the pass only removes an entry", func(t *testing.T) { f.reconfigure(t, noAds) }, true, true, nil},
		{"a write fails", func(t *testing.T) {
			f.rec.Resolver = &seenResolver{SysResolver: refusingResolver{SysResolver: f.world.Resolver(), bad: "example.com"}}
			f.world.RemoveResolverEntry(mustDomain(t, "example.com"))
		}, true, false, errUnmanaged},
	}
	var last string
	for i, s := range steps {
		s.do(t)
		rep, err := f.rec.Converge(t.Context(), f.inputs())
		if !errors.Is(err, s.wantErr) {
			t.Fatalf("%s: err = %v, want %v", s.name, err, s.wantErr)
		}
		if rep.Resolver.Digest == "" {
			t.Errorf("%s: empty digest after a read that succeeded", s.name)
		}
		if changed := rep.Resolver.Digest != last; i > 0 && changed != s.changed {
			t.Errorf("%s: digest changed = %v, want %v", s.name, changed, s.changed)
		}
		if rep.Resolver.Wrote != s.wrote {
			t.Errorf("%s: Wrote = %v, want %v", s.name, rep.Resolver.Wrote, s.wrote)
		}
		if want := r.shadowed; s.wantErr == nil && !slices.Equal(rep.Resolver.Shadowed, want) {
			t.Errorf("%s: Shadowed = %v, want %v", s.name, rep.Resolver.Shadowed, want)
		}
		last = rep.Resolver.Digest
	}
}

// When the entries, the Problems, and the shadowed domains return to an
// earlier state, the digest is the earlier one again.
func TestResolverDigestDependsOnlyOnTheReadState(t *testing.T) {
	f := installV1(t)
	r := &seenResolver{SysResolver: f.world.Resolver()}
	f.rec.Resolver = r
	before := f.converge(t).Resolver.Digest

	r.shadowed = []policy.Domain{mustDomain(t, "www.example.com")}
	f.world.SetProblems(nil, []reconcile.Problem{{Text: "foreign entry for example.com"}})
	if f.converge(t).Resolver.Digest == before {
		t.Fatal("the digest did not change with the Problems and the shadowed domains")
	}
	r.shadowed = nil
	f.world.SetProblems(nil, nil)

	if got := f.converge(t).Resolver.Digest; got != before {
		t.Errorf("digest = %s, want the earlier %s", got, before)
	}
}

// A read that fails sees nothing: the digest is empty, and the part
// writes nothing.
func TestConvergeReportsNoResolverDigestWhenTheReadFails(t *testing.T) {
	f := installV1(t)
	f.rec.Resolver = &seenResolver{SysResolver: f.world.Resolver(), shadowed: []policy.Domain{mustDomain(t, "www.example.com")}, fail: true}

	rep, err := f.rec.Converge(t.Context(), f.inputs())

	if !errors.Is(err, errRead) {
		t.Fatalf("err = %v, want errRead", err)
	}
	if rep.Resolver.Digest != "" || rep.Resolver.Shadowed != nil || rep.Resolver.Wrote {
		t.Errorf("Resolver = %+v, want the zero value", rep.Resolver)
	}
}
