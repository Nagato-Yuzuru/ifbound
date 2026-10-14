package daemon_test

import (
	"math/rand/v2"
	"strings"
	"testing"
	"testing/synctest"

	"github.com/Nagato-Yuzuru/ifbound/internal/daemon"
)

// flagConfig has exact and suffix policies.
const flagConfig = header + `
[[policy]]
name = "web"
to = ["example.com", "*.example.net"]
only_via = ["en0"]

[[policy]]
name = "mail"
to = ["mail.example.org", "*.mail.example.org"]
deny_via = ["en1"]
`

// matchesFlagConfig tells if qname equals an exact domain of flagConfig, or is
// a suffix domain or below it, without ASCII case.
func matchesFlagConfig(qname string) bool {
	n := strings.TrimSuffix(strings.ToLower(qname), ".")
	for _, exact := range []string{"example.com", "mail.example.org"} {
		if n == exact {
			return true
		}
	}
	for _, suffix := range []string{"example.net", "mail.example.org"} {
		if n == suffix || strings.HasSuffix(n, "."+suffix) {
			return true
		}
	}
	return false
}

func TestAckIsProtectedIffTheNameMatchesAPolicy(t *testing.T) {
	labels := []string{"www", "a", "example", "net", "com", "org", "mail", "EXAMPLE", "Net", "notexample", "x-example"}
	fixed := []string{
		"example.com", "EXAMPLE.COM.", "www.example.com", "example.net", "a.b.example.net.", "notexample.net",
		"example.org", "mail.example.org", "x.mail.example.org", "mail.example.org.evil", "net", "com.",
	}
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, flagConfig)
		defer h.stop()
		h.wantState(daemon.StateReady)
		names := append(fixed, randomNames(rand.New(rand.NewPCG(9, 9)), labels, 400)...) //nolint:gosec // deterministic test names
		hits := 0
		for i, name := range names {
			o := obs(name)
			if i%2 == 0 {
				o = obs(name, "203.0.113.7", "2001:db8::7")
			}
			ack, err := h.d.Observe(t.Context(), o)
			if err != nil {
				t.Fatalf("Observe(%q) = %v", name, err)
			}
			want := matchesFlagConfig(name)
			if want {
				hits++
			}
			if ack.Protected != want {
				t.Errorf("Observe(%q): protected %v, want %v", name, ack.Protected, want)
			}
		}
		if hits < 20 || hits > len(names)-20 {
			t.Errorf("only %d of %d names match: the names do not test both sides", hits, len(names))
		}
	})
}

// randomNames joins one to four labels, with a trailing dot or not.
func randomNames(rnd *rand.Rand, labels []string, n int) []string {
	out := make([]string, 0, n)
	for range n {
		parts := make([]string, 1+rnd.IntN(4))
		for i := range parts {
			parts[i] = labels[rnd.IntN(len(labels))]
		}
		name := strings.Join(parts, ".")
		if rnd.IntN(2) == 0 {
			name += "."
		}
		out = append(out, name)
	}
	return out
}
