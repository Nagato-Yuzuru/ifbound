package dnsplugin

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/Nagato-Yuzuru/ifbound/internal/ipc"
)

// syntheticZone holds a protected name with an HTTPS record whose target
// is outside it, the target with a CNAME to its address, and an HTTPS
// record of the target in AliasMode to a third name.
func syntheticZone() map[string]zoneReply {
	return map[string]zoneReply{
		zkey("www.example.com.", dns.TypeHTTPS): {answer: []string{
			"www.example.com. 300 IN HTTPS 1 svc.cdn.net. alpn=h2",
		}},
		zkey("svc.cdn.net.", dns.TypeA): {answer: []string{
			"svc.cdn.net. 60 IN CNAME edge.cdn.org.",
			"edge.cdn.org. 300 IN A 192.0.2.10",
		}},
		zkey("svc.cdn.net.", dns.TypeHTTPS): {answer: []string{
			"svc.cdn.net. 120 IN HTTPS 0 pool.other.org.",
		}},
		zkey("pool.other.org.", dns.TypeAAAA): {answer: []string{
			"pool.other.org. 30 IN AAAA 2001:db8::11",
		}},
	}
}

// targetOf returns the TargetName of the first HTTPS record in m.
func targetOf(t *testing.T, m *dns.Msg) string {
	t.Helper()
	for _, r := range m.Answer {
		if h, ok := r.(*dns.HTTPS); ok {
			return h.Target
		}
	}
	t.Fatalf("no HTTPS record in\n%v", m)
	return ""
}

// The client asks for the synthetic name of an HTTPS target. The plugin
// resolves the target upstream, gives the addresses to the synthetic
// name, and reports them under the protected name.
func TestSyntheticNameResolvesTheTargetUnderTheOrigin(t *testing.T) {
	z := &zone{replies: syntheticZone()}
	first := askZone(t, z, true, "www.example.com.", dns.TypeHTTPS)
	syn := targetOf(t, first.reply)

	for _, protected := range []bool{true, false} {
		z := &zone{replies: syntheticZone()}
		res := askZone(t, z, protected, syn, dns.TypeA)
		if res.err != nil || res.reply == nil || res.reply.Rcode != dns.RcodeSuccess {
			t.Fatalf("protected=%v: ServeDNS = %d, %v", protected, res.rcode, res.err)
		}
		// The reply is flattened also without protection: the name exists
		// only in this form.
		if got, want := strs(res.reply.Answer), records(syn+" 60 IN A 192.0.2.10"); !slices.Equal(got, want) {
			t.Errorf("protected=%v: answer %v, want %v", protected, got, want)
		}
		requireNoAlias(t, syn, res.reply)
		o := res.rep.last.Load()
		if o == nil || o.QName != "www.example.com." || !slices.Equal(addrStrings(o.Addrs), []string{"192.0.2.10"}) || o.TTL != time.Minute {
			t.Errorf("protected=%v: report = %+v, want www.example.com. [192.0.2.10] 1m", protected, o)
		}
		if got := z.questions(); !slices.Equal(got, []string{zkey("svc.cdn.net.", dns.TypeA)}) {
			t.Errorf("protected=%v: upstream got %v, want only the target", protected, got)
		}
	}
}

// An AliasMode target of a target gets a synthetic name below the
// synthetic name, at each depth. Its addresses go under the first origin,
// so a policy for that exact name matches them.
func TestNestedSyntheticNameReportsUnderTheFirstOrigin(t *testing.T) {
	replies := syntheticZone()
	replies[zkey("pool.other.org.", dns.TypeHTTPS)] = zoneReply{answer: []string{"pool.other.org. 60 IN HTTPS 0 deep.third.org."}}
	replies[zkey("deep.third.org.", dns.TypeAAAA)] = zoneReply{answer: []string{"deep.third.org. 30 IN AAAA 2001:db8::12"}}
	z := &zone{replies: replies}
	var seen []ipc.Observation
	exact := ackFunc(func(_ context.Context, o ipc.Observation) (ipc.Ack, error) {
		seen = append(seen, o)
		return ipc.Ack{Protected: o.QName == "www.example.com."}, nil
	})
	h := &handler{key: testKey, next: z, reporter: exact, timeout: time.Second}

	name := "www.example.com."
	for _, target := range []string{"svc.cdn.net.", "pool.other.org.", "deep.third.org."} {
		res := query(t, h, name, dns.TypeHTTPS)
		if res.err != nil || res.reply == nil {
			t.Fatalf("ServeDNS(%s HTTPS) = %d, %v", name, res.rcode, res.err)
		}
		if target == "svc.cdn.net." {
			requireSynthetic(t, res.reply, name, target, 1, "alpn=h2")
		} else {
			requireSynthetic(t, res.reply, name, target, 0, "")
		}
		name = targetOf(t, res.reply)
	}
	seen = nil
	res := query(t, h, name, dns.TypeAAAA)
	if res.err != nil || res.reply == nil {
		t.Fatalf("ServeDNS(%s AAAA) = %d, %v", name, res.rcode, res.err)
	}
	if got, want := strs(res.reply.Answer), records(name+" 30 IN AAAA 2001:db8::12"); !slices.Equal(got, want) {
		t.Errorf("answer %v, want %v", got, want)
	}
	if len(seen) != 1 || seen[0].QName != "www.example.com." || !slices.Equal(addrStrings(seen[0].Addrs), []string{"2001:db8::12"}) {
		t.Errorf("reports = %+v, want one under www.example.com. with 2001:db8::12", seen)
	}
}

// The reply to a synthetic name goes out only after ifboundd has its
// addresses.
func TestSyntheticReplyWaitsForTheAck(t *testing.T) {
	syn, _ := testKey.synthName("svc.cdn.net.", "www.example.com.")
	failing := ackFunc(func(context.Context, ipc.Observation) (ipc.Ack, error) { return ipc.Ack{}, ipc.ErrUnavailable })
	h := &handler{key: testKey, next: &zone{replies: syntheticZone()}, reporter: failing, timeout: time.Second}
	res := query(t, h, syn, dns.TypeA)
	if res.rcode != dns.RcodeServerFailure || !errors.Is(res.err, ipc.ErrUnavailable) || res.reply != nil {
		t.Errorf("ServeDNS = %d, %v, reply %v; want SERVFAIL without a reply", res.rcode, res.err, res.reply)
	}
}

// The target of a synthetic name gets the local answer of its name, as the
// name itself would (see localRcode).
func TestSyntheticTargetWithALocalAnswerStaysLocal(t *testing.T) {
	tests := map[string]int{
		"use-application-dns.net.": dns.RcodeNameError,
		"_dns.resolver.arpa.":      dns.RcodeSuccess,
	}
	for target, want := range tests {
		t.Run(target, func(t *testing.T) {
			syn, _ := testKey.synthName(target, "www.example.com.")
			z := &zone{replies: map[string]zoneReply{}}
			res := askZone(t, z, true, syn, dns.TypeHTTPS)
			if res.err != nil || res.reply == nil || res.reply.Rcode != want || len(res.reply.Answer) != 0 {
				t.Errorf("ServeDNS = %d, %v, reply %v; want rcode %d without records", res.rcode, res.err, res.reply, want)
			}
			if q := z.questions(); len(q) != 0 {
				t.Errorf("upstream got %v, want nothing", q)
			}
		})
	}
}

// A synthetic name has at most 255 octets, and an origin below the root.
func TestSynthNameLength(t *testing.T) {
	owner := strings.Repeat("o", 63) + "." + strings.Repeat("p", 63) + "." + strings.Repeat("q", 63) + ".example."
	if name, ok := testKey.synthName("t.example.", "."); ok {
		t.Errorf("synthetic name %s below the root, want none", name)
	}
	if _, ok, err := testKey.parse("t.example._ifb." + strings.Repeat("a", 26) + "."); ok || !errors.Is(err, errBadTag) {
		t.Errorf("parse of a name with the root as origin = %v, %v; want errBadTag", ok, err)
	}
	// owner has 64*3+9 = 201 wire octets. The synthLabel and the tag
	// take 32, so the target can have 22 octets without its root.
	for n, want := range map[int]bool{21: true, 22: true, 23: false} {
		target := strings.Repeat("t", n-1) + "."
		name, ok := testKey.synthName(target, owner)
		if ok != want {
			t.Errorf("target of %d octets: ok = %v, want %v", n, ok, want)
		}
		if ok {
			if w, err := wireName(name); err != nil || len(w) != n+32+201 {
				t.Errorf("synthetic name has %d octets (%v), want %d", len(w), err, n+32+201)
			}
		}
	}
}
