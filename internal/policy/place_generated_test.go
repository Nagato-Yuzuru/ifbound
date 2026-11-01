package policy

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
)

// placeGen writes a configuration with a random layout and one fault. It
// records the line and the byte column where it writes each token. So the
// expected place of the fault comes from the generator, not from the index.
type placeGen struct {
	r    *rand.Rand
	b    strings.Builder
	crlf bool
}

type place struct{ line, col int }

func (p place) String() string { return fmt.Sprintf("%d:%d", p.line, p.col) }

// here returns the place of the next byte to write.
func (g *placeGen) here() place {
	s := g.b.String()
	return place{strings.Count(s, "\n") + 1, len(s) - strings.LastIndexByte(s, '\n')}
}

func (g *placeGen) pick(xs ...string) string { return xs[g.r.IntN(len(xs))] }

func (g *placeGen) nl() {
	if g.crlf {
		g.b.WriteString("\r\n")
	} else {
		g.b.WriteString("\n")
	}
}

// noise writes blank lines and comments. Some have multi-byte text.
func (g *placeGen) noise() {
	for range g.r.IntN(3) {
		g.b.WriteString(g.pick("", "# é 日本 comment", "  # note", "\t"))
		g.nl()
	}
}

// key writes the indentation and one key in a random form. It returns the
// place of the key.
func (g *placeGen) key(name string) place { return g.keyParts(name)[0] }

// keyParts writes a key like key does. It returns the place of each part
// of a dotted key.
func (g *placeGen) keyParts(name string) []place {
	g.b.WriteString(g.pick("", "  ", "\t", " \t "))
	var at []place
	form := g.r.IntN(4)
	for i, part := range strings.Split(name, ".") {
		if i > 0 {
			g.b.WriteString(".")
		}
		at = append(at, g.here())
		switch form {
		case 0:
			g.b.WriteString(part)
		case 1:
			g.b.WriteString(`"` + part + `"`)
		case 2:
			g.b.WriteString("'" + part + "'")
		default: // an escape in a basic string gives the same key
			g.b.WriteString(`"` + part[:1] + fmt.Sprintf(`\u%04X`, part[1]) + part[2:] + `"`)
		}
	}
	g.b.WriteString(g.pick(" = ", "=", "  =  "))
	return at
}

// header writes "[name]" or "[[name]]". It returns the place of the last
// part of the name.
func (g *placeGen) header(name string, array bool) place {
	g.b.WriteString(g.pick("", "  "))
	open, shut := "[", "]"
	if array {
		open, shut = "[[", "]]"
	}
	g.b.WriteString(open + g.pick("", " "))
	last := strings.LastIndexByte(name, '.') + 1
	g.b.WriteString(name[:last])
	at := g.here()
	g.b.WriteString(name[last:] + g.pick("", " ") + shut + g.pick("", "  # é"))
	g.nl()
	return at
}

// strs writes an array of raw TOML values, sometimes on several lines. It
// returns the place of each element.
func (g *placeGen) strs(elems ...string) []place {
	multi := g.r.IntN(3) == 0
	g.b.WriteString("[")
	var at []place
	for i, e := range elems {
		if multi {
			g.nl()
			g.b.WriteString("    ")
		} else if i > 0 {
			g.b.WriteString(g.pick(" ", "", "  "))
		}
		at = append(at, g.here())
		g.b.WriteString(e)
		if i < len(elems)-1 || multi {
			g.b.WriteString(",")
		}
	}
	if multi {
		g.nl()
	}
	g.b.WriteString("]")
	g.nl()
	return at
}

type faultKind int

const (
	fUnknownPolicyKey faultKind = iota
	fUnknownDNSKey
	fBadAddress
	fBadUser
	fDupKey
	fDupTable
	fBadRetain
	fDupName
	fUpstreamCheck
	fNestedArray
	fDottedTypo
	fUnknownInlineKey
	fScopeArray
	fDottedLeaf
	fDNSSubtable
	nFaults
)

type genCase struct {
	doc   string
	field string
	want  place
	fault faultKind
	check bool // the fault comes from CheckUpstreams, not from Parse
}

func q(s string) string { return `"` + s + `"` }

// generate writes one configuration with the fault f.
func generate(r *rand.Rand, f faultKind) genCase {
	g := &placeGen{r: r, crlf: r.IntN(4) == 0}
	c := genCase{fault: f}
	g.noise()
	c.dns(g)
	if g.r.IntN(2) == 0 || f == fDupKey || f == fDupTable || f == fBadRetain {
		c.addrbook(g)
	}
	n := 1 + g.r.IntN(3)
	if f == fDupName && n == 1 {
		n = 2
	}
	target := g.r.IntN(n)
	for i := range n {
		c.policy(g, i, n, i == target)
	}
	c.doc = g.b.String()
	return c
}

func (c *genCase) dns(g *placeGen) {
	g.header("dns", false)
	if c.fault == fUnknownDNSKey {
		c.field, c.want = "dns.colour", g.key("colour")
		g.b.WriteString("1")
		g.nl()
	}
	g.key("upstream")
	g.strs(q("tls://9.9.9.9@dns.example"))
	g.noise()
	if c.fault == fDNSSubtable {
		c.field, c.want = "dns.foo", g.header("dns.foo", false)
	}
}

func (c *genCase) addrbook(g *placeGen) {
	g.header("addrbook", false)
	k := g.key("retain")
	if c.fault == fBadRetain {
		c.field, c.want = "addrbook.retain", k
		g.b.WriteString(q("never"))
	} else {
		g.b.WriteString(q("7d"))
	}
	g.nl()
	if c.fault == fDupKey {
		c.field, c.want = "addrbook.retain", g.key("retain")
		g.b.WriteString(q("1h"))
		g.nl()
		g.key("retain") // a third definition: the error names the second
		g.b.WriteString(q("2h"))
		g.nl()
	}
	g.noise()
	if c.fault == fDupTable {
		c.field, c.want = "addrbook", g.header("addrbook", false)
		g.header("addrbook", false)
	}
}

// policy writes policy i of n. hit tells whether the fault goes into it.
func (c *genCase) policy(g *placeGen, i, n int, hit bool) {
	pol := fmt.Sprintf("policy[%d]", i)
	f := c.fault
	g.header("policy", true)
	g.noise()
	dupName := f == fDupName && i == n-1
	name := fmt.Sprintf("p%d", i)
	if dupName {
		name = "p0"
	}
	nk := g.key("name")
	g.b.WriteString(q(name))
	g.nl()
	if dupName {
		c.field, c.want = pol+".name", nk
	}
	if f == fUnknownPolicyKey && hit {
		c.field, c.want = pol+".colour", g.key("colour")
		g.b.WriteString(q("red"))
		g.nl()
	}
	c.to(g, pol, hit)
	g.key("only_via")
	g.b.WriteString("[]")
	g.nl()
	if f == fDottedTypo && hit {
		c.field, c.want = pol+".scop", g.key("scop.users")
		g.b.WriteString(`["a"]`)
		g.nl()
	}
	if f == fDottedLeaf && hit {
		c.field, c.want = pol+".scope.userz", g.keyParts("scope.userz")[1]
		g.b.WriteString(`["a"]`)
		g.nl()
	} else {
		c.scope(g, hit, pol)
	}
	g.noise()
}

func (c *genCase) to(g *placeGen, pol string, hit bool) {
	tk := g.key("to")
	elems := []string{q("1.1.1.1"), q("example.com"), q("10.0.0.0/8")}[:1+g.r.IntN(3)]
	k := g.r.IntN(len(elems))
	elem := fmt.Sprintf("%s.to[%d]", pol, k)
	if !hit {
		g.strs(elems...)
		return
	}
	//nolint:exhaustive // the other faults do not touch "to"
	switch c.fault {
	case fBadAddress:
		elems[k] = q("bad host")
		c.field, c.want = elem, g.strs(elems...)[k]
	case fNestedArray:
		elems[k] = `["x"]`
		// An array element that is an array has no range of its own. The
		// place is the key of the array that holds it.
		c.field, c.want = elem, tk
		g.strs(elems...)
	case fUpstreamCheck:
		elems[k] = q("9.9.9.0/24")
		c.field, c.want, c.check = pol+".to", tk, true
		g.strs(elems...)
	default:
		g.strs(elems...)
	}
}

// scope writes an optional scope in one of three forms, or the faulty
// array of tables [[policy.scope]].
func (c *genCase) scope(g *placeGen, hit bool, pol string) {
	if c.fault == fScopeArray && hit {
		c.field, c.want = pol+".scope", g.header("policy.scope", true)
		g.key("users")
		g.strs(q("alice"))
		return
	}
	badUser := c.fault == fBadUser && hit
	inlineKey := c.fault == fUnknownInlineKey && hit
	form := g.r.IntN(4)
	if inlineKey {
		form = 1
	}
	if form == 0 && !badUser {
		return
	}
	users := []string{q("alice"), q("bob")}
	k := g.r.IntN(len(users))
	if badUser {
		users[k] = q("bad user")
	}
	var at []place
	switch form {
	case 1: // an inline table on one line
		g.key("scope")
		g.b.WriteString("{ ")
		if inlineKey {
			g.b.WriteString(`"é" = "日本", `)
			c.field, c.want = pol+".scope.aaa", g.here()
			g.b.WriteString("aaa = 1, ")
		}
		g.b.WriteString("users = [")
		for i, u := range users {
			if i > 0 {
				g.b.WriteString(", ")
			}
			at = append(at, g.here())
			g.b.WriteString(u)
		}
		g.b.WriteString("] }")
		g.nl()
	case 2: // a dotted key
		g.key("scope.users")
		at = g.strs(users...)
	default: // a sub-table header
		g.header("policy.scope", false)
		g.key("users")
		at = g.strs(users...)
	}
	if badUser {
		c.field, c.want = fmt.Sprintf("%s.scope.users[%d]", pol, k), at[k]
	}
}

func checkGenerated(t *testing.T, c genCase) {
	t.Helper()
	cfg, err := ParseBytes([]byte(c.doc))
	if c.check {
		if err != nil {
			t.Fatalf("fault %d: Parse = %v, want nil\n%s", c.fault, err, c.doc)
		}
		err = cfg.CheckUpstreams()
	}
	var fe *FieldError
	if !errors.As(err, &fe) {
		t.Fatalf("fault %d: err = %v, want a *FieldError\n%s", c.fault, err, c.doc)
	}
	if c.check {
		fe.Locate([]byte(c.doc))
	}
	got := place{fe.Line, fe.Column}
	if fe.Field != c.field || got != c.want {
		t.Fatalf("fault %d: got %q at %v, want %q at %v (%v)\n%s", c.fault, fe.Field, got, c.field, c.want, err, c.doc)
	}
}

// TestGeneratedFaultPlaces compares the place of each fault with the place
// where the generator wrote the faulty token.
func TestGeneratedFaultPlaces(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for i := range 30000 {
		checkGenerated(t, generate(r, faultKind(i%int(nFaults))))
	}
}

func FuzzGeneratedFaultPlaces(f *testing.F) {
	f.Add(uint64(1), uint64(2), uint8(0))
	f.Fuzz(func(t *testing.T, s1, s2 uint64, k uint8) {
		checkGenerated(t, generate(rand.New(rand.NewPCG(s1, s2)), faultKind(int(k)%int(nFaults))))
	})
}
