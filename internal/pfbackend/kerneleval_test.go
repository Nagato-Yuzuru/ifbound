package pfbackend_test

// This file holds the evaluation of a packet by the kernel model, as
// pf_test and pf_route in XNU pf.c do it. It reads the rule lines that
// the model keeps, and it refuses each word that it does not know, so a
// rule that it cannot evaluate fails the test.

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/Nagato-Yuzuru/ifbound/internal/pfbackend"
	"github.com/Nagato-Yuzuru/ifbound/pf"
)

// anchorStack is the size of the anchor stack of pf (pf.c,
// pf_anchor_stack). pf skips an anchor rule when the stack is full.
const anchorStack = 64

// maxRoutes is the largest count of earlier routes of a packet that
// pf_route accepts. pf.c:9242: "if (pd->pf_mtag->pftag_routed++ > 3)"
// drops the packet, so pf routes one packet four times.
const maxRoutes = 3

// packet is a packet in the direction dir ("in" or "out") on the
// interface iface, to an address in the table dst ("" for no table). tag
// is the pf tag of the packet.
type packet struct {
	dir, dst, iface, tag string
}

// modelRule is a filter rule line, as the evaluation reads it.
type modelRule struct {
	action    string // "pass", "block", or "anchor"
	call      string // the anchor call of an anchor rule
	dir       string // "in", "out", or "" for both
	quick     bool
	on        []string // nil: each interface
	to        string   // a table, or "" for each address
	tagged    string
	notTagged bool
	tag       string
	route     string // "route-to", "reply-to", "dup-to", or ""
	routeIf   string
}

func parseModelRule(line string) (modelRule, error) {
	w := &words{f: splitWords(strings.ReplaceAll(line, "return-icmp(port-unr, port-unr)", "return-icmp"))}
	var r modelRule
	switch r.action = w.next(); r.action {
	case "pass":
	case "block":
		if slices.Contains([]string{"drop", "return", "return-icmp"}, w.peek()) {
			w.next()
		}
	case "anchor":
		r.call = unquote(w.next())
	default:
		return r, fmt.Errorf("kernel model: cannot evaluate the rule %q", line)
	}
	for !w.done() {
		if err := r.option(w); err != nil {
			return r, fmt.Errorf("kernel model: %w in %q", err, line)
		}
	}
	return r, nil
}

// option reads one option of a rule.
func (r *modelRule) option(w *words) error {
	switch o := w.next(); o {
	case "in", "out":
		r.dir = o
	case "quick":
		r.quick = true
	case "all", "inet":
	case "on":
		r.on = w.list()
	case "from":
		if src := w.next(); src != "any" {
			return fmt.Errorf("cannot evaluate the source %q", src)
		}
	case "to":
		if t := w.next(); t != "any" {
			r.to = unquote(strings.Trim(t, "<>"))
		}
	case "!":
		if w.next() != "tagged" {
			return errors.New("cannot evaluate the negation")
		}
		r.notTagged, r.tagged = true, unquote(w.next())
	case "tagged":
		r.tagged = unquote(w.next())
	case "tag":
		r.tag = unquote(w.next())
	case "label", "flags", "keep", "no":
		w.next()
	case "route-to", "reply-to", "dup-to":
		r.route, r.routeIf = o, w.pool()
	default:
		return fmt.Errorf("cannot evaluate %q", o)
	}
	return nil
}

// splitWords splits a rule line at spaces outside quotes.
func splitWords(line string) []string {
	var f []string
	var w strings.Builder
	quoted := false
	for _, c := range line + " " {
		switch {
		case c == ' ' && !quoted:
			if w.Len() > 0 {
				f = append(f, w.String())
				w.Reset()
			}
			continue
		case c == '"':
			quoted = !quoted
		}
		w.WriteRune(c)
	}
	return f
}

// words reads the words of a rule line in order.
type words struct {
	f []string
	i int
}

func (w *words) done() bool { return w.i >= len(w.f) }

func (w *words) peek() string {
	if w.done() {
		return ""
	}
	return w.f[w.i]
}

func (w *words) next() string {
	s := w.peek()
	w.i++
	return s
}

// list reads an interface, or a list of interfaces in braces.
func (w *words) list() []string {
	if w.peek() != "{" {
		return []string{unquote(w.next())}
	}
	w.next()
	var l []string
	for !w.done() && w.peek() != "}" {
		l = append(l, unquote(w.next()))
	}
	w.next()
	return l
}

// pool reads the pool of a route option, "(en0 192.0.2.1)" or "en0", and
// returns its interface.
func (w *words) pool() string {
	first := w.next()
	for last := first; strings.HasPrefix(first, "(") && !strings.HasSuffix(last, ")") && !w.done(); {
		last = w.next()
	}
	return strings.Trim(first, "()")
}

func unquote(s string) string { return strings.Trim(s, `"`) }

// matches reports whether the rule matches the packet.
func (r modelRule) matches(p packet) bool {
	return (r.dir == "" || r.dir == p.dir) &&
		(r.on == nil || slices.Contains(r.on, p.iface)) &&
		(r.to == "" || r.to == p.dst) &&
		(r.tagged == "" || (p.tag == r.tagged) != r.notTagged)
}

// filterRules returns the filter rule lines of a ruleset; "" is the main
// ruleset.
func (k *kernel) filterRules(path string) []string {
	lines := k.mainRules
	if path != "" {
		lines = k.rules[path]
	}
	return slices.DeleteFunc(slices.Clone(lines), func(l string) bool {
		return pfbackend.RuleKindOf(l) != pf.RulesetFilter
	})
}

// eval evaluates the rules of a ruleset for the packet, as pf_test_rule
// does. last is the last rule that matched. match is the match flag of
// pf_test_rule. eval reports whether a quick rule ended the evaluation.
func (k *kernel) eval(path string, p *packet, last **modelRule, match *bool, depth int) (bool, error) {
	for _, line := range k.filterRules(path) {
		r, err := parseModelRule(line)
		if err != nil {
			return false, err
		}
		if !r.matches(*p) {
			continue
		}
		if r.tag != "" {
			p.tag = r.tag
		}
		stop := r.quick
		if r.action == "anchor" {
			stop, err = k.call(path, r, p, last, match, depth)
		} else {
			*match, *last = true, &r
		}
		if err != nil || stop {
			return stop, err
		}
	}
	return false, nil
}

// call evaluates the anchors that an anchor rule in the ruleset path
// calls, as pf_step_into_anchor and pf_step_out_of_anchor (pf.c:3117,
// 3154) do:
//
//   - The call clears the match flag of pf_test_rule and the match flag
//     of the called anchor, also when the anchor stack is full and pf
//     skips the rule.
//   - A wildcard call evaluates the anchors directly below the called
//     anchor, in byte order of the names. After each one, when its own
//     match flag or the flag of pf_test_rule is set, the flag of the called
//     anchor is set and the flag of pf_test_rule is cleared. Nothing
//     clears the flag of an anchor below: it can hold the flag of an
//     earlier packet.
//   - At the end, when the flag of the called anchor or of pf_test_rule
//     is set, a quick anchor rule ends the evaluation.
//
// When a quick rule ends the evaluation in the call, pf can still set
// the flags of the calls around it on its way out. The model stops at
// once and does not set them.
func (k *kernel) call(path string, r modelRule, p *packet, last **modelRule, match *bool, depth int) (bool, error) {
	c, ok := setup(path, r.call)
	if !ok {
		return false, fmt.Errorf("kernel model: cannot set up the call %q in %q", r.call, path)
	}
	k.anchorMatch[c.path], *match = false, false
	if depth >= anchorStack {
		return false, nil
	}
	targets := []string{c.path}
	if c.wildcard {
		targets = nil
		for _, name := range pfbackend.Children(slices.Collect(maps.Keys(k.rules)), c.path) {
			targets = append(targets, c.path+"/"+name)
		}
	}
	for _, t := range targets {
		stop, err := k.eval(t, p, last, match, depth+1)
		if err != nil || stop {
			return stop, err
		}
		if c.wildcard && (k.anchorMatch[t] || *match) {
			k.anchorMatch[c.path], *match = true, false
		}
	}
	return (k.anchorMatch[c.path] || *match) && r.quick, nil
}

// send gives an outbound packet to the table dst to pf on the interface
// iface. It returns each interface that a copy of the packet leaves on.
// A route-to rule sends the packet out on another interface, and dup-to
// sends a copy there; pf evaluates the rules again on that interface,
// and the packet keeps its tag (pf_route). A reply-to rule routes only
// the packets of the other direction. pf_route counts the routes before
// it looks at the kind of route or the interface.
func (k *kernel) send(dst, iface string) ([]string, error) {
	p := packet{dir: "out", dst: dst, iface: iface}
	var out []string
	for routed := 0; ; routed++ {
		var last *modelRule
		var match bool
		if _, err := k.eval("", &p, &last, &match, 0); err != nil {
			return nil, err
		}
		switch {
		case last != nil && last.action == "block":
			return out, nil
		case last == nil || last.route == "":
			return append(out, p.iface), nil
		case routed > maxRoutes:
			return out, nil
		case last.route == "reply-to" || last.routeIf == p.iface:
			return append(out, p.iface), nil
		case last.route == "dup-to":
			out = append(out, p.iface)
		}
		p.iface = last.routeIf
	}
}

// receive gives an inbound packet on the interface iface to pf. Only the
// match flags of the anchors keep its effect.
func (k *kernel) receive(iface string) error {
	p := packet{dir: "in", iface: iface}
	var last *modelRule
	var match bool
	_, err := k.eval("", &p, &last, &match, 0)
	return err
}
