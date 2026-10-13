package pfbackend

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

var errExit = errors.New("exit status 1")

// fakePF is a Runner that models the part of pf that the Backend uses. It
// prints in the formats that pfctl prints on macOS 27 (see parse_test.go
// for the captured outputs). It keeps the rules of a load as they are:
// the real kernel rewrites them, but the Backend reads only the sentinel
// label and the indentation.
type fakePF struct {
	enabled bool
	tokens  []string
	next    int
	// anchors maps an anchor path to its rule lines. It holds the ifbound
	// anchor, its sub-anchors, and the other anchors.
	anchors map[string][]string
	// main holds the rules of the main ruleset.
	main []string
	// nat maps an anchor path to its NAT rules; "" is the main ruleset.
	nat    map[string][]string
	tables map[string]map[netip.Prefix]bool // entry to negated
	ifaces []string                         // "-sI -v" lines
	states map[netip.Addr]bool              // destinations with a state
	// stickyNegation makes "-T delete" keep negated entries.
	stickyNegation bool
	// fail makes each call whose arguments it accepts fail.
	fail func(args []string) bool
	// complain adds an error to the stderr of each call whose arguments
	// it accepts, with exit status 0, as pfctl does for a ruleset that it
	// cannot read.
	complain func(args []string) bool
	calls    [][]string
}

func newFakePF() *fakePF {
	return &fakePF{
		anchors: map[string][]string{
			"com.apple/200.AirDrop":             {`anchor "com.apple/200.AirDrop/*" all`},
			"com.apple/250.ApplicationFirewall": {`anchor "com.apple/250.ApplicationFirewall/*" all`},
		},
		main:   []string{`scrub-anchor "com.apple/*" all fragment reassemble`, `anchor "com.apple/*" all`},
		nat:    map[string][]string{"": {`nat-anchor "com.apple/*" all`, `rdr-anchor "com.apple/*" all`}},
		tables: make(map[string]map[netip.Prefix]bool),
		ifaces: []string{"ALL", "en0", "lo0", "utun0"},
		states: make(map[netip.Addr]bool),
	}
}

func (f *fakePF) Run(_ context.Context, stdin []byte, args ...string) (Output, error) {
	f.calls = append(f.calls, slices.Clone(args))
	if f.fail != nil && f.fail(args) {
		return Output{Stderr: []byte("pfctl: injected failure\n")}, errExit
	}
	o, err := f.run(stdin, args)
	if f.complain != nil && f.complain(args) {
		o.Stderr = append(o.Stderr, "pfctl: DIOCGETRULES: Invalid argument\n"...)
	}
	return o, err
}

func (f *fakePF) run(stdin []byte, args []string) (Output, error) {
	a := strings.Join(args, " ")
	switch {
	case a == "-s info":
		status := "Disabled"
		if f.enabled {
			status = "Enabled"
		}
		return out("No ALTQ support in kernel\nALTQ related functions disabled\nStatus: " + status + " for 0 days 00:00:01           Debug: Urgent\n\nState Table\n"), nil
	case a == "-E":
		f.enabled = true
		f.next++
		tok := strconv.Itoa(1000 + f.next)
		f.tokens = append(f.tokens, tok)
		return Output{Stderr: []byte("No ALTQ support in kernel\nALTQ related functions disabled\npf enabled\nToken : " + tok + "\n")}, nil
	case len(args) == 2 && args[0] == "-X":
		i := slices.Index(f.tokens, args[1])
		switch {
		case !f.enabled:
			return Output{Stderr: []byte("pfctl: pf not enabled\n")}, errExit
		case i < 0:
			return Output{Stderr: []byte("pfctl: pf: token invalid\n")}, errExit
		}
		f.tokens = slices.Delete(f.tokens, i, i+1)
		f.enabled = len(f.tokens) > 0
		return Output{}, nil
	case a == "-sr":
		return out(strings.Join(f.main, "\n") + "\n"), nil
	case a == "-sn":
		return out(strings.Join(f.nat[""], "\n") + "\n"), nil
	case a == "-sA -v":
		return out(f.listAnchors("", true)), nil
	case a == "-s state":
		return out(f.showStates()), nil
	case a == "-sI -v":
		return out(strings.Join(f.ifaces, "\n") + "\n"), nil
	case len(args) == 4 && args[0] == "-k":
		dst := netip.MustParsePrefix(args[3])
		for d := range f.states {
			if dst.Contains(d) {
				delete(f.states, d)
			}
		}
		return Output{}, nil
	case len(args) >= 2 && args[0] == "-v" && args[1] == "-a":
		return f.table(args[2], args[4], args[6], stdin, true)
	case len(args) >= 2 && args[0] == "-a":
		return f.anchor(args[1], args[2:], stdin)
	}
	return Output{}, fmt.Errorf("fakePF: unknown command %q", a)
}

func (f *fakePF) anchor(path string, rest []string, stdin []byte) (Output, error) {
	r := strings.Join(rest, " ")
	switch {
	case r == "-sr":
		if base, ok := strings.CutSuffix(path, "/*"); ok {
			var b strings.Builder
			f.print(&b, base, "")
			return out(b.String()), nil
		}
		return out(strings.Join(f.anchors[path], "\n") + "\n"), nil
	case r == "-sn":
		return out(strings.Join(f.nat[path], "\n") + "\n"), nil
	case r == "-f -":
		f.load(path, stdin)
		return Output{}, nil
	case r == "-sA" || r == "-sA -v":
		return out(f.listAnchors(path, r == "-sA -v")), nil
	case r == "-F rules":
		f.anchors[path] = nil
		return Output{}, nil
	case r == "-sT":
		return out(strings.Join(slices.Sorted(maps.Keys(f.tables)), "\n") + "\n"), nil
	case len(rest) >= 4 && rest[0] == "-t" && rest[2] == "-T":
		return f.table(path, rest[1], rest[3], stdin, false)
	}
	return Output{}, fmt.Errorf("fakePF: unknown anchor command %q", r)
}

// load replaces the rules of an anchor. A table line creates its table
// when it is missing; an anchor rule creates its sub-anchor.
func (f *fakePF) load(path string, stdin []byte) {
	var rules []string
	for line := range strings.Lines(string(stdin)) {
		line = strings.TrimSpace(line)
		if name, ok := strings.CutPrefix(line, "table <\""); ok {
			name, _, _ = strings.Cut(name, "\"")
			if f.tables[name] == nil {
				f.tables[name] = make(map[netip.Prefix]bool)
			}
		} else if line != "" {
			rules = append(rules, line)
		}
	}
	f.anchors[path] = rules
	for _, rule := range rules {
		if name, ok := anchorRule(rule); ok {
			if _, ok := f.anchors[path+"/"+name]; !ok {
				f.anchors[path+"/"+name] = nil
			}
		}
	}
}

// listAnchors lists the children of an anchor, or all anchors below it.
func (f *fakePF) listAnchors(path string, all bool) string {
	var b strings.Builder
	prefix := path + "/"
	if path == "" {
		prefix = ""
	}
	for _, p := range slices.Sorted(maps.Keys(f.anchors)) {
		sub, ok := strings.CutPrefix(p, prefix)
		if ok && (all || !strings.Contains(sub, "/")) {
			b.WriteString("  " + p + "\n")
		}
	}
	return b.String()
}

// showStates prints the states as "pfctl -s state" does.
func (f *fakePF) showStates() string {
	var b strings.Builder
	for _, a := range slices.SortedFunc(maps.Keys(f.states), netip.Addr.Compare) {
		if a.Is4() {
			b.WriteString("ALL tcp 192.168.64.14:51121 -> " + a.String() + ":443       ESTABLISHED:ESTABLISHED\n")
		} else {
			b.WriteString("ALL tcp fe80::14[51121] -> " + a.String() + "[443]       ESTABLISHED:ESTABLISHED\n")
		}
	}
	return b.String()
}

// print writes the rules of an anchor as "pfctl -a <anchor>/* -sr" does:
// each anchor rule gets the rules of its sub-anchor between braces.
func (f *fakePF) print(b *strings.Builder, path, indent string) {
	for _, rule := range f.anchors[path] {
		name, ok := anchorRule(rule)
		if !ok {
			b.WriteString(indent + rule + "\n")
			continue
		}
		b.WriteString(indent + rule + " {\n")
		f.print(b, path+"/"+name, indent+"  ")
		b.WriteString(indent + "}\n")
	}
}

func (f *fakePF) table(anchor, name, cmd string, stdin []byte, verbose bool) (Output, error) {
	if anchor != Anchor {
		return Output{}, fmt.Errorf("fakePF: table in anchor %s", anchor)
	}
	t, exists := f.tables[name]
	noTable := Output{Stderr: []byte("pfctl: " + noTable + "\n")}
	switch cmd {
	case "show":
		if !exists {
			return noTable, errExit
		}
		return out(show(t)), nil
	case "kill":
		delete(f.tables, name)
		return Output{Stderr: []byte("0 table deleted.\n")}, nil
	case "add":
		if !exists {
			t = make(map[netip.Prefix]bool)
			f.tables[name] = t
		}
		fb := f.add(t, stdinEntries(stdin))
		if !verbose {
			return Output{}, nil
		}
		return out(fb), nil
	case "delete":
		if !exists {
			return noTable, errExit
		}
		for _, e := range stdinEntries(stdin) {
			if neg, ok := t[e.p]; ok && neg == e.neg && (!neg || !f.stickyNegation) {
				delete(t, e.p)
			}
		}
		return Output{}, nil
	}
	return Output{}, fmt.Errorf("fakePF: unknown table command %q", cmd)
}

// show prints a table as "-T show" does.
func show(t map[netip.Prefix]bool) string {
	var b strings.Builder
	for _, p := range slices.SortedFunc(maps.Keys(t), netip.Prefix.Compare) {
		neg := " "
		if t[p] {
			neg = "!"
		}
		b.WriteString("  " + neg + entryText(p) + "\n")
	}
	return b.String()
}

// add adds entries to a table and returns the feedback of "-v -T add".
func (f *fakePF) add(t map[netip.Prefix]bool, entries []stdinEntry) string {
	var b strings.Builder
	for _, e := range entries {
		neg, present := t[e.p]
		switch {
		case present && neg != e.neg:
			b.WriteString("Y  " + entryText(e.p) + "\n")
		case !present:
			t[e.p] = e.neg
			b.WriteString("A  " + entryText(e.p) + "\n")
		}
	}
	return b.String()
}

type stdinEntry struct {
	p   netip.Prefix
	neg bool
}

func stdinEntries(stdin []byte) []stdinEntry {
	var es []stdinEntry
	for line := range strings.Lines(string(stdin)) {
		line = strings.TrimSpace(line)
		text, neg := strings.CutPrefix(line, "!")
		es = append(es, stdinEntry{p: netip.MustParsePrefix(text), neg: neg})
	}
	return es
}

// entryText prints a host entry without its length, as pfctl does.
func entryText(p netip.Prefix) string {
	if p.IsSingleIP() {
		return p.Addr().String()
	}
	return p.String()
}

func out(stdout string) Output { return Output{Stdout: []byte(stdout)} }

// callsOf returns the calls whose arguments contain every word in want.
func (f *fakePF) callsOf(want ...string) [][]string {
	var got [][]string
	for _, c := range f.calls {
		if !slices.ContainsFunc(want, func(w string) bool { return !slices.Contains(c, w) }) {
			got = append(got, c)
		}
	}
	return got
}
