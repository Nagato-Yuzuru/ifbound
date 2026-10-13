package pfbackend_test

// This file holds a model of the pf kernel and of the pfctl command line,
// for the tests of the public methods. It is independent of
// fakepf_test.go: it parses pfctl flags in any order, keeps reference
// tokens as the macOS kernel does, keeps NAT rules apart from filter
// rules, and refuses each flag that it does not know, so an unexpected
// pfctl call fails the test.

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/Nagato-Yuzuru/ifbound/internal/pfbackend"
)

var errKernelExit = errors.New("exit status 1")

// kernel is the model of pf. Its state outlives a Backend, as the real
// kernel state outlives ifboundd.
type kernel struct {
	enabled bool
	// refs holds the reference tokens of "pfctl -E".
	refs    []string
	nextTok int
	// mainRules and mainNat are the filter and the NAT rules of the main
	// ruleset.
	mainRules []string
	mainNat   []string
	// rules and nat map an anchor path to its filter and NAT rules. A key
	// with a nil value is an anchor that exists and has no rule.
	rules map[string][]string
	nat   map[string][]string
	// tables maps an anchor path and a table name to the entries; the
	// value is true for a negated entry.
	tables map[string]map[string]map[netip.Prefix]bool
	// states holds the destination of each state.
	states []netip.Addr
	// ifaces are the lines of "pfctl -sI -v".
	ifaces []string

	// fail makes a call fail when it returns true.
	fail func(args []string) bool
	// calls records the arguments of every call.
	calls [][]string
	// disables counts the calls of "pfctl -d".
	disables int
}

// newKernel returns pf as macOS 27 boots it, with pf disabled: the main
// ruleset of /etc/pf.conf and the two anchors of macOS.
func newKernel() *kernel {
	return &kernel{
		mainRules: []string{`scrub-anchor "com.apple/*" all fragment reassemble`, `anchor "com.apple/*" all`},
		mainNat:   []string{`nat-anchor "com.apple/*" all`, `rdr-anchor "com.apple/*" all`},
		rules: map[string][]string{
			"com.apple":                         nil,
			"com.apple/200.AirDrop":             {`anchor "Bonjour" all`},
			"com.apple/200.AirDrop/Bonjour":     nil,
			"com.apple/250.ApplicationFirewall": {`pass in quick on lo0 all`},
		},
		nat:    map[string][]string{},
		tables: map[string]map[string]map[netip.Prefix]bool{},
		ifaces: []string{"ALL", "en0", "lo0", "utun4"},
	}
}

// pfctlArgs is a parsed pfctl command line.
type pfctlArgs struct {
	anchor, table, tcmd, show, file, flush, release string
	kills                                           []string
	verbose, enable, disable                        bool
	rest                                            []string
}

func parseArgs(args []string) (pfctlArgs, error) {
	var p pfctlArgs
	value := func(i *int) (string, error) {
		if *i+1 >= len(args) {
			return "", fmt.Errorf("pfctl: option %s requires an argument", args[*i])
		}
		*i++
		return args[*i], nil
	}
	for i := 0; i < len(args); i++ {
		var err error
		switch a := args[i]; {
		case a == "-a":
			p.anchor, err = value(&i)
		case a == "-t":
			p.table, err = value(&i)
		case a == "-T":
			p.tcmd, err = value(&i)
		case a == "-f":
			p.file, err = value(&i)
		case a == "-F":
			p.flush, err = value(&i)
		case a == "-X":
			p.release, err = value(&i)
		case a == "-k":
			var k string
			k, err = value(&i)
			p.kills = append(p.kills, k)
		case a == "-s":
			p.show, err = value(&i)
		case strings.HasPrefix(a, "-s") && len(a) > 2:
			p.show = a[2:]
		case a == "-v":
			p.verbose = true
		case a == "-E":
			p.enable = true
		case a == "-d":
			p.disable = true
		case strings.HasPrefix(a, "-"):
			return p, fmt.Errorf("pfctl: unknown option %s", a)
		default:
			p.rest = append(p.rest, a)
		}
		if err != nil {
			return p, err
		}
	}
	return p, nil
}

func stdout(s string) pfbackend.Output { return pfbackend.Output{Stdout: []byte(s)} }

func failure(msg string) (pfbackend.Output, error) {
	return pfbackend.Output{Stderr: []byte("pfctl: " + msg + "\n")}, errKernelExit
}

// Run implements pfbackend.Runner.
func (k *kernel) Run(_ context.Context, stdin []byte, args ...string) (pfbackend.Output, error) {
	k.calls = append(k.calls, slices.Clone(args))
	if k.fail != nil && k.fail(args) {
		return failure("injected failure")
	}
	p, err := parseArgs(args)
	if err != nil {
		return pfbackend.Output{Stderr: []byte(err.Error() + "\n")}, errKernelExit
	}
	switch {
	case p.enable:
		return k.enableRef()
	case p.disable:
		k.disables++
		k.enabled, k.refs = false, nil
		return pfbackend.Output{Stderr: []byte("pf disabled\n")}, nil
	case p.release != "":
		return k.releaseRef(p.release)
	case len(p.kills) > 0:
		return k.kill(p.kills)
	case p.tcmd != "":
		return k.tableCmd(p, stdin)
	case p.file != "":
		if p.file != "-" || p.anchor == "" {
			return failure("kernel model: only -a <anchor> -f - is modeled")
		}
		k.load(p.anchor, stdin)
		return pfbackend.Output{}, nil
	case p.flush != "":
		return k.flushCmd(p)
	case p.show != "":
		return k.showCmd(p)
	}
	return failure(fmt.Sprintf("kernel model: unmodeled command %q", strings.Join(args, " ")))
}

func (k *kernel) enableRef() (pfbackend.Output, error) {
	msg := "pf enabled\n"
	if k.enabled {
		msg = "pf already enabled\n"
	}
	k.enabled = true
	k.nextTok++
	tok := strconv.Itoa(7000000 + k.nextTok)
	k.refs = append(k.refs, tok)
	return pfbackend.Output{Stderr: []byte("No ALTQ support in kernel\nALTQ related functions disabled\n" + msg + "Token : " + tok + "\n")}, nil
}

// releaseRef answers as pfctl on macOS 27 does: "token invalid" for an
// unknown token while pf is enabled.
func (k *kernel) releaseRef(tok string) (pfbackend.Output, error) {
	if !k.enabled {
		return failure("pf not enabled")
	}
	i := slices.Index(k.refs, tok)
	if i < 0 {
		return failure("pf: token invalid")
	}
	k.refs = slices.Delete(k.refs, i, i+1)
	if len(k.refs) == 0 {
		k.enabled = false
		return pfbackend.Output{Stderr: []byte("pf disabled\n")}, nil
	}
	return pfbackend.Output{Stderr: []byte(strconv.Itoa(len(k.refs)) + " more pf enable reference(s) remaining, pf still enabled\n")}, nil
}

func (k *kernel) kill(hosts []string) (pfbackend.Output, error) {
	if len(hosts) != 2 {
		return failure("kernel model: only -k <src> -k <dst> is modeled")
	}
	src, err1 := netip.ParsePrefix(hosts[0])
	dst, err2 := netip.ParsePrefix(hosts[1])
	if err1 != nil || err2 != nil {
		return failure("illegal kill address")
	}
	_ = src // every modeled state has a source inside 0.0.0.0/0 or ::/0
	k.states = slices.DeleteFunc(k.states, func(a netip.Addr) bool {
		return dst.Contains(a) && src.Addr().Is4() == a.Is4()
	})
	return pfbackend.Output{}, nil
}

// load replaces the filter and the NAT rules of an anchor in one
// transaction. A table line creates its table when it is missing and
// keeps the entries of a present one. An anchor rule creates its
// sub-anchor.
func (k *kernel) load(anchor string, stdin []byte) {
	var rules, nat []string
	for line := range strings.Lines(string(stdin)) {
		line = strings.TrimSpace(line)
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
		case strings.HasPrefix(line, "table "):
			name := tableName(line)
			if k.tables[anchor] == nil {
				k.tables[anchor] = map[string]map[netip.Prefix]bool{}
			}
			if k.tables[anchor][name] == nil {
				k.tables[anchor][name] = map[netip.Prefix]bool{}
			}
		case strings.HasPrefix(line, "nat") || strings.HasPrefix(line, "binat") || strings.HasPrefix(line, "rdr"):
			nat = append(nat, line)
		default:
			rules = append(rules, line)
		}
	}
	k.rules[anchor] = rules
	k.nat[anchor] = nat
	for _, r := range rules {
		if sub, ok := anchorName(r); ok {
			if _, ok := k.rules[anchor+"/"+sub]; !ok {
				k.rules[anchor+"/"+sub] = nil
			}
		}
	}
}

func tableName(line string) string {
	rest := strings.TrimPrefix(line, "table <")
	name, _, _ := strings.Cut(rest, ">")
	return strings.Trim(name, `"`)
}

func anchorName(rule string) (string, bool) {
	rest, ok := strings.CutPrefix(rule, `anchor "`)
	if !ok {
		return "", false
	}
	name, _, ok := strings.Cut(rest, `"`)
	return name, ok
}

func (k *kernel) flushCmd(p pfctlArgs) (pfbackend.Output, error) {
	switch p.flush {
	case "rules":
		if p.anchor == "" {
			k.mainRules = nil
		} else {
			k.rules[p.anchor] = nil
		}
	case "nat":
		k.nat[p.anchor] = nil
	default:
		return failure("kernel model: unmodeled flush " + p.flush)
	}
	return pfbackend.Output{Stderr: []byte("rules cleared\n")}, nil
}

func (k *kernel) showCmd(p pfctlArgs) (pfbackend.Output, error) {
	switch p.show {
	case "info":
		status := "Disabled"
		if k.enabled {
			status = "Enabled"
		}
		return stdout("Status: " + status + " for 0 days 00:10:00           Debug: Urgent\n\nState Table                          Total             Rate\n  current entries                        " + strconv.Itoa(len(k.states)) + "\n"), nil
	case "r", "rules":
		if p.anchor == "" {
			return stdout(joinLines(k.mainRules)), nil
		}
		if base, ok := strings.CutSuffix(p.anchor, "/*"); ok {
			var b strings.Builder
			k.printTree(&b, base, "")
			return stdout(b.String()), nil
		}
		return stdout(joinLines(k.rules[p.anchor])), nil
	case "n", "nat":
		if p.anchor == "" {
			return stdout(joinLines(k.mainNat)), nil
		}
		return stdout(joinLines(k.nat[p.anchor])), nil
	case "A", "Anchors":
		return stdout(k.listAnchors(p.anchor, p.verbose)), nil
	case "T", "Tables":
		return stdout(joinLines(slices.Sorted(maps.Keys(k.tables[p.anchor])))), nil
	case "I", "Interfaces":
		return stdout(joinLines(k.ifaces)), nil
	case "s", "state", "states":
		return stdout(k.showStates()), nil
	}
	return failure("kernel model: unmodeled show " + p.show)
}

// showStates prints the states as "pfctl -s state" does on macOS 27. Each
// state has a local source and its destination.
func (k *kernel) showStates() string {
	var b strings.Builder
	for _, a := range k.states {
		if a.Is4() {
			b.WriteString("ALL udp 192.168.64.14:50000 -> " + a.String() + ":443       SINGLE:NO_TRAFFIC\n")
		} else {
			b.WriteString("ALL udp 2001:db8:ffff::14[50000] -> " + a.String() + "[443]       SINGLE:NO_TRAFFIC\n")
		}
	}
	return b.String()
}

func joinLines(ls []string) string {
	if len(ls) == 0 {
		return ""
	}
	return strings.Join(ls, "\n") + "\n"
}

func (k *kernel) printTree(b *strings.Builder, path, indent string) {
	for _, r := range k.rules[path] {
		sub, ok := anchorName(r)
		if !ok {
			b.WriteString(indent + r + "\n")
			continue
		}
		b.WriteString(indent + r + " {\n")
		k.printTree(b, path+"/"+sub, indent+"  ")
		b.WriteString(indent + "}\n")
	}
}

// listAnchors prints the children of an anchor, or with verbose all
// anchors below it, each as a full path after two spaces.
func (k *kernel) listAnchors(path string, all bool) string {
	var b strings.Builder
	prefix := path + "/"
	if path == "" {
		prefix = ""
	}
	for _, a := range slices.Sorted(maps.Keys(k.rules)) {
		sub, ok := strings.CutPrefix(a, prefix)
		if ok && sub != "" && (all || !strings.Contains(sub, "/")) {
			b.WriteString("  " + a + "\n")
		}
	}
	return b.String()
}

func (k *kernel) tableCmd(p pfctlArgs, stdin []byte) (pfbackend.Output, error) {
	t := k.tables[p.anchor][p.table]
	switch p.tcmd {
	case "show":
		if t == nil {
			return failure("Table does not exist.")
		}
		return stdout(showTable(t)), nil
	case "kill":
		if t == nil {
			return pfbackend.Output{Stderr: []byte("0 table deleted.\n")}, nil
		}
		delete(k.tables[p.anchor], p.table)
		return pfbackend.Output{Stderr: []byte("1 table deleted.\n")}, nil
	case "flush":
		if t == nil {
			return failure("Table does not exist.")
		}
		clear(t)
		return pfbackend.Output{}, nil
	case "add":
		return k.tableAdd(p, stdin)
	case "delete":
		return tableDelete(t, p, stdin)
	}
	return failure("kernel model: unmodeled table command " + p.tcmd)
}

// showTable prints a table as "pfctl -T show" does on macOS 27.
func showTable(t map[netip.Prefix]bool) string {
	var b strings.Builder
	for _, e := range slices.SortedFunc(maps.Keys(t), netip.Prefix.Compare) {
		mark := " "
		if t[e] {
			mark = "!"
		}
		b.WriteString("  " + mark + hostText(e) + "\n")
	}
	return b.String()
}

// tableDelete removes the entries that match in address and negation.
func tableDelete(t map[netip.Prefix]bool, p pfctlArgs, stdin []byte) (pfbackend.Output, error) {
	if t == nil {
		return failure("Table does not exist.")
	}
	es, err := entriesOf(p, stdin)
	if err != nil {
		return failure(err.Error())
	}
	for _, e := range es {
		if neg, ok := t[e.p]; ok && neg == e.neg {
			delete(t, e.p)
		}
	}
	return pfbackend.Output{}, nil
}

func (k *kernel) tableAdd(p pfctlArgs, stdin []byte) (pfbackend.Output, error) {
	es, err := entriesOf(p, stdin)
	if err != nil {
		return failure(err.Error())
	}
	if k.tables[p.anchor] == nil {
		k.tables[p.anchor] = map[string]map[netip.Prefix]bool{}
	}
	t := k.tables[p.anchor][p.table]
	if t == nil {
		t = map[netip.Prefix]bool{}
		k.tables[p.anchor][p.table] = t
	}
	var fb strings.Builder
	for _, e := range es {
		neg, ok := t[e.p]
		switch {
		case ok && neg != e.neg:
			fb.WriteString("Y  " + hostText(e.p) + "\n")
		case !ok:
			t[e.p] = e.neg
			fb.WriteString("A  " + hostText(e.p) + "\n")
		}
	}
	if !p.verbose {
		return pfbackend.Output{}, nil
	}
	return stdout(fb.String()), nil
}

type entry struct {
	p   netip.Prefix
	neg bool
}

func entriesOf(p pfctlArgs, stdin []byte) ([]entry, error) {
	words := slices.Clone(p.rest)
	if p.file == "-" {
		for line := range strings.Lines(string(stdin)) {
			words = append(words, strings.Fields(line)...)
		}
	}
	var es []entry
	for _, w := range words {
		text, neg := strings.CutPrefix(w, "!")
		pr, err := netip.ParsePrefix(text)
		if err != nil {
			a, aerr := netip.ParseAddr(text)
			if aerr != nil {
				return nil, fmt.Errorf("cannot parse %q", w)
			}
			pr = netip.PrefixFrom(a, a.BitLen())
		}
		es = append(es, entry{p: pr.Masked(), neg: neg})
	}
	return es, nil
}

func hostText(p netip.Prefix) string {
	if p.IsSingleIP() {
		return p.Addr().String()
	}
	return p.String()
}

// The helpers below change the kernel as another tool would.

func (k *kernel) entries(anchor, table string) []netip.Prefix {
	var out []netip.Prefix
	for e, neg := range k.tables[anchor][table] {
		if !neg {
			out = append(out, e)
		}
	}
	slices.SortFunc(out, netip.Prefix.Compare)
	return out
}

func (k *kernel) setEntries(anchor, table string, entries ...string) {
	if k.tables[anchor] == nil {
		k.tables[anchor] = map[string]map[netip.Prefix]bool{}
	}
	t := map[netip.Prefix]bool{}
	for _, s := range entries {
		text, neg := strings.CutPrefix(s, "!")
		t[netip.MustParsePrefix(text)] = neg
	}
	k.tables[anchor][table] = t
}

func (k *kernel) hasState(a string) bool {
	return slices.Contains(k.states, netip.MustParseAddr(a))
}

func (k *kernel) callsWith(words ...string) [][]string {
	var out [][]string
	for _, c := range k.calls {
		if !slices.ContainsFunc(words, func(w string) bool { return !slices.Contains(c, w) }) {
			out = append(out, c)
		}
	}
	return out
}
