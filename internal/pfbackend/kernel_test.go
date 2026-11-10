package pfbackend_test

// This file holds a model of the pf kernel, of the pfctl command line,
// and of the ioctl calls on /dev/pf, for the tests of the public methods. It is independent of
// fakepf_test.go: it parses pfctl flags in any order, keeps references
// as the macOS kernel does, keeps NAT rules apart from filter rules, and
// refuses each flag that it does not know, so an unexpected pfctl call
// fails the test.

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/pfbackend"
	"github.com/Nagato-Yuzuru/ifbound/pf"
)

var errKernelExit = errors.New("exit status 1")

// kernel is the model of pf. Its state outlives a Backend, as the real
// kernel state outlives ifboundd.
type kernel struct {
	enabled bool
	// refs holds the reference tokens, oldest first. born holds the time
	// when each one was taken, in whole seconds as the kernel keeps it,
	// and owner the pid of the process that took it. pf gives a released
	// value again, also to another process: free holds the released
	// values, and the next reference takes the last one.
	refs    []string
	born    map[string]time.Time
	owner   map[string]int
	free    []string
	now     func() time.Time
	nextTok int
	// pid is the pid of ifboundd, the process that calls the Device.
	// Each "pfctl -E" runs in a new pfctl process with a new pid.
	pid     int
	nextPID int
	// mainRules and mainNat are the filter and the NAT rules of the main
	// ruleset. An anchor rule keeps its call as the rule was loaded; pfctl
	// prints it as pf_anchor_copyout gives it (see printed).
	mainRules []string
	mainNat   []string
	// rules and nat map an anchor path to its filter and NAT rules. A key
	// with a nil value is an anchor that exists and has no rule.
	rules map[string][]string
	nat   map[string][]string
	// tables maps an anchor path and a table name to the entries; the
	// value is true for a negated entry.
	tables map[string]map[string]map[netip.Prefix]bool
	// anchorMatch is the match flag of each anchor (struct pf_anchor,
	// match). pf keeps it across packets.
	anchorMatch map[string]bool
	// states holds the destination of each state.
	states []netip.Addr
	// ifaces are the lines of "pfctl -sI -v".
	ifaces []string
	// uplink is the interface of the route that the routing table gives
	// for each destination, where fastroute sends a packet.
	uplink string

	// fail makes a call fail when it returns true.
	fail func(args []string) bool
	// calls records the arguments of every pfctl call, and the name of
	// every ioctl call (for example "DIOCGETSTATUS"), with the token after
	// "DIOCSTOPREF".
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
		nat:         map[string][]string{},
		tables:      map[string]map[string]map[netip.Prefix]bool{},
		anchorMatch: map[string]bool{},
		born:        map[string]time.Time{},
		owner:       map[string]int{},
		now:         time.Now,
		pid:         4242,
		ifaces:      []string{"ALL", "en0", "lo0", "utun4"},
		uplink:      "en0",
	}
}

// pfctlArgs is a parsed pfctl command line.
type pfctlArgs struct {
	anchor, table, tcmd, show, file, flush, release string
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

// ioctl records an ioctl call with its arguments, and reports whether
// fail refuses it.
func (k *kernel) ioctl(name string, args ...string) error {
	call := append([]string{name}, args...)
	k.calls = append(k.calls, call)
	if k.fail != nil && k.fail(call) {
		return fmt.Errorf("%s: injected failure", name)
	}
	return nil
}

// exists reports whether pf holds the anchor.
func (k *kernel) exists(anchor string) bool {
	if _, ok := k.rules[anchor]; ok {
		return true
	}
	return len(pfbackend.Children(slices.Collect(maps.Keys(k.rules)), anchor)) > 0
}

// Rules implements pfbackend.Device.
func (k *kernel) Rules(rs pf.Ruleset) ([]pf.Rule, error) {
	if err := k.ioctl("DIOCGETRULES", rs.Anchor, rs.Kind.String()); err != nil {
		return nil, err
	}
	lines := slices.Concat(k.printed(""), k.mainNat)
	if rs.Anchor != "" {
		if !k.exists(rs.Anchor) {
			return nil, fmt.Errorf("anchor %s: %w", rs.Anchor, pf.ErrNotFound)
		}
		lines = slices.Concat(k.printed(rs.Anchor), k.nat[rs.Anchor])
	}
	return pfbackend.RulesOf(lines, rs.Kind), nil
}

// Anchors implements pfbackend.Device.
func (k *kernel) Anchors(anchor string) ([]string, error) {
	if err := k.ioctl("DIOCGETRULESETS", anchor); err != nil {
		return nil, err
	}
	if anchor != "" && !k.exists(anchor) {
		return nil, fmt.Errorf("anchor %s: %w", anchor, pf.ErrNotFound)
	}
	return pfbackend.Children(slices.Collect(maps.Keys(k.rules)), anchor), nil
}

func (k *kernel) tableOf(t pf.Table) (map[netip.Prefix]bool, error) {
	tbl := k.tables[t.Anchor][t.Name]
	if tbl == nil {
		return nil, fmt.Errorf("table %s: %w", t, pf.ErrNotFound)
	}
	return tbl, nil
}

// CreateTable implements pfbackend.Device.
func (k *kernel) CreateTable(t pf.Table) error {
	if err := k.ioctl("DIOCRADDTABLES", t.Anchor, t.Name); err != nil {
		return err
	}
	if k.tables[t.Anchor] == nil {
		k.tables[t.Anchor] = map[string]map[netip.Prefix]bool{}
	}
	if k.tables[t.Anchor][t.Name] == nil {
		k.tables[t.Anchor][t.Name] = map[netip.Prefix]bool{}
	}
	return nil
}

// AddAddrs implements pfbackend.Device.
func (k *kernel) AddAddrs(t pf.Table, addrs []pf.Addr) ([]pf.Feedback, error) {
	if err := k.ioctl("DIOCRADDADDRS", pfbackend.AddrArgs(t, addrs)...); err != nil {
		return nil, err
	}
	tbl, err := k.tableOf(t)
	if err != nil {
		return nil, err
	}
	return pfbackend.AddAddrs(tbl, addrs), nil
}

// DeleteAddrs implements pfbackend.Device.
func (k *kernel) DeleteAddrs(t pf.Table, addrs []pf.Addr) ([]pf.Feedback, error) {
	if err := k.ioctl("DIOCRDELADDRS", pfbackend.AddrArgs(t, addrs)...); err != nil {
		return nil, err
	}
	tbl, err := k.tableOf(t)
	if err != nil {
		return nil, err
	}
	return pfbackend.DelAddrs(tbl, addrs, nil), nil
}

// Addrs implements pfbackend.Device.
func (k *kernel) Addrs(t pf.Table) ([]pf.Addr, error) {
	if err := k.ioctl("DIOCRGETADDRS", t.Anchor, t.Name); err != nil {
		return nil, err
	}
	tbl, err := k.tableOf(t)
	if err != nil {
		return nil, err
	}
	return pfbackend.AddrsOf(tbl), nil
}

// KillStates implements pfbackend.Device.
func (k *kernel) KillStates(dst netip.Prefix) error {
	if err := k.ioctl("DIOCKILLSTATES", dst.String()); err != nil {
		return err
	}
	k.states = slices.DeleteFunc(k.states, dst.Contains)
	return nil
}

var _ pfbackend.Device = (*kernel)(nil)

// Status implements pfbackend.Device.
func (k *kernel) Status() (pf.Status, error) {
	if err := k.ioctl("DIOCGETSTATUS"); err != nil {
		return pf.Status{}, err
	}
	return pf.Status{Running: k.enabled}, nil
}

// StartRef implements pfbackend.Device.
func (k *kernel) StartRef() (uint64, error) {
	if err := k.ioctl("DIOCSTARTREF"); err != nil {
		return 0, err
	}
	return strconv.ParseUint(k.take(k.pid), 10, 64)
}

// StopRef implements pfbackend.Device. As pf.Handle does, it answers
// pf.ErrNotFound for an unknown token and on a disabled pf.
func (k *kernel) StopRef(token uint64) error {
	if err := k.ioctl("DIOCSTOPREF", strconv.FormatUint(token, 10)); err != nil {
		return err
	}
	if !k.drop(strconv.FormatUint(token, 10)) {
		return fmt.Errorf("giving back reference %d: %w", token, pf.ErrNotFound)
	}
	return nil
}

// Refs implements pfbackend.Device. The kernel lists the newest
// reference first.
func (k *kernel) Refs() ([]pf.Ref, error) {
	if err := k.ioctl("DIOCGETSTARTERS"); err != nil {
		return nil, err
	}
	var refs []pf.Ref
	for _, tok := range slices.Backward(k.refs) {
		v, err := strconv.ParseUint(tok, 10, 64)
		if err != nil {
			return nil, err
		}
		proc := "pfctl"
		if k.owner[tok] == k.pid {
			proc = "ifboundd"
		}
		refs = append(refs, pf.Ref{Token: v, Created: k.born[tok], PID: k.owner[tok], Process: proc})
	}
	return refs, nil
}

// take takes a reference for the process pid and enables pf.
func (k *kernel) take(pid int) string {
	k.enabled = true
	var tok string
	if n := len(k.free); n > 0 {
		tok, k.free = k.free[n-1], k.free[:n-1]
	} else {
		k.nextTok++
		tok = strconv.Itoa(7000000 + k.nextTok)
	}
	k.refs = append(k.refs, tok)
	k.born[tok] = time.Unix(k.now().Unix(), 0)
	k.owner[tok] = pid
	return tok
}

// drop gives back a reference and reports whether pf held it. pf stops
// with its last reference.
func (k *kernel) drop(tok string) bool {
	i := slices.Index(k.refs, tok)
	if !k.enabled || i < 0 {
		return false
	}
	k.refs = slices.Delete(k.refs, i, i+1)
	k.free = append(k.free, tok)
	k.enabled = len(k.refs) > 0
	return true
}

// enableRef is "pfctl -E" of another tool, in a new pfctl process.
func (k *kernel) enableRef() (pfbackend.Output, error) {
	msg := "pf enabled\n"
	if k.enabled {
		msg = "pf already enabled\n"
	}
	k.nextPID++
	tok := k.take(800 + k.nextPID)
	return pfbackend.Output{Stderr: []byte("No ALTQ support in kernel\nALTQ related functions disabled\n" + msg + "Token : " + tok + "\n")}, nil
}

// releaseRef is "pfctl -X" of another tool. It answers as pfctl on macOS
// 27 does: "token invalid" for an unknown token while pf is enabled.
func (k *kernel) releaseRef(tok string) (pfbackend.Output, error) {
	if !k.enabled {
		return failure("pf not enabled")
	}
	if !k.drop(tok) {
		return failure("pf: token invalid")
	}
	if len(k.refs) == 0 {
		return pfbackend.Output{Stderr: []byte("pf disabled\n")}, nil
	}
	return pfbackend.Output{Stderr: []byte(strconv.Itoa(len(k.refs)) + " more pf enable reference(s) remaining, pf still enabled\n")}, nil
}

// load replaces the filter and the NAT rules of an anchor in one
// transaction. A table line creates its table when it is missing and
// keeps the entries of a present one. An anchor rule creates the anchor
// that it calls (pf_anchor_setup).
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
		if _, c, ok := callOf(anchor, r); ok {
			if _, ok := k.rules[c.path]; !ok {
				k.rules[c.path] = nil
			}
		}
	}
}

func tableName(line string) string {
	rest := strings.TrimPrefix(line, "table <")
	name, _, _ := strings.Cut(rest, ">")
	return strings.Trim(name, `"`)
}

// callOf returns the call name of an anchor rule in the ruleset from, as
// the rule was loaded, and the call as pf keeps it.
func callOf(from, rule string) (string, anchorCall, bool) {
	rest, ok := strings.CutPrefix(rule, `anchor "`)
	if !ok {
		return "", anchorCall{}, false
	}
	name, _, ok := strings.Cut(rest, `"`)
	if !ok {
		return "", anchorCall{}, false
	}
	c, ok := setup(from, name)
	return name, c, ok
}

// anchorCall is the call of an anchor rule as pf keeps it
// (pf_anchor_setup): the anchor, 0 for an absolute call or 1 plus the
// number of "../" for a relative call (anchor_relative), and the wildcard
// flag.
type anchorCall struct {
	path     string
	relative int
	wildcard bool
}

// setup reads the call name of an anchor rule in the ruleset from, as
// pf_anchor_setup in pf_ruleset.c does. ok is false when "../" goes
// above the main ruleset.
func setup(from, name string) (c anchorCall, ok bool) {
	if abs, ok := strings.CutPrefix(name, "/"); ok {
		c.path = abs
	} else {
		c.relative, c.path = 1, from
		for {
			rest, ok := strings.CutPrefix(name, "../")
			if !ok {
				break
			}
			if c.path == "" {
				return c, false
			}
			c.path = c.path[:max(strings.LastIndex(c.path, "/"), 0)]
			c.relative++
			name = rest
		}
		if c.path != "" {
			c.path += "/"
		}
		c.path += name
	}
	c.path, c.wildcard = strings.CutSuffix(c.path, "/*")
	return c, true
}

// copyout returns the call of an anchor rule in the ruleset from, as
// pf_anchor_copyout in pf_ruleset.c gives it to pfctl.
func (c anchorCall) copyout(from string) string {
	var call string
	if c.relative == 0 {
		call = "/" + c.path
	} else {
		a := from
		for range c.relative - 1 {
			a = a[:max(strings.LastIndex(a, "/"), 0)]
			call += "../"
		}
		switch {
		case len(c.path) <= len(a):
		case a == "":
			call += c.path
		default:
			call += c.path[len(a)+1:]
		}
	}
	if c.wildcard {
		if call == "" {
			return "*"
		}
		call += "/*"
	}
	return call
}

// printed returns the filter rules of a ruleset as pfctl prints them;
// "" is the main ruleset. An anchor rule shows the call that
// pf_anchor_copyout gives, which can differ from the loaded text: pfctl
// prints "../*" as "..//*".
func (k *kernel) printed(path string) []string {
	lines := k.mainRules
	if path != "" {
		lines = k.rules[path]
	}
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = l
		if name, c, ok := callOf(path, l); ok {
			out[i] = `anchor "` + c.copyout(path) + `"` + strings.TrimPrefix(l, `anchor "`+name+`"`)
		}
	}
	return out
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
	case "Tables":
		n := len(k.tables[p.anchor])
		delete(k.tables, p.anchor)
		return pfbackend.Output{Stderr: []byte(strconv.Itoa(n) + " tables deleted.\n")}, nil
	default:
		return failure("kernel model: unmodeled flush " + p.flush)
	}
	return pfbackend.Output{Stderr: []byte("rules cleared\n")}, nil
}

func (k *kernel) showCmd(p pfctlArgs) (pfbackend.Output, error) {
	switch p.show {
	case "r", "rules":
		// pf_find_ruleset finds no ruleset, and DIOCGETRULES fails.
		if p.anchor != "" && !k.exists(p.anchor) {
			return failure("DIOCGETRULES: Invalid argument")
		}
		return stdout(joinLines(k.printed(p.anchor))), nil
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
	}
	return failure("kernel model: unmodeled show " + p.show)
}

func joinLines(ls []string) string {
	if len(ls) == 0 {
		return ""
	}
	return strings.Join(ls, "\n") + "\n"
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
