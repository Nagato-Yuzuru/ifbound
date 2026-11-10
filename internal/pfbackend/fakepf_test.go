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
	"time"

	"github.com/Nagato-Yuzuru/ifbound/pf"
)

var errExit = errors.New("exit status 1")

// fakePF is a Runner and a Device that models the part of pf that the
// Backend uses. It prints in the formats that pfctl prints on macOS 27
// (see parse_test.go for the captured outputs). It keeps the rules of a
// load as they are: the real kernel rewrites them, but the Backend reads
// only the sentinel label and the indentation.
type fakePF struct {
	enabled bool
	tokens  []string
	// born holds the creation time of each token in whole seconds, and
	// owner the pid of the process that took it. free holds the released
	// values, which pf gives again, last released first.
	born  map[string]time.Time
	owner map[string]int
	free  []string
	now   func() time.Time
	next  int
	// pid is the pid of ifboundd, the process that calls the Device.
	// Each "-E" runs in a new pfctl process with a new pid.
	pid     int
	nextPID int
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
	// fail makes each call whose arguments it accepts fail. An ioctl call
	// has its name as its first argument, for example "DIOCGETSTATUS",
	// and the token after "DIOCSTOPREF".
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
		born:   make(map[string]time.Time),
		owner:  make(map[string]int),
		now:    time.Now,
		pid:    4100,
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

var _ Device = (*fakePF)(nil)

// Status implements Device.
func (f *fakePF) Status() (pf.Status, error) {
	if err := f.ioctl("DIOCGETSTATUS"); err != nil {
		return pf.Status{}, err
	}
	return pf.Status{Running: f.enabled}, nil
}

// StartRef implements Device.
func (f *fakePF) StartRef() (uint64, error) {
	if err := f.ioctl("DIOCSTARTREF"); err != nil {
		return 0, err
	}
	return strconv.ParseUint(f.take(f.pid), 10, 64)
}

// StopRef implements Device. As pf.Handle does, it answers
// pf.ErrNotFound for an unknown token and on a disabled pf.
func (f *fakePF) StopRef(token uint64) error {
	if err := f.ioctl("DIOCSTOPREF", strconv.FormatUint(token, 10)); err != nil {
		return err
	}
	if !f.drop(strconv.FormatUint(token, 10)) {
		return fmt.Errorf("giving back reference %d: %w", token, pf.ErrNotFound)
	}
	return nil
}

// Refs implements Device, newest reference first.
func (f *fakePF) Refs() ([]pf.Ref, error) {
	if err := f.ioctl("DIOCGETSTARTERS"); err != nil {
		return nil, err
	}
	var refs []pf.Ref
	for _, tok := range slices.Backward(f.tokens) {
		v, err := strconv.ParseUint(tok, 10, 64)
		if err != nil {
			return nil, err
		}
		proc := "pfctl"
		if f.owner[tok] == f.pid {
			proc = "ifboundd"
		}
		refs = append(refs, pf.Ref{Token: v, Created: f.born[tok], PID: f.owner[tok], Process: proc})
	}
	return refs, nil
}

// take takes a reference for the process pid and enables pf.
func (f *fakePF) take(pid int) string {
	f.enabled = true
	var tok string
	if n := len(f.free); n > 0 {
		tok, f.free = f.free[n-1], f.free[:n-1]
	} else {
		f.next++
		tok = strconv.Itoa(1000 + f.next)
	}
	f.tokens = append(f.tokens, tok)
	f.born[tok] = time.Unix(f.now().Unix(), 0)
	f.owner[tok] = pid
	return tok
}

// drop gives back a reference and reports whether pf held it.
func (f *fakePF) drop(tok string) bool {
	i := slices.Index(f.tokens, tok)
	if !f.enabled || i < 0 {
		return false
	}
	f.tokens = slices.Delete(f.tokens, i, i+1)
	f.free = append(f.free, tok)
	f.enabled = len(f.tokens) > 0
	return true
}

// ioctl records an ioctl call with its arguments, and reports whether
// fail refuses it.
func (f *fakePF) ioctl(name string, args ...string) error {
	call := append([]string{name}, args...)
	f.calls = append(f.calls, call)
	if f.fail != nil && f.fail(call) {
		return fmt.Errorf("%s: injected failure", name)
	}
	return nil
}

// Rules implements Device.
func (f *fakePF) Rules(rs pf.Ruleset) ([]pf.Rule, error) {
	if err := f.ioctl("DIOCGETRULES", rs.Anchor, rs.Kind.String()); err != nil {
		return nil, err
	}
	lines := slices.Concat(f.main, f.nat[""])
	if rs.Anchor != "" {
		if !f.exists(rs.Anchor) {
			return nil, fmt.Errorf("anchor %s: %w", rs.Anchor, pf.ErrNotFound)
		}
		lines = slices.Concat(f.anchors[rs.Anchor], f.nat[rs.Anchor])
	}
	return rulesOf(lines, rs.Kind), nil
}

// Anchors implements Device.
func (f *fakePF) Anchors(anchor string) ([]string, error) {
	if err := f.ioctl("DIOCGETRULESETS", anchor); err != nil {
		return nil, err
	}
	if anchor != "" && !f.exists(anchor) {
		return nil, fmt.Errorf("anchor %s: %w", anchor, pf.ErrNotFound)
	}
	return children(slices.Collect(maps.Keys(f.anchors)), anchor), nil
}

// exists reports whether pf holds the anchor: it has rules, or an anchor
// below it does.
func (f *fakePF) exists(anchor string) bool {
	if _, ok := f.anchors[anchor]; ok {
		return true
	}
	return len(children(slices.Collect(maps.Keys(f.anchors)), anchor)) > 0
}

// tableOf returns the table t. The fake keeps tables only in the anchor.
func (f *fakePF) tableOf(t pf.Table) (map[netip.Prefix]bool, error) {
	if t.Anchor != Anchor {
		return nil, fmt.Errorf("fakePF: table in anchor %s", t.Anchor)
	}
	tbl, ok := f.tables[t.Name]
	if !ok {
		return nil, fmt.Errorf("table %s: %w", t, pf.ErrNotFound)
	}
	return tbl, nil
}

// CreateTable implements Device.
func (f *fakePF) CreateTable(t pf.Table) error {
	if err := f.ioctl("DIOCRADDTABLES", t.Anchor, t.Name); err != nil {
		return err
	}
	if t.Anchor != Anchor {
		return fmt.Errorf("fakePF: table in anchor %s", t.Anchor)
	}
	if f.tables[t.Name] == nil {
		f.tables[t.Name] = make(map[netip.Prefix]bool)
	}
	return nil
}

// AddAddrs implements Device.
func (f *fakePF) AddAddrs(t pf.Table, addrs []pf.Addr) ([]pf.Feedback, error) {
	if err := f.ioctl("DIOCRADDADDRS", addrArgs(t, addrs)...); err != nil {
		return nil, err
	}
	tbl, err := f.tableOf(t)
	if err != nil {
		return nil, err
	}
	return addAddrs(tbl, addrs), nil
}

// DeleteAddrs implements Device. With stickyNegation it keeps negated
// entries.
func (f *fakePF) DeleteAddrs(t pf.Table, addrs []pf.Addr) ([]pf.Feedback, error) {
	if err := f.ioctl("DIOCRDELADDRS", addrArgs(t, addrs)...); err != nil {
		return nil, err
	}
	tbl, err := f.tableOf(t)
	if err != nil {
		return nil, err
	}
	keep := func(a pf.Addr) bool { return a.Negated && f.stickyNegation }
	return deleteAddrs(tbl, addrs, keep), nil
}

// Addrs implements Device.
func (f *fakePF) Addrs(t pf.Table) ([]pf.Addr, error) {
	if err := f.ioctl("DIOCRGETADDRS", t.Anchor, t.Name); err != nil {
		return nil, err
	}
	tbl, err := f.tableOf(t)
	if err != nil {
		return nil, err
	}
	return addrsOf(tbl), nil
}

// KillStates implements Device.
func (f *fakePF) KillStates(dst netip.Prefix) error {
	if err := f.ioctl("DIOCKILLSTATES", dst.String()); err != nil {
		return err
	}
	for d := range f.states {
		if dst.Contains(d) {
			delete(f.states, d)
		}
	}
	return nil
}

func (f *fakePF) run(stdin []byte, args []string) (Output, error) {
	a := strings.Join(args, " ")
	switch {
	case a == "-E":
		f.nextPID++
		tok := f.take(700 + f.nextPID)
		return Output{Stderr: []byte("No ALTQ support in kernel\nALTQ related functions disabled\npf enabled\nToken : " + tok + "\n")}, nil
	case len(args) == 2 && args[0] == "-X":
		switch {
		case !f.enabled:
			return Output{Stderr: []byte("pfctl: pf not enabled\n")}, errExit
		case !f.drop(args[1]):
			return Output{Stderr: []byte("pfctl: pf: token invalid\n")}, errExit
		}
		return Output{}, nil
	case a == "-sr":
		return out(strings.Join(f.main, "\n") + "\n"), nil
	case a == "-sn":
		return out(strings.Join(f.nat[""], "\n") + "\n"), nil
	case a == "-sA -v":
		return out(f.listAnchors("", true)), nil
	case a == "-sI -v":
		return out(strings.Join(f.ifaces, "\n") + "\n"), nil
	case len(args) >= 2 && args[0] == "-a":
		return f.anchor(args[1], args[2:], stdin)
	}
	return Output{}, fmt.Errorf("fakePF: unknown command %q", a)
}

func (f *fakePF) anchor(path string, rest []string, stdin []byte) (Output, error) {
	r := strings.Join(rest, " ")
	switch {
	case r == "-sr":
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
	case r == "-F Tables":
		clear(f.tables)
		return Output{}, nil
	case r == "-sT":
		return out(strings.Join(slices.Sorted(maps.Keys(f.tables)), "\n") + "\n"), nil
	case len(rest) >= 4 && rest[0] == "-t" && rest[2] == "-T":
		return f.table(path, rest[1], rest[3], stdin)
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
		if name, _, ok := anchorRule(rule); ok {
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

func (f *fakePF) table(anchor, name, cmd string, stdin []byte) (Output, error) {
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
