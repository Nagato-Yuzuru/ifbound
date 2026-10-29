package pfrules

import (
	"flag"
	"fmt"
	"math/rand/v2"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
)

// This file is a property test of Compile. It builds random policies,
// inventories, and account snapshots, compiles them, and then reads the
// ruleset back with a small model of pf for the rule forms that Compile
// writes. The expected decision comes from the policy contract and its
// documented gaps alone.
//
// The pf model follows pf_test_rule and pf_test_fragment: the rules in
// order; a matching anchor rule sets its tag and does not decide; the
// first matching quick block decides; with no quick block, the decision
// of the rules before the ifbound anchor stands. pf finds a socket owner
// for TCP and UDP only, and a range of IDs never matches an unknown
// owner (pf_match_uid). pf does not tag fragments: a packet with "more
// fragments" set or a nonzero offset, the first fragment too, gets no tag
// and no owner check.
//
// Run more seeds with: go test ./internal/pfrules -run TestCompileProperties
// -args -pfrules.seeds=20000

var propSeeds = flag.Int("pfrules.seeds", 300, "number of random seeds of the compiler property test")

// The pools. "all" is a pf keyword. ghost and phantom are never in a
// snapshot. nobody has an ID that pf cannot take as a number; the packet
// IDs around that limit test the range.
var (
	ifacePool    = []string{"en0", "en1", "en7", "utun4", "utun5", "utun9", "bridge100", "gif0", "lo0", "ipsec0", "all"}
	selectorPool = []string{"en0", "en7", "utun4", "utun9", "gif0", "all", "utun*", "en?", "bridge[0-9]*", "ipsec*", "@tunnel", "@hardware"}
	classPool    = []policy.Class{0, policy.ClassHardware, policy.ClassTunnel}
	userIDs      = map[string]uint32{"root": 0, "daemon": 1, "_www": 70, "_buildbot": 299, "alias": 299, "nobody": 4294967294}
	groupIDs     = map[string]uint32{"wheel": 0, "daemon": 1, "staff": 20, "nobody": 4294967294}
	userPool     = []string{"root", "daemon", "_www", "_buildbot", "alias", "nobody", "ghost"}
	groupPool    = []string{"wheel", "daemon", "staff", "nobody", "phantom"}
	uidPool      = []uint32{0, 1, 70, 299, 501, 2147483646, 3000000000, 4294967294}
	gidPool      = []uint32{0, 1, 20, 2147483646, 3000000000, 4294967294}
)

type world struct {
	policies []policy.Policy
	ifaces   []reconcile.Interface
	// classes holds the classes that each interface in ifaces was built
	// with, so that the oracle does not read them back through the
	// reconcile.Interface code under test.
	classes  map[string]ifaceClasses
	accounts reconcile.Accounts
}

// ifaceClasses is the certain class of an interface, or the classes that
// it was built with by reconcile.Uncertain. possible can hold the zero
// Class, which is not a class.
type ifaceClasses struct {
	certain  policy.Class
	possible []policy.Class
}

func randomWorld(t testing.TB, r *rand.Rand) world {
	t.Helper()
	w := world{classes: map[string]ifaceClasses{}, accounts: reconcile.Accounts{Users: map[string]uint32{}, Groups: map[string]uint32{}}}
	for _, name := range ifacePool {
		if r.IntN(2) == 0 {
			i, c := randomInterface(r, name)
			w.ifaces = append(w.ifaces, i)
			w.classes[name] = c
		}
	}
	for name, id := range userIDs {
		if r.IntN(5) != 0 {
			w.accounts.Users[name] = id
		}
	}
	for name, id := range groupIDs {
		if r.IntN(5) != 0 {
			w.accounts.Groups[name] = id
		}
	}
	seen := map[policy.Name]bool{}
	for range r.IntN(6) {
		name := randomName(r)
		if seen[name] {
			continue
		}
		seen[name] = true
		w.policies = append(w.policies, policy.Policy{Name: name, Constraint: randomConstraint(t, r), Scope: randomScope(t, r)})
	}
	return w
}

// randomInterface returns an interface with a certain class, no class,
// or one or two possible classes, and the classes that it is built with.
func randomInterface(r *rand.Rand, name string) (reconcile.Interface, ifaceClasses) {
	if r.IntN(3) == 0 {
		possible := []policy.Class{classPool[r.IntN(len(classPool))], classPool[r.IntN(len(classPool))]}
		return reconcile.Uncertain(name, possible...), ifaceClasses{possible: possible}
	}
	c := classPool[r.IntN(len(classPool))]
	return reconcile.Interface{Name: name, Class: c}, ifaceClasses{certain: c}
}

func (w world) compile() (reconcile.Ruleset, error) {
	return Compiler{}.Compile(w.policies, w.ifaces, w.accounts)
}

// randomName returns a valid policy name of 1 to 24 bytes.
func randomName(r *rand.Rand) policy.Name {
	const first, rest = "abcdefghijklmnopqrstuvwxyz0123456789", "abcdefghijklmnopqrstuvwxyz0123456789_-"
	b := []byte{first[r.IntN(len(first))]}
	for range r.IntN(24) {
		b = append(b, rest[r.IntN(len(rest))])
	}
	return policy.Name(b)
}

func randomConstraint(t testing.TB, r *rand.Rand) policy.Constraint {
	t.Helper()
	var sels []policy.InterfaceSelector
	n := r.IntN(4)
	deny := r.IntN(2) == 0
	if deny {
		n++
	}
	for range n {
		s, err := policy.ParseInterfaceSelector(selectorPool[r.IntN(len(selectorPool))])
		if err != nil {
			t.Fatal(err)
		}
		sels = append(sels, s)
	}
	if !deny {
		return policy.NewOnlyVia(sels...)
	}
	c, err := policy.NewDenyVia(sels...)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func randomScope(t testing.TB, r *rand.Rand) policy.Scope {
	t.Helper()
	if r.IntN(3) != 0 {
		return policy.Scope{}
	}
	pick := func(pool []string) []policy.Account {
		var out []policy.Account
		for _, s := range pool {
			if r.IntN(4) == 0 {
				a, err := policy.ParseAccount(s)
				if err != nil {
					t.Fatal(err)
				}
				out = append(out, a)
			}
		}
		return out
	}
	users, groups := pick(userPool), pick(groupPool)
	if len(users)+len(groups) == 0 {
		return policy.Scope{}
	}
	s, err := policy.NewScope(users, groups)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// evalRule is one rule of a compiled ruleset, as the pf model reads it.
type evalRule struct {
	anchor    bool
	on        []string // nil: any interface
	table     string
	tag       string // anchor: the tag that the rule sets
	notTagged string // block: the rule does not match this tag; "" means no condition
	owner     string // block: "user", "group", or "" for any owner
	ids       []uint32
	above     bool // block: the owner list also holds the range "> maxID"
}

var (
	tableRE  = regexp.MustCompile(`^table <"([^"]+)"> persist$`)
	anchorRE = regexp.MustCompile(`^anchor "tag\.([^"]+)" out on \{ ((?:"[^"]+" )+)\} to <"([^"]+)"> tag "([^"]+)"$`)
	blockRE  = regexp.MustCompile(`^block return-icmp\(port-unr, port-unr\) out quick(?: on \{ ((?:"[^"]+" )+)\})? to <"([^"]+)">(?: ! tagged "([^"]+)")?(?: (user|group) \{ ((?:(?:\d+|> \d+) )+)\})?$`)
	quotedRE = regexp.MustCompile(`"([^"]+)"`)
)

func listItems(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, m := range quotedRE.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}
	return out
}

// idItems reads an owner list: IDs that pf takes as numbers, then at
// most one range "> maxID" at the end.
func idItems(t testing.TB, s string) ([]uint32, bool) {
	t.Helper()
	rest, above := strings.CutSuffix(s, "> "+strconv.Itoa(maxID)+" ")
	var out []uint32
	for f := range strings.FieldsSeq(rest) {
		id, err := strconv.ParseUint(f, 10, 32)
		if err != nil || id > maxID {
			t.Fatalf("owner list %q: %q is not a number that pf takes", s, f)
		}
		out = append(out, uint32(id))
	}
	return out, above
}

// readRuleset parses a compiled ruleset. Every line must have one of the
// three forms, so a pass rule, a stateful rule, or any other rule fails
// the test. It returns the declared tables and the rules in order.
func readRuleset(t testing.TB, text string) ([]string, []evalRule) {
	t.Helper()
	var tables []string
	var rules []evalRule
	for line := range strings.Lines(text) {
		line = strings.TrimSuffix(line, "\n")
		if m := tableRE.FindStringSubmatch(line); m != nil {
			if len(rules) > 0 {
				t.Fatalf("table after a rule: %q", line)
			}
			tables = append(tables, m[1])
			continue
		}
		if m := anchorRE.FindStringSubmatch(line); m != nil {
			if m[1] != m[3] {
				t.Fatalf("sub-anchor %q of table %q", m[1], m[3])
			}
			rules = append(rules, evalRule{anchor: true, on: listItems(m[2]), table: m[3], tag: m[4]})
			continue
		}
		if m := blockRE.FindStringSubmatch(line); m != nil {
			ids, above := idItems(t, m[5])
			rules = append(rules, evalRule{on: listItems(m[1]), table: m[2], notTagged: m[3], owner: m[4], ids: ids, above: above})
			continue
		}
		t.Fatalf("line has no known form: %q", line)
	}
	return tables, rules
}

type proto int

const (
	tcp proto = iota
	udp
	icmp
)

// packet is an outbound packet. Its destination is in the tables of
// inTable. A packet without a socket owner (VM NAT traffic) has owned
// false. fragment marks any fragment, the first one too. foreign is
// the decision of the rules before the ifbound anchor: true when another
// tool's non-quick rule blocks the packet so far.
type packet struct {
	iface    string
	inTable  map[string]bool
	proto    proto
	fragment bool
	owned    bool
	uid, gid uint32
	foreign  bool
}

// pfBlocks is the pf model: it reports whether pf blocks p.
func pfBlocks(rules []evalRule, p packet) bool {
	tag := "foreign.tag" // a tag that an earlier rule of another tool set
	for _, r := range rules {
		if !p.inTable[r.table] || r.on != nil && !slices.Contains(r.on, p.iface) {
			continue
		}
		if r.anchor {
			if !p.fragment {
				tag = r.tag
			}
			continue // the empty sub-anchor decides nothing
		}
		if (r.notTagged == "" || tag != r.notTagged) && pfOwnerMatches(r, p) {
			return true
		}
	}
	return p.foreign
}

// pfOwnerMatches is the owner part of a block rule in the pf model.
func pfOwnerMatches(r evalRule, p packet) bool {
	if p.fragment || r.owner == "" {
		return true
	}
	if !p.owned || p.proto != tcp && p.proto != udp {
		return false
	}
	id := p.gid
	if r.owner == "user" {
		id = p.uid
	}
	return slices.Contains(r.ids, id) || r.above && id > maxID
}

// wantBlocks is the policy contract with its documented gaps:
//
//   - An earlier block of another tool holds.
//   - A packet is blocked when a policy whose table holds the destination
//     and whose scope holds the owner does not allow the interface.
//   - A glob or a class selects only the interfaces in the inventory.
//   - A deny_via class also selects the interfaces that can have it; an
//     only_via class selects only the interfaces that have it for certain.
//   - A scope with an unknown name is dropped.
//   - An ID above the pf number limit stands for every ID above it.
//   - A scope holds only TCP and UDP packets with a socket owner.
//   - A fragment ignores the scope, and only_via blocks it everywhere.
func wantBlocks(w world, p packet) bool {
	if p.foreign {
		return true
	}
	for _, pol := range w.policies {
		if !p.inTable[string(pol.Name)] {
			continue
		}
		_, only := pol.Constraint.(policy.OnlyVia)
		var hit bool
		for _, s := range pol.Constraint.Selectors() {
			hit = hit || selects(s, p.iface, w.classes, !only)
		}
		if p.fragment {
			if only || hit {
				return true
			}
			continue
		}
		if !inScope(w.accounts, pol.Scope, p) {
			continue
		}
		if only != hit {
			return true
		}
	}
	return false
}

func inScope(acc reconcile.Accounts, s policy.Scope, p packet) bool {
	if !s.Limited() {
		return true
	}
	uids, uok := resolveIDs(s.Users(), acc.Users)
	gids, gok := resolveIDs(s.Groups(), acc.Groups)
	if !uok || !gok {
		return true // dropped scope
	}
	if !p.owned || p.proto != tcp && p.proto != udp {
		return false
	}
	return holds(uids, p.uid) || holds(gids, p.gid)
}

// holds reports whether ids hold id. An ID above 2^31 - 2 holds every
// ID above that limit.
func holds(ids []uint32, id uint32) bool {
	const limit = 1<<31 - 2
	return slices.ContainsFunc(ids, func(x uint32) bool { return x == id || x > limit && id > limit })
}

func resolveIDs(as []policy.Account, ids map[string]uint32) ([]uint32, bool) {
	var out []uint32
	for _, a := range as {
		id, ok := ids[a.String()]
		if !ok {
			return nil, false
		}
		out = append(out, id)
	}
	return out, true
}

// selects reports whether s selects iface in the inventory inv. deny
// tells that s is a selector of deny_via.
func selects(s policy.InterfaceSelector, iface string, inv map[string]ifaceClasses, deny bool) bool {
	c, inInventory := inv[iface]
	switch s := s.(type) {
	case policy.InterfaceName:
		return s.Name() == iface
	case policy.InterfaceGlob:
		ok, _ := path.Match(s.Pattern(), iface) //nolint:errcheck // a bad pattern gives ok=false, which selects nothing
		return ok && inInventory
	case policy.InterfaceClass:
		return inInventory && (c.certain == s.Class() || deny && slices.Contains(c.possible, s.Class()))
	default:
		panic(fmt.Sprintf("unknown selector %T", s))
	}
}

func randomPacket(r *rand.Rand, w world) packet {
	p := packet{
		iface:    "new0",
		inTable:  map[string]bool{},
		proto:    proto(r.IntN(3)),
		fragment: r.IntN(8) == 0,
		owned:    r.IntN(4) != 0,
		uid:      uidPool[r.IntN(len(uidPool))],
		gid:      gidPool[r.IntN(len(gidPool))],
		foreign:  r.IntN(10) == 0,
	}
	if i := r.IntN(len(ifacePool) + 1); i < len(ifacePool) {
		p.iface = ifacePool[i]
	}
	for _, pol := range w.policies {
		if r.IntN(2) == 0 {
			p.inTable[string(pol.Name)] = true
		}
	}
	return p
}

func TestCompileProperties(t *testing.T) {
	for seed := range *propSeeds {
		r := rand.New(rand.NewPCG(uint64(seed), 0x5eed))
		w := randomWorld(t, r)
		rs, err := w.compile()
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		text := string(rs.Body())
		checkDeterministic(t, seed, r, w, rs)
		tables, rules := readRuleset(t, text)
		checkStructure(t, seed, w, rs, tables, rules)
		for range 300 {
			p := randomPacket(r, w)
			if got, want := pfBlocks(rules, p), wantBlocks(w, p); got != want {
				t.Fatalf("seed %d: packet %+v: blocked = %v, want %v\nruleset:\n%s", seed, p, got, want, text)
			}
		}
	}
}

// checkDeterministic compiles shuffled copies of the input: every order
// must give the same ruleset.
func checkDeterministic(t *testing.T, seed int, r *rand.Rand, w world, want reconcile.Ruleset) {
	t.Helper()
	shuffled := world{policies: slices.Clone(w.policies), ifaces: slices.Clone(w.ifaces), accounts: w.accounts}
	r.Shuffle(len(shuffled.policies), func(i, j int) {
		shuffled.policies[i], shuffled.policies[j] = shuffled.policies[j], shuffled.policies[i]
	})
	r.Shuffle(len(shuffled.ifaces), func(i, j int) { shuffled.ifaces[i], shuffled.ifaces[j] = shuffled.ifaces[j], shuffled.ifaces[i] })
	got, err := shuffled.compile()
	if err != nil {
		t.Fatalf("seed %d: shuffled input: %v", seed, err)
	}
	if got.ID() != want.ID() || string(got.Body()) != string(want.Body()) || !slices.Equal(got.Problems(), want.Problems()) {
		t.Fatalf("seed %d: shuffled input changes the ruleset:\n%s\nwant:\n%s", seed, got.Body(), want.Body())
	}
	if want.ID() != reconcile.NewRuleset(want.Body()).ID() {
		t.Fatalf("seed %d: ID is not the digest of the text", seed)
	}
}

// checkStructure checks that each policy has its table and its rules,
// that names stay within the pf limits, that each anchor rule is
// followed by the block rules that test its tag before any other tag,
// and that each dropped scope is reported once.
func checkStructure(t *testing.T, seed int, w world, rs reconcile.Ruleset, tables []string, rules []evalRule) {
	t.Helper()
	want := make([]string, len(w.policies))
	for i, p := range w.policies {
		want[i] = string(p.Name)
	}
	slices.Sort(want)
	if !slices.Equal(tables, want) {
		t.Fatalf("seed %d: tables %v, want one per policy %v", seed, tables, want)
	}
	for i, r := range rules {
		if !slices.Contains(tables, r.table) || len(r.table) > maxTableName {
			t.Fatalf("seed %d: rule %d uses table %q", seed, i, r.table)
		}
		if tag := r.tag + r.notTagged; tag != "" && (tag != tagPrefix+r.table || len(tag) > maxTagName) {
			t.Fatalf("seed %d: rule %d of table %q uses tag %q", seed, i, r.table, tag)
		}
		if r.anchor && (i+1 == len(rules) || rules[i+1].notTagged != r.tag) {
			t.Fatalf("seed %d: anchor rule %d is not followed by its block rule", seed, i)
		}
	}
	for _, p := range w.policies {
		blocks := slices.ContainsFunc(rules, func(r evalRule) bool { return !r.anchor && r.table == string(p.Name) })
		if _, deny := p.Constraint.(policy.DenyVia); !blocks && !deny {
			t.Fatalf("seed %d: only_via policy %q has no block rule", seed, p.Name)
		}
	}
	checkProblems(t, seed, w, rs)
}

// checkProblems checks that each dropped scope is reported once, and
// that no report voids the enforcement.
func checkProblems(t *testing.T, seed int, w world, rs reconcile.Ruleset) {
	t.Helper()
	var dropped int
	for _, p := range w.policies {
		_, uok := resolveIDs(p.Scope.Users(), w.accounts.Users)
		_, gok := resolveIDs(p.Scope.Groups(), w.accounts.Groups)
		if !uok || !gok {
			dropped++
		}
	}
	if got := len(rs.Problems()); got != dropped {
		t.Fatalf("seed %d: %d problems, want one per dropped scope: %d", seed, got, dropped)
	}
	for _, p := range rs.Problems() {
		if p.Voids {
			t.Fatalf("seed %d: a dropped scope voids nothing: %+v", seed, p)
		}
	}
}
