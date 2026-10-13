package pfrules

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
)

// hostIfaces is the inventory of the golden tests.
var hostIfaces = []reconcile.Interface{
	{Name: "en0", Class: policy.ClassHardware},
	{Name: "en1", Class: policy.ClassHardware},
	{Name: "utun4", Class: policy.ClassTunnel},
	{Name: "utun5", Class: policy.ClassTunnel},
	{Name: "bridge100"},
	{Name: "lo0"},
}

// noTunnels is hostIfaces without the tunnel interfaces.
var noTunnels = []reconcile.Interface{
	{Name: "en0", Class: policy.ClassHardware},
	{Name: "lo0"},
}

// hostAccounts is the account snapshot of the tests. nobody has the ID
// -2, as on macOS, which pfctl does not take as a number. alias shares the
// uid of _buildbot.
var hostAccounts = reconcile.Accounts{
	Users:  map[string]uint32{"root": 0, "daemon": 1, "_www": 70, "_buildbot": 299, "alias": 299, "nobody": 4294967294},
	Groups: map[string]uint32{"wheel": 0, "daemon": 1, "staff": 20, "nobody": 4294967294},
}

// rfcExample is the policy part of the RFC example configuration.
const rfcExample = `
[[policy]]
name     = "bing"
to       = ["*.bing.com", "203.0.113.0/24"]
only_via = ["@tunnel"]

[[policy]]
name     = "doh-servers"
to       = ["1.1.1.1/32", "8.8.8.8/32"]
only_via = []

[[policy]]
name     = "build-bot"
to       = ["*.example.com"]
deny_via = ["@hardware"]
scope    = { users = ["_buildbot"] }
`

const rfcExampleRules = `table <"bing"> persist
table <"build-bot"> persist
table <"doh-servers"> persist
anchor "tag.bing" out on { "utun4" "utun5" } to <"bing"> tag "ifbound.bing"
block return-icmp(port-unr, port-unr) out quick to <"bing"> ! tagged "ifbound.bing"
block return-icmp(port-unr, port-unr) out quick on { "en0" "en1" } to <"build-bot"> user { 299 }
block return-icmp(port-unr, port-unr) out quick to <"doh-servers">
`

// goldenCase is one compile input and its expected ruleset text and
// problems.
type goldenCase struct {
	name     string
	config   string // [[policy]] tables only
	ifaces   []reconcile.Interface
	want     string
	problems []string
}

var goldenCases = []goldenCase{
	{
		name:   "only_via list: explicit name also when absent, class from the inventory",
		config: "[[policy]]\nname = \"bing\"\nto = [\"*.bing.com\"]\nonly_via = [\"@tunnel\", \"en7\"]\n",
		ifaces: hostIfaces,
		want: `table <"bing"> persist
anchor "tag.bing" out on { "en7" "utun4" "utun5" } to <"bing"> tag "ifbound.bing"
block return-icmp(port-unr, port-unr) out quick to <"bing"> ! tagged "ifbound.bing"
`,
	},
	{
		name:   "only_via empty: block only",
		config: "[[policy]]\nname = \"doh\"\nto = [\"1.1.1.1\"]\nonly_via = []\n",
		ifaces: hostIfaces,
		want: `table <"doh"> persist
block return-icmp(port-unr, port-unr) out quick to <"doh">
`,
	},
	{
		name:   "deny_via: class and glob",
		config: "[[policy]]\nname = \"p\"\nto = [\"a.com\"]\ndeny_via = [\"@hardware\", \"bridge*\"]\n",
		ifaces: hostIfaces,
		want: `table <"p"> persist
block return-icmp(port-unr, port-unr) out quick on { "bridge100" "en0" "en1" } to <"p">
`,
	},
	{
		name:   "glob selectors: only the inventory, sorted, no duplicates",
		config: "[[policy]]\nname = \"p\"\nto = [\"a.com\"]\nonly_via = [\"utun*\", \"en?\", \"utun4\"]\n",
		ifaces: hostIfaces,
		want: `table <"p"> persist
anchor "tag.p" out on { "en0" "en1" "utun4" "utun5" } to <"p"> tag "ifbound.p"
block return-icmp(port-unr, port-unr) out quick to <"p"> ! tagged "ifbound.p"
`,
	},
	{
		name:   "scope users on deny_via: numeric, sorted, one ID once",
		config: "[[policy]]\nname = \"build-bot\"\nto = [\"a.com\"]\ndeny_via = [\"@hardware\"]\nscope = { users = [\"root\", \"_buildbot\", \"alias\"] }\n",
		ifaces: hostIfaces,
		want: `table <"build-bot"> persist
block return-icmp(port-unr, port-unr) out quick on { "en0" "en1" } to <"build-bot"> user { 0 299 }
`,
	},
	{
		name:   "scope groups on only_via",
		config: "[[policy]]\nname = \"p\"\nto = [\"a.com\"]\nonly_via = [\"@tunnel\"]\nscope = { groups = [\"staff\"] }\n",
		ifaces: hostIfaces,
		want: `table <"p"> persist
anchor "tag.p" out on { "utun4" "utun5" } to <"p"> tag "ifbound.p"
block return-icmp(port-unr, port-unr) out quick to <"p"> ! tagged "ifbound.p" group { 20 }
`,
	},
	{
		name:   "scope users and groups: one block rule each",
		config: "[[policy]]\nname = \"p\"\nto = [\"a.com\"]\nonly_via = []\nscope = { users = [\"daemon\"], groups = [\"wheel\", \"staff\"] }\n",
		ifaces: hostIfaces,
		want: `table <"p"> persist
block return-icmp(port-unr, port-unr) out quick to <"p"> user { 1 }
block return-icmp(port-unr, port-unr) out quick to <"p"> group { 0 20 }
`,
	},
	{
		name: "unknown names drop the scope of their policy only",
		config: "[[policy]]\nname = \"p\"\nto = [\"a.com\"]\ndeny_via = [\"en0\"]\nscope = { users = [\"root\", \"ghost\"], groups = [\"phantom\"] }\n" +
			"[[policy]]\nname = \"q\"\nto = [\"b.com\"]\ndeny_via = [\"en0\"]\nscope = { users = [\"root\"] }\n",
		ifaces: hostIfaces,
		want: `table <"p"> persist
table <"q"> persist
block return-icmp(port-unr, port-unr) out quick on { "en0" } to <"p">
block return-icmp(port-unr, port-unr) out quick on { "en0" } to <"q"> user { 0 }
`,
		problems: []string{`policy p applies to all traffic: its scope is dropped, because these accounts are unknown: group "phantom", user "ghost"`},
	},
	{
		name:   "an ID above the pf number limit becomes a range",
		config: "[[policy]]\nname = \"p\"\nto = [\"a.com\"]\nonly_via = [\"@tunnel\"]\nscope = { users = [\"nobody\"], groups = [\"staff\", \"nobody\"] }\n",
		ifaces: hostIfaces,
		want: `table <"p"> persist
anchor "tag.p" out on { "utun4" "utun5" } to <"p"> tag "ifbound.p"
block return-icmp(port-unr, port-unr) out quick to <"p"> ! tagged "ifbound.p" user { > 2147483646 }
block return-icmp(port-unr, port-unr) out quick to <"p"> ! tagged "ifbound.p" group { 20 > 2147483646 }
`,
	},
	{
		name:   "dropped scope on deny_via without a denied interface: no rule, still reported",
		config: "[[policy]]\nname = \"p\"\nto = [\"a.com\"]\ndeny_via = [\"ppp*\"]\nscope = { users = [\"ghost\"] }\n",
		ifaces: hostIfaces,
		want: `table <"p"> persist
`,
		problems: []string{`policy p applies to all traffic: its scope is dropped, because these accounts are unknown: user "ghost"`},
	},
	{
		name:   "empty interface set, only_via class: block only",
		config: "[[policy]]\nname = \"p\"\nto = [\"a.com\"]\nonly_via = [\"@tunnel\", \"utun*\"]\n",
		ifaces: noTunnels,
		want: `table <"p"> persist
block return-icmp(port-unr, port-unr) out quick to <"p">
`,
	},
	{
		name:   "empty interface set, deny_via glob: table only",
		config: "[[policy]]\nname = \"p\"\nto = [\"a.com\"]\ndeny_via = [\"ppp*\", \"@tunnel\"]\n",
		ifaces: noTunnels,
		want: `table <"p"> persist
`,
	},
	{
		name:   "no interfaces at all",
		config: "[[policy]]\nname = \"p\"\nto = [\"a.com\"]\nonly_via = [\"@hardware\"]\n",
		ifaces: nil,
		want: `table <"p"> persist
block return-icmp(port-unr, port-unr) out quick to <"p">
`,
	},
	{
		name:   "an unwritable interface that no selector selects",
		config: "[[policy]]\nname = \"p\"\nto = [\"a.com\"]\nonly_via = [\"@tunnel\"]\n",
		ifaces: append(slices.Clone(hostIfaces), reconcile.Interface{Name: `en9" all`, Class: policy.ClassHardware}),
		want: `table <"p"> persist
anchor "tag.p" out on { "utun4" "utun5" } to <"p"> tag "ifbound.p"
block return-icmp(port-unr, port-unr) out quick to <"p"> ! tagged "ifbound.p"
`,
	},
	{
		name:   "names that are pf keywords",
		config: "[[policy]]\nname = \"any\"\nto = [\"a.com\"]\nonly_via = [\"all\"]\n",
		ifaces: hostIfaces,
		want: `table <"any"> persist
anchor "tag.any" out on { "all" } to <"any"> tag "ifbound.any"
block return-icmp(port-unr, port-unr) out quick to <"any"> ! tagged "ifbound.any"
`,
	},
	{
		name:   "no policies",
		config: "",
		ifaces: hostIfaces,
		want:   "",
	},
	{
		name:   "RFC example: one policy per constraint form, one with scope",
		config: rfcExample,
		ifaces: hostIfaces,
		want:   rfcExampleRules,
	},
}

func parsePolicies(t testing.TB, config string) []policy.Policy {
	t.Helper()
	cfg, err := policy.ParseBytes([]byte("[dns]\nupstream = [\"tls://1.1.1.1@a.example\"]\n" + config))
	if err != nil {
		t.Fatal(err)
	}
	return cfg.Policies
}

// compile compiles with hostAccounts.
func compile(ps []policy.Policy, ifaces []reconcile.Interface) (reconcile.Ruleset, error) {
	return Compiler{}.Compile(ps, ifaces, hostAccounts)
}

func compileText(t testing.TB, ps []policy.Policy, ifaces []reconcile.Interface) string {
	t.Helper()
	rs, err := compile(ps, ifaces)
	if err != nil {
		t.Fatal(err)
	}
	return string(rs.Body())
}

func problemTexts(rs reconcile.Ruleset) []string {
	var out []string
	for _, p := range rs.Problems() {
		if p.Voids {
			out = append(out, "VOIDS: "+p.Text)
			continue
		}
		out = append(out, p.Text)
	}
	return out
}

func TestCompileGolden(t *testing.T) {
	for _, tt := range goldenCases {
		t.Run(tt.name, func(t *testing.T) {
			ps := parsePolicies(t, tt.config)
			rs, err := compile(ps, tt.ifaces)
			if err != nil {
				t.Fatal(err)
			}
			if got := string(rs.Body()); got != tt.want {
				t.Errorf("ruleset\n got:\n%s\nwant:\n%s", got, tt.want)
			}
			if want := reconcile.NewRuleset([]byte(tt.want)).ID(); rs.ID() != want {
				t.Errorf("ID = %s, want the digest of the text %s", rs.ID(), want)
			}
			if got := problemTexts(rs); !slices.Equal(got, tt.problems) {
				t.Errorf("problems\n got %q\nwant %q", got, tt.problems)
			}
		})
	}
}

// TestCompilePolicyOrder checks that the order of the policies and of
// the interfaces has no effect: every order gives the same text.
func TestCompilePolicyOrder(t *testing.T) {
	ps := parsePolicies(t, rfcExample)
	ifaces := slices.Clone(hostIfaces)
	for range 6 {
		ps = append(ps[1:], ps[0])
		slices.Reverse(ifaces)
		if got := compileText(t, ps, ifaces); got != rfcExampleRules {
			t.Errorf("order %v changes the ruleset:\n%s", names(ps), got)
		}
	}
}

func names(ps []policy.Policy) []policy.Name {
	out := make([]policy.Name, len(ps))
	for i, p := range ps {
		out[i] = p.Name
	}
	return out
}

// TestCompileAccounts checks that empty accounts drop every scope and
// that a changed ID changes the ruleset.
func TestCompileAccounts(t *testing.T) {
	ps := parsePolicies(t, rfcExample)
	rs, err := Compiler{}.Compile(ps, hostIfaces, reconcile.Accounts{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rs.Body()), `on { "en0" "en1" } to <"build-bot">`+"\n") || len(rs.Problems()) != 1 {
		t.Errorf("empty accounts: want build-bot without scope and one problem\n%s\n%v", rs.Body(), rs.Problems())
	}
	moved := reconcile.Accounts{Users: map[string]uint32{"_buildbot": 300}}
	rs2, err := Compiler{}.Compile(ps, hostIfaces, moved)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rs2.Body()), "user { 300 }") || rs2.ID() == reconcile.NewRuleset([]byte(rfcExampleRules)).ID() {
		t.Errorf("a new uid must change the ruleset\n%s", rs2.Body())
	}
}

func TestCompileNameLimits(t *testing.T) {
	only := policy.NewOnlyVia()
	longest := strings.Repeat("n", maxTableName)
	got := compileText(t, []policy.Policy{{Name: policy.Name(longest), Constraint: only}}, nil)
	want := `table <"` + longest + `"> persist
block return-icmp(port-unr, port-unr) out quick to <"` + longest + `">
`
	if got != want {
		t.Errorf("31-byte name\n got:\n%s\nwant:\n%s", got, want)
	}
	for _, n := range []policy.Name{
		"",
		policy.Name(strings.Repeat("n", maxTableName+1)),
		`a" pass quick all "`,
		"a\nb",
		"a b",
		"a/b",
	} {
		_, err := compile([]policy.Policy{{Name: n, Constraint: only}}, nil)
		if !errors.Is(err, errName) {
			t.Errorf("name %q: error = %v, want %v", n, err, errName)
		}
	}
}

func TestCompileRejects(t *testing.T) {
	sel := func(s string) policy.InterfaceSelector {
		x, err := policy.ParseInterfaceSelector(s)
		if err != nil {
			t.Fatal(err)
		}
		return x
	}
	only := policy.NewOnlyVia(sel("en0"))
	badIface := []reconcile.Interface{{Name: `en0" all`, Class: policy.ClassHardware}, {Name: strings.Repeat("u", maxIfaceName+1), Class: policy.ClassTunnel}}
	tests := []struct {
		name   string
		ps     []policy.Policy
		ifaces []reconcile.Interface
		want   error
	}{
		{"duplicate name", []policy.Policy{{Name: "p", Constraint: only}, {Name: "q", Constraint: only}, {Name: "p", Constraint: only}}, nil, errDuplicate},
		{"nil constraint", []policy.Policy{{Name: "p"}}, nil, errConstraint},
		{"zero deny_via", []policy.Policy{{Name: "p", Constraint: policy.DenyVia{}}}, nil, errConstraint},
		{"nil selector", []policy.Policy{{Name: "p", Constraint: policy.NewOnlyVia(nil)}}, nil, errSelector},
		{"zero name selector", []policy.Policy{{Name: "p", Constraint: policy.NewOnlyVia(policy.InterfaceName{})}}, nil, errSelector},
		{"zero glob selector", []policy.Policy{{Name: "p", Constraint: policy.NewOnlyVia(policy.InterfaceGlob{})}}, nil, errSelector},
		{"zero class selector", []policy.Policy{{Name: "p", Constraint: policy.NewOnlyVia(policy.InterfaceClass{})}}, nil, errSelector},
		{"class selects a name with a quote", []policy.Policy{{Name: "p", Constraint: policy.NewOnlyVia(sel("@hardware"))}}, badIface, errInterface},
		{"glob selects a name too long", []policy.Policy{{Name: "p", Constraint: policy.NewOnlyVia(sel("u*"))}}, badIface, errInterface},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := compile(tt.ps, tt.ifaces)
			if !errors.Is(err, tt.want) {
				t.Errorf("error = %v, want %v", err, tt.want)
			}
		})
	}
	for _, tt := range tests[len(tests)-2:] {
		deny, err := policy.NewDenyVia(tt.ps[0].Constraint.Selectors()...)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := compile([]policy.Policy{{Name: "p", Constraint: deny}}, badIface); !errors.Is(err, errInterface) {
			t.Errorf("%s, deny_via: error = %v, want %v", tt.name, err, errInterface)
		}
	}
}
