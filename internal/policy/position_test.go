package policy

import (
	"errors"
	"math/rand/v2"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

// secondPolicy is a config whose second policy has the destination "bad host".
const secondPolicy = dnsTable + "[[policy]]\nname = \"a\"\nto = [\"1.1.1.1\"]\nonly_via = []\n" +
	"[[policy]]\nname = \"b\"\nto = [\"bad host\"]\nonly_via = []\n"

func TestParseErrorPosition(t *testing.T) {
	tests := []struct {
		name, doc, field string
		line, column     int
	}{
		{"missing closing bracket", "[dns]\nupstream = [\"tls://1.1.1.1@a.b\"\n", "", 2, 32},
		{
			"unknown key",
			dnsTable + "[[policy]]\nname = \"p\"\nto = [\"1.1.1.1\"]\nonly_via = []\n  colour = \"red\"\n",
			"policy[0].colour", 7, 3,
		},
		{"invalid address in policy[1].to[0]", secondPolicy, "policy[1].to[0]", 9, 7},
		{
			"invalid address as the second element",
			dnsTable + "[[policy]]\nname = \"b\"\nto = [\"1.1.1.2\", \"bad host\"]\nonly_via = []\n",
			"policy[0].to[1]", 5, 18,
		},
		{
			"three duplicate keys point at the second",
			dnsTable + "[addrbook]\nretain = \"1h\"\nretain = \"2h\"\nretain = \"3h\"\n",
			"addrbook.retain", 5, 1,
		},
		{
			"three duplicate tables point at the second",
			dnsTable + "[addrbook]\n[addrbook]\n[addrbook]\n",
			"addrbook", 4, 2,
		},
		{"absent key falls back to the table", "[dns]\n", "dns.upstream", 1, 2},
		{
			"absent only_via and deny_via fall back to the policy header",
			dnsTable + "[[policy]]\nname = \"p\"\nto = [\"1.1.1.1\"]\n",
			"policy[0].only_via/deny_via", 3, 3,
		},
		{
			"dotted key in a policy",
			dnsTable + "[[policy]]\nname = \"p\"\nto = [\"1.1.1.1\"]\nonly_via = []\nscop.users = [\"a\"]\n",
			"policy[0].scop", 7, 1,
		},
		{"dotted key in dns", dnsTable + "foo.bar = 1\n", "dns.foo", 3, 1},
		{"dotted key where a string belongs", "[dns]\nlisten.x = 1\n", "dns.listen", 2, 1},
		{"implicit table from a header", dnsTable + "[policy.scope]\nusers = [\"a\"]\n", "policy", 3, 2},
		{"dotted key at the policy name", "policy.x = 1\n" + dnsTable, "policy", 1, 1},
		{
			"nested array in to",
			dnsTable + "[[policy]]\nname = \"p\"\nto = [[\"x\"]]\nonly_via = []\n",
			"policy[0].to[0]", 5, 1,
		},
		{"nested array in upstream", "[dns]\nupstream = [[\"tls://1.1.1.1@a.b\"]]\n", "dns.upstream[0]", 2, 1},
		{
			"nested array as the second element of a multiline to",
			dnsTable + "[[policy]]\nname = \"p\"\nto = [\n  \"1.1.1.1\",\n  [\"x\"],\n]\nonly_via = []\n",
			"policy[0].to[1]", 5, 1,
		},
		{
			"array of tables where a table belongs",
			dnsTable + "[[policy]]\nname = \"p\"\nto = [\"1.1.1.1\"]\nonly_via = []\n[[policy.scope]]\nusers = [\"a\"]\n",
			"policy[0].scope", 7, 10,
		},
		{
			"dotted key: the place is the part that ends the field",
			dnsTable + "[[policy]]\nname = \"p\"\nto = [\"1.1.1.1\"]\nonly_via = []\nscope.userz = [\"a\"]\n",
			"policy[0].scope.userz", 7, 7,
		},
		{"subtable header: the place is the last part", dnsTable + "[dns.foo]\n", "dns.foo", 3, 6},
		{"prefix of a header takes its own part", dnsTable + "[dns.foo.bar]\n", "dns.foo", 3, 6},
		{
			"prefix of a dotted key takes its own part",
			dnsTable + "[[policy]]\nname = \"p\"\nto = [\"1.1.1.1\"]\nonly_via = []\nscope.userz.x = 1\n",
			"policy[0].scope.userz", 7, 7,
		},
		{
			"quoted key that spells an element",
			secondPolicy[:strings.Index(secondPolicy, "[[policy]]\nname = \"b\"")] + "\"to[0]\" = 1\n",
			"policy[0].to[0]", 7, 1,
		},
		{
			"quoted key that spells a path in an inline table",
			"dns = { upstream = [\"tls://1.1.1.1@a.b\"] }\n\"dns.upstream\" = 1\n",
			"dns.upstream", 2, 1,
		},
		{
			"keys in two elements of an array of tables are not duplicates",
			"[[a]]\nb = 1\n[[a]]\nb = 1\n" + dnsTable,
			"a", 1, 3,
		},
		{
			"element of an inline table",
			policyDoc(`"1.1.1.1"`, "only_via = []\nscope = { users = [\"ok\", \"bad user\"] }\n"),
			"policy[0].scope.users[1]", 7, 26,
		},
		{
			"unknown key in an inline table counts bytes",
			policyDoc(`"1.1.1.1"`, "only_via = []\nscope = { users = [\"é\"], bad = 1 }\n"),
			"policy[0].scope.bad", 7, 27,
		},
		{"empty quoted key", "\"\" = 1\n" + dnsTable, "", 1, 1},
		{
			"CRLF line ends",
			strings.ReplaceAll(secondPolicy, "\n", "\r\n"),
			"policy[1].to[0]", 9, 7,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseBytes([]byte(tt.doc))

			var fe *FieldError
			if !errors.As(err, &fe) {
				t.Fatalf("err = %v, want a *FieldError", err)
			}
			if fe.Line != tt.line || fe.Column != tt.column {
				t.Errorf("place = %d:%d, want %d:%d (%v)", fe.Line, fe.Column, tt.line, tt.column, err)
			}
			if tt.field != "" && fe.Field != tt.field {
				t.Errorf("field = %q, want %q", fe.Field, tt.field)
			}
		})
	}
	testQuotedKeyPlaces(t)
}

// testQuotedKeyPlaces checks keys that hold the characters of the path
// syntax, quoted headers, and the bare and quoted spellings of one key. It
// compares the whole text of the error, not only the field.
func testQuotedKeyPlaces(t *testing.T) {
	const dns = "[dns]\nupstream = [\"tls://1.1.1.1@a.b\"]\n"                         // lines 1-2
	const pol = dns + "[[policy]]\nname = \"p\"\nto = [\"1.1.1.1\"]\nonly_via = []\n" // lines 3-6
	tests := []struct {
		name, doc, text string
		line, column    int
	}{
		{"key with ]", dns + "\"a]b\" = 1\n", `"dns.a]b": unknown key`, 3, 1},
		{"key with a quote", dns + "  \"a\\\"b\" = 1\n", `"dns.a\"b": unknown key`, 3, 3},
		{"key with a space", dns + "'a b' = 1\n", `"dns.a b": unknown key`, 3, 1},
		{"key with [0] in a policy", pol + "only_via[0] = 1\n", "", 0, 0},
		{
			"quoted key after the real dotted key",
			pol + "scope.users = [\"ok\"]\n\"scope.users\" = 1\n",
			`"policy[0].scope.users": unknown key`, 8, 1,
		},
		{"quoted table header", dns + "[\"policy\"]\nname = \"p\"\n", `"policy": must be an array of tables: use [[policy]]`, 3, 2},
		{
			"quoted array-of-tables header",
			dns + "[[\"policy\"]]\nname = \"p\"\nto = [\"bad host\"]\nonly_via = []\n",
			`"policy[0].to[0]": invalid domain: "bad host"`, 5, 7,
		},
		{
			"bare then quoted array-of-tables header make one array",
			pol + "[[\"policy\"]]\nname = \"b\"\nto = [\"bad host\"]\nonly_via = []\n",
			`"policy[1].to[0]": invalid domain: "bad host"`, 9, 7,
		},
		{
			"quoted sub-table header belongs to the latest policy",
			pol + "[policy.scope]\nusers = [\"a\"]\n[[policy]]\nname = \"b\"\nto = [\"1.1.1.2\"]\nonly_via = []\n" +
				"[ \"policy\" . 'scope' ]\nusers = [\"bad user\"]\n",
			`"policy[1].scope.users[0]": user or group name must be 1 to 32 bytes of [A-Za-z0-9_.-], starting with a letter or "_": "bad user"`,
			14, 10,
		},
		{
			"bare then quoted sub-table header is a duplicate",
			pol + "[policy.scope]\n[\"policy\".\"scope\"]\n",
			`"policy[0].scope": cannot decode: duplicate key`, 8, 11,
		},
		{
			"bare then quoted key is a duplicate",
			dns + "[addrbook]\nretain = \"1h\"\n\"retain\" = \"2h\"\n",
			`"addrbook.retain": cannot decode: duplicate key`, 5, 1,
		},
		{
			"bare then literal key is a duplicate",
			dns + "[addrbook]\nretain = \"1h\"\n'retain' = \"2h\"\n",
			`"addrbook.retain": cannot decode: duplicate key`, 5, 1,
		},
		{
			"bare then escaped key is a duplicate",
			dns + "[addrbook]\nretain = \"1h\"\n\"r\\u0065tain\" = \"2h\"\n",
			`"addrbook.retain": cannot decode: duplicate key`, 5, 1,
		},
		{
			"bare then quoted header is a duplicate",
			dns + "[addrbook]\n[\"addrbook\"]\n",
			`"addrbook": cannot decode: duplicate key`, 4, 2,
		},
		{
			"dotted bare then quoted key is a duplicate",
			"dns.upstream = [\"tls://1.1.1.1@a.b\"]\n\"dns\".\"upstream\" = []\n",
			`"dns.upstream": cannot decode: duplicate key`, 2, 7,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseBytes([]byte(tt.doc))

			var fe *FieldError
			if !errors.As(err, &fe) {
				t.Fatalf("err = %v, want a *FieldError", err)
			}
			if tt.text == "" { // the decoder decides the text: the place must still lie in the file
				checkInDoc(t, tt.doc, err.Error(), fe.Line, fe.Column)
				return
			}
			if err.Error() != tt.text || fe.Line != tt.line || fe.Column != tt.column {
				t.Errorf("got %q at %d:%d, want %q at %d:%d", err, fe.Line, fe.Column, tt.text, tt.line, tt.column)
			}
		})
	}
}

// TestParseQuotedKeyMessage pins the text of the error for a quoted key that
// spells the path of another key. The key is unknown. It is not a duplicate.
func TestParseQuotedKeyMessage(t *testing.T) {
	_, err := ParseBytes([]byte("dns = { upstream = [\"tls://1.1.1.1@a.b\"] }\n\"dns.upstream\" = 1\n"))

	if want := `"dns.upstream": unknown key`; err == nil || err.Error() != want {
		t.Errorf("err = %v, want %q", err, want)
	}
}

func TestParseSyntaxErrorCRLF(t *testing.T) {
	const lf = "[dns]\nupstream = [\"tls://1.1.1.1@a.b\"\n"

	_, errLF := ParseBytes([]byte(lf))
	_, errCRLF := ParseBytes([]byte(strings.ReplaceAll(lf, "\n", "\r\n")))

	var a, b *FieldError
	if !errors.As(errLF, &a) || !errors.As(errCRLF, &b) {
		t.Fatalf("errors = %v, %v, want *FieldError", errLF, errCRLF)
	}
	if a.Line != b.Line {
		t.Errorf("lines = %d and %d, want equal", a.Line, b.Line)
	}
	// go-toml counts the "\r" at the end of the line in the column.
	if b.Column != a.Column+1 {
		t.Errorf("columns = %d (LF) and %d (CRLF), want the CRLF column one larger", a.Column, b.Column)
	}
}

func TestCheckUpstreamsErrorGetsAPlace(t *testing.T) {
	doc := []byte(policyDoc(`"1.1.1.0/24"`, "only_via = []\n"))
	cfg, err := ParseBytes(doc)
	if err != nil {
		t.Fatal(err)
	}

	err = cfg.CheckUpstreams()

	var fe *FieldError
	if !errors.As(err, &fe) {
		t.Fatalf("err = %v, want a *FieldError", err)
	}
	if fe.Line != 0 {
		t.Errorf("place before Locate = %d:%d, want unknown", fe.Line, fe.Column)
	}
	fe.Locate(doc)
	if fe.Field != "policy[0].to" || fe.Line != 5 || fe.Column != 1 {
		t.Errorf("after Locate: field %q at %d:%d, want policy[0].to at 5:1", fe.Field, fe.Line, fe.Column)
	}
}

var elementRE = regexp.MustCompile(`^(.*)\[[0-9]+\]$`)

// FuzzIndex checks the places that the index gives, for any input: each
// place lies in the document, an element never sits before its array, and
// the place 1:1 only appears where a key really starts.
func FuzzIndex(f *testing.F) {
	for _, s := range fuzzSeeds() {
		f.Add(s)
	}
	f.Add(policyDoc(`["x"]`, "only_via = []\n"))
	f.Add(dnsTable + "[[policy]]\nname = \"p\"\nto = [\n  \"1.1.1.1\",\n  [\"x\", [\"y\"]],\n]\n")
	f.Add("a = [[1], [2, [3]]]\nb = { c = [{ d = 1 }], e.f = 2 }\n")
	f.Add("a.b = 1\n[a.c]\n[a]\n")
	f.Add("\"\" = 1\n\"é\" = [1]\r\n")
	f.Fuzz(func(t *testing.T, doc string) {
		b := []byte(doc)
		x := newIndex(b)
		// Two definitions of one path can place its elements in different
		// arrays. TOML refuses such a file, so the checks of places need a valid one.
		var tree map[string]any
		valid := toml.Unmarshal(b, &tree) == nil
		for path, r := range x.places {
			if !valid {
				break
			}
			if r.Length == 0 {
				t.Errorf("path %q has an empty range", path)
				continue
			}
			line, col := x.pos(r)
			checkInDoc(t, doc, strconv.Quote(path), line, col)
			// The decoder can report a fault at 1:1, but a key cannot start
			// at a blank, a comment, or the end of the document.
			if line == 1 && col == 1 && (len(b) == 0 || strings.IndexByte(" \t\r\n#", b[0]) >= 0) {
				t.Errorf("path %q at 1:1, but no key starts there", path)
			}
			checkElementOrder(t, x, path)
		}

		_, err := ParseBytes(b)
		var fe *FieldError
		if errors.As(err, &fe) && fe.Line > 0 {
			checkInDoc(t, doc, "error "+err.Error(), fe.Line, fe.Column)
		}
	})
}

// FuzzErrorPlaceIsAToken checks the place of an error from Parse for any
// input. The place lies in the document. If the index chose it, and not the
// TOML decoder, a key or a value starts there. So 1:1 appears only where a
// key or a value starts at the first byte.
func FuzzErrorPlaceIsAToken(f *testing.F) {
	for i := range 64 {
		f.Add(generate(rand.New(rand.NewPCG(uint64(i), 7)), faultKind(i%int(nFaults))).doc)
	}
	f.Add("# c\n[dns]\nupstream = [[\"tls://1.1.1.1@a.b\"]]\n")
	f.Add("\n\n[dns]\nupstream = []\n")
	f.Add("\"\" = 1\n")
	f.Fuzz(func(t *testing.T, doc string) {
		_, err := ParseBytes([]byte(doc))
		var fe *FieldError
		if !errors.As(err, &fe) || fe.Line == 0 {
			return
		}
		checkInDoc(t, doc, "error "+err.Error(), fe.Line, fe.Column)
		if strings.Contains(err.Error(), "toml: ") { // the decoder chose this place
			return
		}
		off := fe.Column - 1
		for _, l := range strings.Split(doc, "\n")[:fe.Line-1] {
			off += len(l) + 1
		}
		if off >= len(doc) || strings.IndexByte(" \t\r\n#=,]}[", doc[off]) >= 0 {
			t.Fatalf("place %d:%d does not start a key or a value (%v)\n%q", fe.Line, fe.Column, err, doc)
		}
	})
}

// checkInDoc checks that line and column name a place in doc, or the end of a line.
func checkInDoc(t *testing.T, doc, what string, line, col int) {
	t.Helper()
	lines := strings.Split(doc, "\n")
	if line < 1 || line > len(lines) || col < 1 || col > len(lines[line-1])+1 {
		t.Errorf("%s at %d:%d lies outside the document", what, line, col)
	}
}

// checkElementOrder checks that an array element does not sit before the
// nearest enclosing path that the index places.
func checkElementOrder(t *testing.T, x *index, path string) {
	t.Helper()
	line, col := x.pos(x.places[path])
	// A quoted name ends with a quote, so a path that ends with "]" ends with an index.
	for m := elementRE.FindStringSubmatch(path); m != nil; m = elementRE.FindStringSubmatch(m[1]) {
		if pr, ok := x.places[m[1]]; ok {
			pl, pc := x.pos(pr)
			if line < pl || line == pl && col < pc {
				t.Errorf("element %q at %d:%d sits before %q at %d:%d", path, line, col, m[1], pl, pc)
			}
			return
		}
	}
}

func TestAtKeepsThePlace(t *testing.T) {
	inner := newFieldError(literal("b"), errBadName)
	inner.Line, inner.Column = 2, 3

	err := at("a", inner)

	var fe *FieldError
	if !errors.As(err, &fe) || fe.Field != "a.b" || fe.Line != 2 || fe.Column != 3 {
		t.Errorf("err = %#v, want a.b at 2:3", fe)
	}
}
