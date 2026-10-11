package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
	"github.com/pelletier/go-toml/v2/unstable"
)

// The reasons that Parse reports. Each syntax or validation error is a
// *FieldError that wraps one of them.
var (
	errSyntax         = errors.New("cannot decode")
	errUnknownKey     = errors.New("unknown key")
	errPolicyShape    = errors.New("must be an array of tables: use [[policy]]")
	errUpstreamEmpty  = errors.New("must list at least one upstream")
	errUpstreamForm   = errors.New("must have the form tls://<ip>[:port]@<server-name>")
	errBadAddress     = errors.New("invalid address")
	errPortZero       = errors.New("port must not be zero")
	errZoned          = errors.New("zoned address is not allowed")
	errMappedPrefix   = errors.New("IPv4-mapped IPv6 prefix must have at least 96 bits")
	errBadDuration    = errors.New("invalid duration")
	errNotPositive    = errors.New("must be greater than zero")
	errBadName        = errors.New("policy name must be 1 to 24 bytes of [a-z0-9_-], starting with a letter or digit")
	errNameDuplicate  = errors.New("duplicate policy name")
	errToEmpty        = errors.New("must list at least one destination")
	errBadDomain      = errors.New("invalid domain")
	errNonASCII       = errors.New("domain must be ASCII: use the punycode form")
	errBadDestination = errors.New("invalid destination")
	errViaConflict    = errors.New("exactly one of only_via and deny_via is required")
	errDenyEmpty      = errors.New("deny_via must not be empty: the policy would have no effect")
	errBadSelector    = errors.New("invalid interface selector")
	errUnknownClass   = errors.New("unknown interface class")
)

// FieldError reports a configuration fault at one field. Field is the
// path in the file, for example "policy[1].to[0]". It is empty when the
// fault is not tied to a field, such as a TOML syntax error.
type FieldError struct {
	Field string
	Err   error
}

func (e *FieldError) Error() string {
	if e.Field == "" {
		return e.Err.Error()
	}
	// The path can hold raw key bytes: quote it so it cannot forge log lines.
	return strconv.Quote(e.Field) + ": " + e.Err.Error()
}

func (e *FieldError) Unwrap() error { return e.Err }

// at puts field in front of the field path of err.
func at(field string, err error) error {
	var fe *FieldError
	if !errors.As(err, &fe) {
		return &FieldError{Field: field, Err: err}
	}
	sep := "."
	if fe.Field == "" || strings.HasPrefix(fe.Field, "[") {
		sep = ""
	}
	return &FieldError{Field: field + sep + fe.Field, Err: fe.Err}
}

type rawConfig struct {
	DNS      rawDNS      `toml:"dns"`
	AddrBook rawAddrBook `toml:"addrbook"`
	Policy   []rawPolicy `toml:"policy"`
}

type rawDNS struct {
	Listen   *string  `toml:"listen"`
	Upstream []string `toml:"upstream"`
}

type rawAddrBook struct {
	Retain *string `toml:"retain"`
}

// rawPolicy uses pointers to slices so that an absent key (nil) differs
// from an empty array (non-nil, length zero).
type rawPolicy struct {
	Name    string    `toml:"name"`
	To      []string  `toml:"to"`
	OnlyVia *[]string `toml:"only_via"`
	DenyVia *[]string `toml:"deny_via"`
}

// ParseBytes parses a configuration file. See Parse.
func ParseBytes(b []byte) (Config, error) {
	return Parse(bytes.NewReader(b))
}

// Parse reads a TOML configuration and validates it.
//
// A read failure returns the reader's error. Any other failure is a
// *FieldError. Parse accepts only keys spelled exactly as documented:
// the TOML decoder matches keys without regard to case, so Parse checks
// the key set itself before it decodes into typed values.
func Parse(r io.Reader) (Config, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return Config{}, fmt.Errorf("reading config: %w", err)
	}
	if field, dup := findDuplicateKey(b); dup {
		return Config{}, &FieldError{Field: field, Err: fmt.Errorf("%w: duplicate key", errSyntax)}
	}
	var tree map[string]any
	if err := toml.Unmarshal(b, &tree); err != nil {
		return Config{}, decodeError(err)
	}
	if err := checkKeys(tree); err != nil {
		return Config{}, err
	}
	var raw rawConfig
	dec := toml.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return Config{}, decodeError(err)
	}
	return raw.validate()
}

// decodeError turns a decoder failure into this package's vocabulary.
// The decoder's own error stays out of the %w chain.
func decodeError(err error) error {
	var missing *toml.StrictMissingError
	if errors.As(err, &missing) && len(missing.Errors) > 0 {
		key := strings.Join(missing.Errors[0].Key(), ".")
		return &FieldError{Field: key, Err: errUnknownKey}
	}
	var derr *toml.DecodeError
	if errors.As(err, &derr) {
		return &FieldError{
			Field: strings.Join(derr.Key(), "."),
			Err:   fmt.Errorf("%w: %v", errSyntax, err),
		}
	}
	return &FieldError{Err: fmt.Errorf("%w: %v", errSyntax, err)}
}

// findDuplicateKey finds a key or table that the file defines twice. The
// decoder reports such a key without its parent path, so Parse looks for
// it first, with the full path. It does not see duplicates inside inline
// tables: for those, the decoder's own error stands.
func findDuplicateKey(b []byte) (string, bool) {
	var p unstable.Parser
	p.Reset(b)
	f := dupFinder{seen: map[string]struct{}{}}
	for p.NextExpression() {
		e := p.Expression()
		parts := keyParts(e.Key())
		var dup string
		//nolint:exhaustive // the other kinds are comments and values: they define no path
		switch e.Kind {
		case unstable.Table:
			dup = f.enterTable(parts)
		case unstable.ArrayTable:
			f.enterArrayTable(parts)
		case unstable.KeyValue:
			dup = f.keyValue(parts)
		}
		if dup != "" {
			return dup, true
		}
	}
	return "", false
}

// dupFinder tracks the paths that the file has defined so far.
type dupFinder struct {
	seen     map[string]struct{}
	current  string // path of the current table
	policies int    // number of [[policy]] headers so far
}

// define records a path. It returns the path if it was already defined.
func (f *dupFinder) define(path string) string {
	if _, dup := f.seen[path]; dup {
		return path
	}
	f.seen[path] = struct{}{}
	return ""
}

func (f *dupFinder) enterTable(parts []string) string {
	// A table below [[policy]] belongs to the latest policy.
	if parts[0] == "policy" && f.policies > 0 {
		parts = slices.Clone(parts)
		parts[0] = fmt.Sprintf("policy[%d]", f.policies-1)
	}
	f.current = strings.Join(parts, ".")
	return f.define(f.current)
}

func (f *dupFinder) enterArrayTable(parts []string) {
	if len(parts) == 1 && parts[0] == "policy" {
		f.current = fmt.Sprintf("policy[%d]", f.policies)
		f.policies++
		return
	}
	f.current = strings.Join(parts, ".")
}

func (f *dupFinder) keyValue(parts []string) string {
	for i := 1; i < len(parts); i++ { // a dotted key defines its tables
		f.define(joinPath(f.current, strings.Join(parts[:i], ".")))
	}
	return f.define(joinPath(f.current, strings.Join(parts, ".")))
}

func joinPath(table, key string) string {
	if table == "" {
		return key
	}
	return table + "." + key
}

func keyParts(it unstable.Iterator) []string {
	var parts []string
	for it.Next() {
		parts = append(parts, string(it.Node().Data))
	}
	return parts
}

// checkKeys rejects every key that is not spelled exactly as the schema
// says, and every value of the wrong type. It works on the generic tree,
// where the array indices are known, so each error names its exact path.
// It also requires [[policy]] to be an array of tables.
func checkKeys(tree map[string]any) error {
	if err := checkTable("", tree, "dns", "addrbook", "policy"); err != nil {
		return err
	}
	if v, ok := tree["dns"]; ok {
		if err := checkTableValue("dns", v, map[string]fieldKind{"listen": kindString, "upstream": kindStrings}); err != nil {
			return err
		}
	}
	if v, ok := tree["addrbook"]; ok {
		if err := checkTableValue("addrbook", v, map[string]fieldKind{"retain": kindString}); err != nil {
			return err
		}
	}
	pol, present := tree["policy"]
	if !present {
		return nil
	}
	list, ok := pol.([]any)
	if !ok {
		return &FieldError{Field: "policy", Err: errPolicyShape}
	}
	for i, e := range list {
		kinds := map[string]fieldKind{"name": kindString, "to": kindStrings, "only_via": kindStrings, "deny_via": kindStrings}
		if err := checkTableValue(fmt.Sprintf("policy[%d]", i), e, kinds); err != nil {
			return err
		}
	}
	return nil
}

func typeError(want string) error {
	return fmt.Errorf("%w: must be %s", errSyntax, want)
}

type fieldKind int

const (
	kindString fieldKind = iota
	kindStrings
)

// checkTableValue checks that v is a table that holds only the keys in
// kinds, each with its kind of value. path is the table's own path.
// Several keys can be wrong; the error names the first in key order.
func checkTableValue(path string, v any, kinds map[string]fieldKind) error {
	m, ok := v.(map[string]any)
	if !ok {
		return &FieldError{Field: path, Err: typeError("a table")}
	}
	keys := slices.Sorted(maps.Keys(kinds))
	if err := checkTable(path, m, keys...); err != nil {
		return err
	}
	for _, k := range keys {
		val, ok := m[k]
		if !ok {
			continue
		}
		field := path + "." + k
		if kinds[k] == kindString {
			if _, isStr := val.(string); !isStr {
				return &FieldError{Field: field, Err: typeError("a string")}
			}
			continue
		}
		list, isList := val.([]any)
		if !isList {
			return &FieldError{Field: field, Err: typeError("an array of strings")}
		}
		for i, e := range list {
			if _, isStr := e.(string); !isStr {
				return &FieldError{Field: fmt.Sprintf("%s[%d]", field, i), Err: typeError("a string")}
			}
		}
	}
	return nil
}

func checkTable(path string, m map[string]any, allowed ...string) error {
	var unknown []string
	for k := range m {
		if !slices.Contains(allowed, k) {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	slices.Sort(unknown) // the same file always gives the same error
	field := unknown[0]
	if path != "" {
		field = path + "." + field
	}
	return &FieldError{Field: field, Err: errUnknownKey}
}

func (raw rawConfig) validate() (Config, error) {
	var cfg Config
	var err error
	if cfg.DNS, err = raw.DNS.validate(); err != nil {
		return Config{}, at("dns", err)
	}
	if cfg.AddrBook, err = raw.AddrBook.validate(); err != nil {
		return Config{}, at("addrbook", err)
	}
	seen := make(map[Name]struct{}, len(raw.Policy))
	for i, rp := range raw.Policy {
		field := fmt.Sprintf("policy[%d]", i)
		p, err := rp.validate()
		if err != nil {
			return Config{}, at(field, err)
		}
		if _, dup := seen[p.Name]; dup {
			return Config{}, at(field+".name", fmt.Errorf("%w: %q", errNameDuplicate, p.Name))
		}
		seen[p.Name] = struct{}{}
		cfg.Policies = append(cfg.Policies, p)
	}
	return cfg, nil
}

func (d rawDNS) validate() (DNS, error) {
	listen := DefaultListen
	if d.Listen != nil {
		listen = *d.Listen
	}
	ap, err := netip.ParseAddrPort(listen)
	if err != nil {
		return DNS{}, at("listen", fmt.Errorf("%w: %q", errBadAddress, listen))
	}
	if ap, err = normalizeAddrPort(ap); err != nil {
		return DNS{}, at("listen", err)
	}
	if len(d.Upstream) == 0 {
		return DNS{}, at("upstream", errUpstreamEmpty)
	}
	out := DNS{Listen: ap}
	for i, s := range d.Upstream {
		u, err := parseUpstream(s)
		if err != nil {
			return DNS{}, at(fmt.Sprintf("upstream[%d]", i), err)
		}
		out.Upstream = append(out.Upstream, u)
	}
	return out, nil
}

func normalizeAddrPort(ap netip.AddrPort) (netip.AddrPort, error) {
	if ap.Port() == 0 {
		return netip.AddrPort{}, errPortZero
	}
	a, err := normalizeAddr(ap.Addr())
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(a, ap.Port()), nil
}

// parseUpstream parses "tls://<ip>[:port]@<server-name>". An IPv6 address
// takes brackets.
func parseUpstream(s string) (Upstream, error) {
	rest, ok := strings.CutPrefix(s, "tls://")
	if !ok {
		return Upstream{}, fmt.Errorf("%w: %q", errUpstreamForm, s)
	}
	hostPort, name, ok := strings.Cut(rest, "@")
	if !ok {
		return Upstream{}, fmt.Errorf("%w: %q", errUpstreamForm, s)
	}
	// A port follows the last colon that comes after any closing bracket.
	if strings.LastIndex(hostPort, ":") <= strings.LastIndex(hostPort, "]") {
		hostPort += ":" + strconv.Itoa(DefaultDoTPort)
	}
	ap, err := netip.ParseAddrPort(hostPort)
	if err != nil {
		return Upstream{}, fmt.Errorf("%w: %q", errBadAddress, rest)
	}
	if ap, err = normalizeAddrPort(ap); err != nil {
		return Upstream{}, err
	}
	d, err := ParseDomain(name)
	if err != nil {
		return Upstream{}, err
	}
	return Upstream{Addr: ap, ServerName: d}, nil
}

func (a rawAddrBook) validate() (AddrBook, error) {
	if a.Retain == nil {
		return AddrBook{Retain: DefaultRetain}, nil
	}
	d, err := parseDuration(*a.Retain)
	if err != nil {
		return AddrBook{}, at("retain", fmt.Errorf("%w: %q", err, *a.Retain))
	}
	if d <= 0 {
		return AddrBook{}, at("retain", errNotPositive)
	}
	return AddrBook{Retain: d}, nil
}

// parseDuration accepts the Go syntax and a whole number of days ("7d").
func parseDuration(s string) (time.Duration, error) {
	if days, ok := strings.CutSuffix(s, "d"); ok {
		const day = int64(24 * time.Hour)
		n, err := strconv.ParseInt(days, 10, 64)
		if err != nil || n > math.MaxInt64/day || n < math.MinInt64/day {
			return 0, errBadDuration
		}
		return time.Duration(n * day), nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, errBadDuration
	}
	return d, nil
}

func (rp rawPolicy) validate() (Policy, error) {
	name, err := parseName(rp.Name)
	if err != nil {
		return Policy{}, at("name", err)
	}
	if len(rp.To) == 0 {
		return Policy{}, at("to", errToEmpty)
	}
	p := Policy{Name: name}
	seen := make(map[Destination]struct{}, len(rp.To))
	for i, s := range rp.To {
		d, err := ParseDestination(s)
		if err != nil {
			return Policy{}, at(fmt.Sprintf("to[%d]", i), err)
		}
		if _, dup := seen[d]; dup {
			continue
		}
		seen[d] = struct{}{}
		p.To = append(p.To, d)
	}
	if p.Constraint, err = rp.constraint(); err != nil {
		return Policy{}, err
	}
	return p, nil
}

func (rp rawPolicy) constraint() (Constraint, error) {
	switch {
	case rp.OnlyVia != nil && rp.DenyVia == nil:
		sels, err := parseSelectors(*rp.OnlyVia)
		if err != nil {
			return nil, at("only_via", err)
		}
		return NewOnlyVia(sels...), nil
	case rp.DenyVia != nil && rp.OnlyVia == nil:
		sels, err := parseSelectors(*rp.DenyVia)
		if err != nil {
			return nil, at("deny_via", err)
		}
		c, err := NewDenyVia(sels...)
		if err != nil {
			return nil, at("deny_via", err)
		}
		return c, nil
	default:
		return nil, at("only_via/deny_via", errViaConflict)
	}
}

func parseSelectors(in []string) ([]InterfaceSelector, error) {
	out := make([]InterfaceSelector, 0, len(in))
	seen := make(map[InterfaceSelector]struct{}, len(in))
	for i, s := range in {
		sel, err := ParseInterfaceSelector(s)
		if err != nil {
			return nil, at(fmt.Sprintf("[%d]", i), err)
		}
		if _, dup := seen[sel]; dup {
			continue
		}
		seen[sel] = struct{}{}
		out = append(out, sel)
	}
	return out, nil
}
