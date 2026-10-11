package addrbook

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/dnsname"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

// snapshotVersion is the version that Save writes. Version 2 added the
// aliases. Load also reads version 1, which has no aliases key.
const snapshotVersion = 2

// Errors that Save and Load return.
var (
	// ErrSnapshot marks a snapshot that exists but is not usable:
	// malformed, an unknown version, or an invalid entry. The book does
	// not start empty in this case. An empty book could unblock addresses
	// that applications still use.
	ErrSnapshot = errors.New("addrbook: bad snapshot")
	// ErrNotEmpty is the error of Load on a book that holds entries.
	ErrNotEmpty = errors.New("addrbook: load into a book that is not empty")
	// ErrBadPath is the error for a snapshot path that is not a plain
	// file location: a symlink, a non-file, or a missing directory.
	ErrBadPath = errors.New("addrbook: bad snapshot path")
	// ErrTimeRange is the error of Save for a time that Unix nanoseconds
	// cannot hold.
	ErrTimeRange = errors.New("addrbook: time outside the snapshot range")
)

var (
	errNull             = errors.New("null value")
	errEmptyName        = errors.New("empty policy name")
	errNotCanonical     = errors.New("key is not in canonical form")
	errExpiryBeforeSeen = errors.New("expiry before last_seen")
	errNotArray         = errors.New("not an array")
	errDuplicate        = errors.New("duplicate")
)

const tempInfix = ".addrbook-tmp-"

type snapshotFile struct {
	Version int             `json:"version"`
	Entries []snapshotEntry `json:"entries"`
	Aliases []snapshotAlias `json:"aliases"`
}

// snapshotEntry stores times as integers. A monotonic clock reading then
// cannot reach the book after a load.
type snapshotEntry struct {
	Policy       policy.Name `json:"policy"`
	Addr         netip.Addr  `json:"addr"`
	LastSeenNano int64       `json:"last_seen_unix_nano"`
	TTLNano      int64       `json:"ttl_nano"`
	ExpiryNano   int64       `json:"expiry_unix_nano"`
}

// snapshotAlias is one alias record. Alias holds the String of a
// dnsname.Name.
type snapshotAlias struct {
	Policy       policy.Name `json:"policy"`
	Alias        string      `json:"alias"`
	LastSeenNano int64       `json:"last_seen_unix_nano"`
	TTLNano      int64       `json:"ttl_nano"`
	ExpiryNano   int64       `json:"expiry_unix_nano"`
}

// topFields returns the top-level keys of a snapshot version. The bool
// is false for a version that Load does not know.
func topFields(version int) ([]string, bool) {
	switch version {
	case 1:
		return []string{"version", "entries"}, true
	case snapshotVersion:
		return []string{"version", "entries", "aliases"}, true
	}
	return nil, false
}

// itemFields returns the keys of an entry (key "addr") or an alias (key
// "alias").
func itemFields(key string) []string {
	return []string{"policy", key, "last_seen_unix_nano", "ttl_nano", "expiry_unix_nano"}
}

// Save writes the book to path. It removes the temporary files of earlier
// crashed saves, writes a new temporary file in the same directory, syncs
// it, renames it over path, and syncs the directory. A crash leaves either
// the old file or the new one. Save refuses a path that is a symlink and
// times that Unix nanoseconds cannot hold; it then writes nothing.
//
// Only a successful Save moves the saved expiry that Observe compares.
func (b *AddrBook) Save(path string) error {
	data, err := b.encode()
	if err != nil {
		return fmt.Errorf("save addrbook: %w", err)
	}
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("save addrbook: %w: %s is a symlink", ErrBadPath, path)
	}
	dir := filepath.Dir(path)
	if err := removeTemps(path); err != nil {
		return fmt.Errorf("save addrbook: %w", err)
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+tempInfix+"*")
	if err != nil {
		return fmt.Errorf("save addrbook: %w", err)
	}
	if err := writeSynced(tmp, data); err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("save addrbook: %w", err)
	}
	if err := b.rename(tmp.Name(), path); err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("save addrbook: %w", err)
	}
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("save addrbook: %w", err)
	}
	markSaved(b.entries)
	markSaved(b.aliases)
	return nil
}

func markSaved[K comparable](byPolicy map[policy.Name]map[K]*record) {
	for _, byKey := range byPolicy {
		for _, r := range byKey {
			r.savedExpiry = r.expiry
		}
	}
}

func osRename(oldpath, newpath string) error { return os.Rename(oldpath, newpath) }

func (b *AddrBook) encode() ([]byte, error) {
	f := snapshotFile{Version: snapshotVersion, Entries: []snapshotEntry{}, Aliases: []snapshotAlias{}}
	for _, name := range slices.Sorted(maps.Keys(b.entries)) {
		for _, a := range b.Addrs(name) {
			r := b.entries[name][a]
			seen, exp, err := unixNanos(r)
			if err != nil {
				return nil, err
			}
			f.Entries = append(f.Entries, snapshotEntry{name, a, seen, int64(r.ttl), exp})
		}
	}
	for _, name := range slices.Sorted(maps.Keys(b.aliases)) {
		for _, n := range b.Aliases(name) {
			r := b.aliases[name][n]
			seen, exp, err := unixNanos(r)
			if err != nil {
				return nil, err
			}
			f.Aliases = append(f.Aliases, snapshotAlias{name, n.String(), seen, int64(r.ttl), exp})
		}
	}
	return json.Marshal(f)
}

// unixNanos returns last_seen and expiry as Unix nanoseconds, or
// ErrTimeRange for a time that they cannot hold.
func unixNanos(r *record) (seen, exp int64, err error) {
	for _, t := range []time.Time{r.lastSeen, r.expiry} {
		if !t.Equal(time.Unix(0, t.UnixNano())) {
			return 0, 0, fmt.Errorf("%w: %v", ErrTimeRange, t)
		}
	}
	return r.lastSeen.UnixNano(), r.expiry.UnixNano(), nil
}

// removeTemps deletes the temporary files that an earlier crashed Save
// left next to path. It matches names by prefix, not by glob: the path
// may hold glob characters.
func removeTemps(path string) error {
	dir := filepath.Dir(path)
	ents, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	prefix := filepath.Base(path) + tempInfix
	for _, e := range ents {
		if !e.Type().IsRegular() || !strings.HasPrefix(e.Name(), prefix) {
			continue
		}
		if err := os.Remove(filepath.Join(dir, e.Name())); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

func writeSynced(f *os.File, data []byte) error {
	_, err := f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}

// Load fills an empty book from the snapshot at path. A book that holds
// entries is an error, so Load cannot drop entries that exist only in
// memory. The file is missing, and the book stays empty, only when the
// path does not exist and its directory does. A symlink, a dangling
// link, a missing directory and every other read error are errors. Load
// never loads a part of a snapshot, and a failed Load leaves the book
// unchanged. Load does not drop expired entries. The next Expire does.
//
// If the configured retain is larger than when the snapshot was saved,
// the expiry becomes the later of the stored one and
// last_seen + max(ttl, retain).
func (b *AddrBook) Load(path string) error {
	if !b.isEmpty() {
		return fmt.Errorf("load addrbook: %w", ErrNotEmpty)
	}
	data, missing, err := readRegular(path)
	if err != nil {
		return fmt.Errorf("load addrbook: %w", err)
	}
	if missing {
		return nil
	}
	entries, aliases, err := b.decode(data)
	if err != nil {
		return fmt.Errorf("load addrbook %s: %w", path, err)
	}
	b.entries, b.aliases = entries, aliases
	return nil
}

// readRegular reads path, which must be a regular file. Missing is true
// when the path does not exist in an existing directory.
func readRegular(path string) (data []byte, missing bool, err error) {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		dir, derr := os.Stat(filepath.Dir(path))
		if derr != nil {
			return nil, false, derr
		}
		if !dir.IsDir() {
			return nil, false, fmt.Errorf("%w: %s is not a directory", ErrBadPath, filepath.Dir(path))
		}
		return nil, true, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !fi.Mode().IsRegular() {
		return nil, false, fmt.Errorf("%w: %s is not a regular file", ErrBadPath, path)
	}
	data, err = os.ReadFile(path)
	return data, false, err
}

func badf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrSnapshot, fmt.Sprintf(format, args...))
}

func (b *AddrBook) decode(data []byte) (map[policy.Name]map[netip.Addr]*record, map[policy.Name]map[dnsname.Name]*record, error) {
	top, err := objectFields(data)
	if err != nil {
		return nil, nil, err
	}
	if _, ok := top["version"]; !ok {
		return nil, nil, badf("missing key %q", "version")
	}
	var version int
	if err := json.Unmarshal(top["version"], &version); err != nil {
		return nil, nil, badf("unknown version %s", top["version"])
	}
	want, ok := topFields(version)
	if !ok {
		return nil, nil, badf("unknown version %s", top["version"])
	}
	if err := exactFields(top, want); err != nil {
		return nil, nil, err
	}
	entries, err := decodeItems(b, top["entries"], "addr", parseAddr)
	if err != nil {
		return nil, nil, badf("entries: %v", err)
	}
	aliases := make(map[policy.Name]map[dnsname.Name]*record)
	if raw, ok := top["aliases"]; ok {
		if aliases, err = decodeItems(b, raw, "alias", parseAlias); err != nil {
			return nil, nil, badf("aliases: %v", err)
		}
	}
	return entries, aliases, nil
}

func parseAddr(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	switch {
	case err != nil:
		return netip.Addr{}, err
	case a.Zone() != "" || a.Is4In6():
		return netip.Addr{}, errNotCanonical
	}
	return a, nil
}

// parseAlias accepts only the String of a dnsname.Name, so one alias has
// one spelling in a snapshot.
func parseAlias(s string) (dnsname.Name, error) {
	n, err := dnsname.Parse(s)
	switch {
	case err != nil:
		return dnsname.Name{}, err
	case n.String() != s:
		return dnsname.Name{}, errNotCanonical
	}
	return n, nil
}

// decodeItems decodes a JSON array of records. Each record has the key
// field keyField, which parse reads.
func decodeItems[K comparable](b *AddrBook, raw json.RawMessage, keyField string, parse func(string) (K, error)) (map[policy.Name]map[K]*record, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '[' {
		return nil, errNotArray
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, err
	}
	out := make(map[policy.Name]map[K]*record)
	for i, item := range items {
		name, keyText, r, err := b.decodeItem(item, keyField)
		if err != nil {
			return nil, fmt.Errorf("item %d: %w", i, err)
		}
		k, err := parse(keyText)
		if err != nil {
			return nil, fmt.Errorf("item %d: %s: %w", i, keyField, err)
		}
		if out[name] == nil {
			out[name] = make(map[K]*record)
		}
		if _, dup := out[name][k]; dup {
			return nil, fmt.Errorf("item %d: %w", i, errDuplicate)
		}
		out[name][k] = r
	}
	return out, nil
}

// decodeItem decodes one record. It returns the text of the key field
// unparsed.
func (b *AddrBook) decodeItem(item json.RawMessage, keyField string) (policy.Name, string, *record, error) {
	f, err := objectFields(item)
	if err != nil {
		return "", "", nil, err
	}
	if err := exactFields(f, itemFields(keyField)); err != nil {
		return "", "", nil, err
	}
	var (
		name                       string
		keyText                    string
		seenNano, ttlNano, expNano int64
	)
	targets := map[string]any{
		"policy": &name, keyField: &keyText,
		"last_seen_unix_nano": &seenNano, "ttl_nano": &ttlNano, "expiry_unix_nano": &expNano,
	}
	for field, dst := range targets {
		if string(bytes.TrimSpace(f[field])) == "null" {
			return "", "", nil, fmt.Errorf("%s: %w", field, errNull)
		}
		if err := json.Unmarshal(f[field], dst); err != nil {
			return "", "", nil, fmt.Errorf("%s: %w", field, err)
		}
	}
	switch {
	case name == "":
		return "", "", nil, errEmptyName
	case ttlNano < 0:
		return "", "", nil, ErrNegativeTTL
	case expNano < seenNano:
		return "", "", nil, errExpiryBeforeSeen
	}
	r := &record{
		lastSeen:    time.Unix(0, seenNano).UTC(),
		ttl:         time.Duration(ttlNano),
		expiry:      time.Unix(0, expNano).UTC(),
		savedExpiry: time.Unix(0, expNano).UTC(),
	}
	if floor := r.lastSeen.Add(max(r.ttl, b.retain)); floor.After(r.expiry) {
		r.expiry = floor
	}
	return policy.Name(name), keyText, r, nil
}

// objectFields splits a JSON object into its raw values. It accepts each
// key once, spelled exactly, and nothing after the object. The caller
// checks the key set with exactFields. The standard decoder folds key
// case and allows duplicate keys, so the walk is by hand.
func objectFields(data []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, badf("not an object")
	}
	fields := make(map[string]json.RawMessage)
	for dec.More() {
		tok, err := dec.Token()
		key, isStr := tok.(string)
		if err != nil || !isStr {
			return nil, badf("malformed object")
		}
		if _, dup := fields[key]; dup {
			return nil, badf("duplicate key %q", key)
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, badf("key %q: %v", key, err)
		}
		fields[key] = raw
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, badf("malformed object")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, badf("data after the document")
	}
	return fields, nil
}

// exactFields checks that fields has each key of want and no other key.
func exactFields(fields map[string]json.RawMessage, want []string) error {
	for _, k := range want {
		if _, ok := fields[k]; !ok {
			return badf("missing key %q", k)
		}
	}
	for k := range fields {
		if !slices.Contains(want, k) {
			return badf("unknown key %q", k)
		}
	}
	return nil
}
