package addrbook

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

const snapshotVersion = 1

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
	errNotCanonical     = errors.New("address is not canonical")
	errExpiryBeforeSeen = errors.New("expiry before last_seen")
)

const tempInfix = ".addrbook-tmp-"

type snapshotFile struct {
	Version int             `json:"version"`
	Entries []snapshotEntry `json:"entries"`
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

func topFields() []string { return []string{"version", "entries"} }

func entryFields() []string {
	return []string{"policy", "addr", "last_seen_unix_nano", "ttl_nano", "expiry_unix_nano"}
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
	for _, byAddr := range b.entries {
		for _, r := range byAddr {
			r.savedExpiry = r.expiry
		}
	}
	return nil
}

func osRename(oldpath, newpath string) error { return os.Rename(oldpath, newpath) }

func (b *AddrBook) encode() ([]byte, error) {
	var all []Entry
	for name, byAddr := range b.entries {
		for a, r := range byAddr {
			all = append(all, entryOf(name, a, r))
		}
	}
	sortEntries(all)
	out := make([]snapshotEntry, len(all))
	for i, e := range all {
		for _, t := range []time.Time{e.LastSeen, e.Expiry} {
			if !t.Equal(time.Unix(0, t.UnixNano())) {
				return nil, fmt.Errorf("%w: %v", ErrTimeRange, t)
			}
		}
		out[i] = snapshotEntry{e.Policy, e.Addr, e.LastSeen.UnixNano(), int64(e.TTL), e.Expiry.UnixNano()}
	}
	return json.Marshal(snapshotFile{Version: snapshotVersion, Entries: out})
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
	loaded, err := b.decode(data)
	if err != nil {
		return fmt.Errorf("load addrbook %s: %w", path, err)
	}
	b.entries = loaded
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

func (b *AddrBook) decode(data []byte) (map[policy.Name]map[netip.Addr]*record, error) {
	top, err := objectFields(data, topFields())
	if err != nil {
		return nil, err
	}
	var version int
	if err := json.Unmarshal(top["version"], &version); err != nil || version != snapshotVersion {
		return nil, badf("unknown version %s", top["version"])
	}
	rawEntries := bytes.TrimSpace(top["entries"])
	if len(rawEntries) == 0 || rawEntries[0] != '[' {
		return nil, badf("entries is not an array")
	}
	var items []json.RawMessage
	if err := json.Unmarshal(rawEntries, &items); err != nil {
		return nil, badf("entries: %v", err)
	}
	out := make(map[policy.Name]map[netip.Addr]*record)
	for i, item := range items {
		name, a, r, err := b.decodeEntry(item)
		if err != nil {
			return nil, badf("entry %d: %v", i, err)
		}
		if out[name] == nil {
			out[name] = make(map[netip.Addr]*record)
		}
		if _, dup := out[name][a]; dup {
			return nil, badf("entry %d: duplicate", i)
		}
		out[name][a] = r
	}
	return out, nil
}

func (b *AddrBook) decodeEntry(item json.RawMessage) (policy.Name, netip.Addr, *record, error) {
	f, err := objectFields(item, entryFields())
	if err != nil {
		return "", netip.Addr{}, nil, err
	}
	var (
		name                       string
		addrText                   string
		seenNano, ttlNano, expNano int64
	)
	targets := map[string]any{
		"policy": &name, "addr": &addrText,
		"last_seen_unix_nano": &seenNano, "ttl_nano": &ttlNano, "expiry_unix_nano": &expNano,
	}
	for field, dst := range targets {
		if string(bytes.TrimSpace(f[field])) == "null" {
			return "", netip.Addr{}, nil, fmt.Errorf("%s: %w", field, errNull)
		}
		if err := json.Unmarshal(f[field], dst); err != nil {
			return "", netip.Addr{}, nil, fmt.Errorf("%s: %w", field, err)
		}
	}
	a, err := netip.ParseAddr(addrText)
	switch {
	case name == "":
		return "", netip.Addr{}, nil, errEmptyName
	case err != nil:
		return "", netip.Addr{}, nil, fmt.Errorf("addr: %w", err)
	case a.Zone() != "" || a.Is4In6():
		return "", netip.Addr{}, nil, errNotCanonical
	case ttlNano < 0:
		return "", netip.Addr{}, nil, ErrNegativeTTL
	case expNano < seenNano:
		return "", netip.Addr{}, nil, errExpiryBeforeSeen
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
	return policy.Name(name), a, r, nil
}

// objectFields splits a JSON object into its raw values. It accepts only
// the allowed keys, spelled exactly, each once and all present, and
// nothing after the object. The standard decoder folds key case and
// allows duplicate keys, so the walk is by hand.
func objectFields(data []byte, allowed []string) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, badf("not an object")
	}
	fields := make(map[string]json.RawMessage, len(allowed))
	for dec.More() {
		tok, err := dec.Token()
		key, isStr := tok.(string)
		if err != nil || !isStr {
			return nil, badf("malformed object")
		}
		if !slices.Contains(allowed, key) {
			return nil, badf("unknown key %q", key)
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
	for _, k := range allowed {
		if _, ok := fields[k]; !ok {
			return nil, badf("missing key %q", k)
		}
	}
	return fields, nil
}
