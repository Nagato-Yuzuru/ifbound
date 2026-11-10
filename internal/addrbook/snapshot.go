package addrbook

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/blockable"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

// snapshotVersion is the version that Save writes. Load also reads
// version 2, which has an "aliases" key next to the entries. Load checks
// the top level of version 2 as strictly as that of version 1: the exact
// key set, and an array as the value of "aliases". It does not check the
// items of that array on purpose: the book does not use them.
const snapshotVersion = 1

// aliasesVersion is the snapshot version with the ignored "aliases" key.
const aliasesVersion = 2

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
	errMissing          = errors.New("missing or null")
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
		_ = os.Remove(tmp.Name()) //nolint:errcheck // best-effort cleanup; the next Save removes leftover temp files
		return fmt.Errorf("save addrbook: %w", err)
	}
	if err := b.rename(tmp.Name(), path); err != nil {
		_ = os.Remove(tmp.Name()) //nolint:errcheck // best-effort cleanup; the next Save removes leftover temp files
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
	f := snapshotFile{Version: snapshotVersion, Entries: []snapshotEntry{}}
	for _, name := range slices.Sorted(maps.Keys(b.entries)) {
		for _, a := range b.Addrs(name) {
			r := b.entries[name][a]
			seen, exp, err := unixNanos(r)
			if err != nil {
				return nil, err
			}
			f.Entries = append(f.Entries, snapshotEntry{name, a.Addr(), seen, int64(r.ttl), exp})
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
// Load drops an entry with an address that blockable.New refuses: an
// earlier version can have saved it. The next Save does not write it.
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
	entries, err := b.decode(data)
	if err != nil {
		return fmt.Errorf("load addrbook %s: %w", path, err)
	}
	b.entries = entries
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

// decode reads a snapshot. It accepts each key once, spelled exactly,
// and nothing after the document. It decodes in two passes: the key set
// depends on the version.
func (b *AddrBook) decode(data []byte) (map[policy.Name]map[blockable.Addr]*record, error) {
	var head struct {
		Version *int `json:"version"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		return nil, badf("%v", err)
	}
	switch {
	case head.Version == nil:
		return nil, badf("missing or null key %q", "version")
	case *head.Version != snapshotVersion && *head.Version != aliasesVersion:
		return nil, badf("unknown version %d", *head.Version)
	}
	var doc struct {
		Version int            `json:"version"`
		Entries *[]loadedEntry `json:"entries"`
		Aliases jsontext.Value `json:"aliases"`
	}
	if err := json.Unmarshal(data, &doc, json.RejectUnknownMembers(true)); err != nil {
		return nil, badf("%v", err)
	}
	if doc.Entries == nil {
		return nil, badf("missing or null key %q", "entries")
	}
	switch {
	case doc.Version == snapshotVersion && doc.Aliases != nil:
		return nil, badf("version %d has no key %q", doc.Version, "aliases")
	case doc.Version == aliasesVersion && doc.Aliases.Kind() != '[':
		return nil, badf("aliases: %v", errNotArray)
	}
	entries, err := b.decodeEntries(*doc.Entries)
	if err != nil {
		return nil, badf("entries: %v", err)
	}
	return entries, nil
}

// loadedEntry is a snapshotEntry as Load reads it. A nil field is a key
// that is missing or null.
type loadedEntry struct {
	Policy       *string `json:"policy"`
	Addr         *string `json:"addr"`
	LastSeenNano *int64  `json:"last_seen_unix_nano"`
	TTLNano      *int64  `json:"ttl_nano"`
	ExpiryNano   *int64  `json:"expiry_unix_nano"`
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

func (b *AddrBook) decodeEntries(items []loadedEntry) (map[policy.Name]map[blockable.Addr]*record, error) {
	out := make(map[policy.Name]map[blockable.Addr]*record)
	for i, item := range items {
		name, a, r, err := b.decodeEntry(item)
		if err != nil {
			return nil, fmt.Errorf("item %d: %w", i, err)
		}
		k, ok := blockable.New(a)
		if !ok {
			continue
		}
		if out[name] == nil {
			out[name] = make(map[blockable.Addr]*record)
		}
		if _, dup := out[name][k]; dup {
			return nil, fmt.Errorf("item %d: %w", i, errDuplicate)
		}
		out[name][k] = r
	}
	return out, nil
}

func (b *AddrBook) decodeEntry(e loadedEntry) (policy.Name, netip.Addr, *record, error) {
	for _, f := range []struct {
		key     string
		missing bool
	}{
		{"policy", e.Policy == nil},
		{"addr", e.Addr == nil},
		{"last_seen_unix_nano", e.LastSeenNano == nil},
		{"ttl_nano", e.TTLNano == nil},
		{"expiry_unix_nano", e.ExpiryNano == nil},
	} {
		if f.missing {
			return "", netip.Addr{}, nil, fmt.Errorf("%s: %w", f.key, errMissing)
		}
	}
	seenNano, ttlNano, expNano := *e.LastSeenNano, *e.TTLNano, *e.ExpiryNano
	switch {
	case *e.Policy == "":
		return "", netip.Addr{}, nil, errEmptyName
	case ttlNano < 0:
		return "", netip.Addr{}, nil, ErrNegativeTTL
	case expNano < seenNano:
		return "", netip.Addr{}, nil, errExpiryBeforeSeen
	}
	k, err := parseAddr(*e.Addr)
	if err != nil {
		return "", netip.Addr{}, nil, fmt.Errorf("addr: %w", err)
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
	return policy.Name(*e.Policy), k, r, nil
}
