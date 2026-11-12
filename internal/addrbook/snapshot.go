package addrbook

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/blockable"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

// snapshotVersion is the version of the last JSON format. Read also
// reads version 2, which has an "aliases" key next to the entries. Read
// checks the top level of version 2 as strictly as that of version 1:
// the exact key set, and an array as the value of "aliases". It does not
// check the items of that array on purpose: the book does not use them.
const snapshotVersion = 1

// aliasesVersion is the snapshot version with the ignored "aliases" key.
const aliasesVersion = 2

// Errors that Read returns.
var (
	// ErrSnapshot marks a snapshot that exists but is not usable:
	// malformed, an unknown version, or an invalid entry. The book does
	// not start empty in this case. An empty book could unblock addresses
	// that applications still use.
	ErrSnapshot = errors.New("addrbook: bad snapshot")
	// ErrBadPath is the error for a snapshot path that is not a plain
	// file location: a symlink, a non-file, or a missing directory.
	ErrBadPath = errors.New("addrbook: bad snapshot path")
)

var (
	errMissing          = errors.New("missing or null")
	errEmptyName        = errors.New("empty policy name")
	errNegativeTTL      = errors.New("negative ttl")
	errNotCanonical     = errors.New("key is not in canonical form")
	errExpiryBeforeSeen = errors.New("expiry before last_seen")
	errNotArray         = errors.New("not an array")
	errDuplicate        = errors.New("duplicate")
)

// Read returns the entries of the snapshot at path, in the order of the
// file. It returns no entry and a nil error only when the path does not
// exist and its directory does. A symlink, a dangling link, a missing
// directory and every other read error are errors. Read never returns a
// part of a snapshot. It keeps expired entries: the caller decides when
// they leave. It drops an entry with an address that blockable.New
// refuses: an earlier version can have saved it.
func Read(path string) ([]Entry, error) {
	data, missing, err := readRegular(path)
	if err != nil {
		return nil, fmt.Errorf("read addrbook: %w", err)
	}
	if missing {
		return nil, nil
	}
	entries, err := decode(data)
	if err != nil {
		return nil, fmt.Errorf("read addrbook %s: %w", path, err)
	}
	return entries, nil
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
func decode(data []byte) ([]Entry, error) {
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
	entries, err := decodeEntries(*doc.Entries)
	if err != nil {
		return nil, badf("entries: %v", err)
	}
	return entries, nil
}

// loadedEntry is one entry as Read reads it. A nil field is a key that
// is missing or null.
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

type entryKey struct {
	policy policy.Name
	addr   blockable.Addr
}

func decodeEntries(items []loadedEntry) ([]Entry, error) {
	out := make([]Entry, 0, len(items))
	seen := make(map[entryKey]bool, len(items))
	for i, item := range items {
		e, a, err := decodeEntry(item)
		if err != nil {
			return nil, fmt.Errorf("item %d: %w", i, err)
		}
		k, ok := blockable.New(a)
		if !ok {
			continue
		}
		if seen[entryKey{e.Policy, k}] {
			return nil, fmt.Errorf("item %d: %w", i, errDuplicate)
		}
		seen[entryKey{e.Policy, k}] = true
		e.Addr = k
		out = append(out, e)
	}
	return out, nil
}

// decodeEntry returns the entry without its Addr, and the address that
// the caller checks with blockable.New.
func decodeEntry(e loadedEntry) (Entry, netip.Addr, error) {
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
			return Entry{}, netip.Addr{}, fmt.Errorf("%s: %w", f.key, errMissing)
		}
	}
	seenNano, ttlNano, expNano := *e.LastSeenNano, *e.TTLNano, *e.ExpiryNano
	switch {
	case *e.Policy == "":
		return Entry{}, netip.Addr{}, errEmptyName
	case ttlNano < 0:
		return Entry{}, netip.Addr{}, errNegativeTTL
	case expNano < seenNano:
		return Entry{}, netip.Addr{}, errExpiryBeforeSeen
	}
	a, err := parseAddr(*e.Addr)
	if err != nil {
		return Entry{}, netip.Addr{}, fmt.Errorf("addr: %w", err)
	}
	return Entry{
		Policy:   policy.Name(*e.Policy),
		LastSeen: time.Unix(0, seenNano).UTC(),
		TTL:      time.Duration(ttlNano),
		Expiry:   time.Unix(0, expNano).UTC(),
	}, a, nil
}
