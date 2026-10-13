// Package macresolver manages the resolver entries of ifbound on macOS.
// Each entry is one file in /etc/resolver, named after its domain. The
// package implements reconcile.SysResolver.
//
// Every file that ifbound writes starts with the Marker line. The package
// changes or removes only files that start with that line. A file without
// it for a domain that ifbound wants is a conflict: Write refuses it with
// ErrConflict and does not change the file.
//
// macOS applies a new or changed file after a delay. Read reports an
// entry as active when Settle has passed since the modification time of
// its file, the file is exactly what Write renders, the system resolver
// configuration lists the file, and no other resolver for the same domain
// can win against it. The time is in the file, not in memory, so a daemon
// that restarts does not report a new entry as active too early.
//
// Read also reads the resolver configuration of the system and reports
// each resolver that is at or below an ifbound entry but is not an
// ifbound file. The most specific resolver domain wins on macOS, so such a
// resolver takes names from the ifbound entry.
//
// The directory, the clock, and the source of the resolver configuration
// are parameters, so the logic runs without root on any system.
package macresolver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
)

const (
	// Dir is the directory of the per-domain resolver files on macOS.
	Dir = "/etc/resolver"
	// Settle is the time from a write until Read reports the entry as
	// active. The slowest measured application of a new file took 1.55 s.
	Settle = 2 * time.Second
	// Marker is the first line of each file that ifbound writes. It is a
	// comment for the resolver file parser of macOS.
	Marker = "# Managed by ifboundd. Do not edit: ifboundd changes or removes this file."
)

// Errors of Write and Remove.
var (
	// ErrCannotWrite means that the system refused to change the resolver
	// directory: no permission (EACCES, EPERM), a read-only file system
	// (EROFS), or a missing path (ENOENT).
	ErrCannotWrite = errors.New("cannot write the resolver directory")
	// ErrConflict means that a resolver file for the domain exists and
	// ifbound does not manage it: its first line is not the Marker line,
	// or it is not a regular file. Write did not change the file.
	ErrConflict = errors.New("a resolver file that ifbound does not manage exists for the domain")
)

var (
	errInvalidEntry = errors.New("invalid resolver entry")
	errFile         = errors.New("resolver file operation failed")
	errRead         = errors.New("cannot read the resolver directory")
)

const (
	// tempPrefix starts the name of a temporary file. A leading dot makes
	// the name an invalid domain, so Read never takes it for an entry.
	tempPrefix = ".ifbound-tmp-"
	fileMode   = 0o644
	dirMode    = 0o755
	dnsPort    = 53
)

// Resolver manages the resolver files of ifbound in one directory. It is
// not safe for concurrent use. Build one with New.
type Resolver struct {
	dir    string
	now    func() time.Time
	config ConfigSource
	// writes counts the Writes that changed the file of each domain. It
	// is part of the version, because a file system can give a new file
	// the inode number of a file that was just removed (ext4 does), and
	// two Writes in one clock tick then give the same file identity.
	writes map[policy.Domain]uint64
}

var _ reconcile.SysResolver = (*Resolver)(nil)

// New returns a Resolver for the files in dir (Dir on macOS). Now is the
// clock: Write sets it as the modification time of a file, and Read
// compares it with that time. Config gives the system resolver
// configuration (Scutil on macOS).
func New(dir string, now func() time.Time, config ConfigSource) *Resolver {
	return &Resolver{dir: dir, now: now, config: config, writes: make(map[policy.Domain]uint64)}
}

// Read implements reconcile.SysResolver. It reports each file that starts
// with the Marker line and whose name is a domain. Server is the zero
// AddrPort when the file is not exactly what Write renders, so the next
// Write repairs the file.
//
// When there is at least one entry, Read also reads the system resolver
// configuration. For each resolver at or below an entry that is not the
// file of an entry, it reports a Problem and lists the domain in
// Shadowed. Read compares the configuration with all entries at once, so
// the file of an alias entry below an apex entry is never foreign. When
// the configuration cannot be read, Read reports that as a Problem and
// still returns the entries.
//
// An entry is active only when all of these are true:
//   - Settle has passed since the modification time of its file;
//   - the file is exactly what Write renders (Server is valid);
//   - the configuration lists the file with the server of the entry;
//   - no other resolver for the domain has an order that is equal to or
//     lower than the order of the file.
//
// Read reports a resolver at or below an entry only from the second
// convergence that sees the entry: the Reconciler reads before it
// writes, and Read compares the configuration only with the files that
// exist. A more specific resolver that exists before ifbound writes the
// entry is thus reported one convergence later.
func (r *Resolver) Read(ctx context.Context) (reconcile.ResolverState, error) {
	entries, err := r.managed()
	if err != nil {
		return reconcile.ResolverState{}, err
	}
	st := reconcile.ResolverState{Entries: entries}
	if len(entries) == 0 {
		return st, nil
	}
	conf, err := r.config.Resolvers(ctx)
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return reconcile.ResolverState{}, fmt.Errorf("reading the resolver configuration: %w", cerr)
		}
		for i := range st.Entries {
			st.Entries[i].Active = false
		}
		st.Problems = []reconcile.Problem{{Text: "cannot read the system resolver configuration: " + err.Error()}}
		return st, nil
	}
	f := examine(entries, conf)
	for i, e := range st.Entries {
		d := e.Domain.String()
		if _, listed := f.own[d]; !listed || f.contested[d] {
			st.Entries[i].Active = false
		}
	}
	for _, t := range f.texts {
		st.Problems = append(st.Problems, reconcile.Problem{Text: t})
	}
	st.Shadowed = f.shadowed
	return st, nil
}

// Write implements reconcile.SysResolver. It renders the file from e and
// writes a temporary file in the same directory. It renames the temporary
// file over an ifbound file, or links it to the name when no file exists,
// so a file that appears in the meantime is not replaced. It creates the
// directory when it is missing. When the file already holds the rendered
// content, Write does not change the file: the modification time stays,
// so the entry stays active.
//
// The error wraps ErrConflict or ErrCannotWrite when that is the cause.
func (r *Resolver) Write(_ context.Context, e reconcile.ResolverEntry) error {
	data, err := render(e)
	if err != nil {
		return err
	}
	path := filepath.Join(r.dir, e.Domain.String())
	old, exists, err := managedFile(path)
	if err != nil {
		return fmt.Errorf("writing resolver entry %s: %w", e.Domain, err)
	}
	if exists && bytes.Equal(old, data) {
		return nil
	}
	if err := r.replace(path, data, exists); err != nil {
		return fmt.Errorf("writing resolver entry %s: %w", e.Domain, err)
	}
	r.writes[e.Domain]++
	return nil
}

// Remove implements reconcile.SysResolver. It deletes the file of the
// domain only when the file starts with the Marker line. A missing file
// or a file that ifbound does not manage is not an error: no ifbound
// entry exists.
//
// The error wraps ErrCannotWrite when that is the cause.
func (r *Resolver) Remove(_ context.Context, d policy.Domain) error {
	if d.String() == "" {
		return fmt.Errorf("%w: empty domain", errInvalidEntry)
	}
	path := filepath.Join(r.dir, d.String())
	_, ok, err := managedFile(path)
	if errors.Is(err, ErrConflict) || (err == nil && !ok) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("removing resolver entry %s: %w", d, err)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("removing resolver entry %s: %w", d, classify(err))
	}
	return nil
}

// managed returns the entries in the directory, sorted by domain. Active
// here depends only on the file; Read also checks the configuration.
func (r *Resolver) managed() ([]reconcile.ManagedEntry, error) {
	des, err := os.ReadDir(r.dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errRead, err)
	}
	now := r.now()
	var out []reconcile.ManagedEntry
	for _, de := range des {
		d, err := policy.ParseDomain(de.Name())
		if err != nil || d.String() != de.Name() || !de.Type().IsRegular() {
			continue
		}
		path := filepath.Join(r.dir, de.Name())
		data, err := os.ReadFile(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %v", errRead, err)
		}
		if !hasMarker(data) {
			continue
		}
		fi, err := os.Lstat(path)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", errRead, err)
		}
		server := parseServer(d, data)
		out = append(out, reconcile.ManagedEntry{
			Domain:  d,
			Server:  server,
			Active:  server.IsValid() && !now.Before(fi.ModTime().Add(Settle)),
			Version: fileVersion(r.writes[d], fi),
		})
	}
	return out, nil
}

// fileVersion returns the version of an entry: the number of Writes of
// this Resolver that changed the file, then the identity of the file
// content (device, inode, modification time in nanoseconds, and size).
// The count makes each Write of ifbound give a new version, also when the
// file system reuses the inode number in the same clock tick. A rename of
// a new file by another process gives a new inode, and a write in place
// gives a new modification time. The count starts again in a new
// process, so a version can come back only across a restart of ifboundd.
// It is "" when the file information has no inode.
func fileVersion(writes uint64, fi fs.FileInfo) string {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	return fmt.Sprintf("%d:%d:%d:%d:%d", writes, st.Dev, st.Ino, fi.ModTime().UnixNano(), fi.Size())
}

// managedFile reads the file at path. It returns ok == false when no file
// exists, and an error that wraps ErrConflict when the file is not one
// that ifbound manages.
func managedFile(path string) (data []byte, ok bool, err error) {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, classify(err)
	}
	if !fi.Mode().IsRegular() {
		return nil, false, fmt.Errorf("%w: %s is not a regular file", ErrConflict, path)
	}
	data, err = os.ReadFile(path)
	if err != nil {
		return nil, false, classify(err)
	}
	if !hasMarker(data) {
		return nil, false, fmt.Errorf("%w: %s does not start with the ifbound marker", ErrConflict, path)
	}
	return data, true, nil
}

// replace puts data at path, so the system never reads a part of the
// file. Over an existing ifbound file it renames. For a new file it makes
// a hard link, which fails when a file appeared at path after the check:
// another tool then owns that file.
func (r *Resolver) replace(path string, data []byte, exists bool) error {
	if err := os.Mkdir(r.dir, dirMode); err != nil && !errors.Is(err, fs.ErrExist) {
		return classify(err)
	}
	if err := removeTemps(r.dir); err != nil {
		return classify(err)
	}
	tmp, err := os.CreateTemp(r.dir, tempPrefix+"*")
	if err != nil {
		return classify(err)
	}
	if err := r.fill(tmp, data); err != nil {
		_ = os.Remove(tmp.Name()) // the write error below is the cause; a left file is removed by the next write
		return classify(err)
	}
	if exists {
		err = os.Rename(tmp.Name(), path)
	} else {
		err = os.Link(tmp.Name(), path)
	}
	_ = os.Remove(tmp.Name()) // after a rename it is gone; after a link the name at path keeps the file; a left file is removed by the next write
	if errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("%w: %s appeared during the write", ErrConflict, path)
	}
	if err != nil {
		return classify(err)
	}
	return nil
}

// fill writes, syncs, and closes f, and then sets its modification time
// to the clock. The sync comes before the rename, so a crash cannot leave
// an empty file without the marker, which Read would take for a conflict.
func (r *Resolver) fill(f *os.File, data []byte) error {
	_, err := f.Write(data)
	if err == nil {
		err = f.Chmod(fileMode)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	now := r.now()
	return os.Chtimes(f.Name(), now, now)
}

// removeTemps deletes the temporary files that an interrupted write left.
// Only one Resolver writes the directory, so each such file is stale.
func removeTemps(dir string) error {
	des, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, de := range des {
		if !de.Type().IsRegular() || !strings.HasPrefix(de.Name(), tempPrefix) {
			continue
		}
		if err := os.Remove(filepath.Join(dir, de.Name())); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

// classify maps a file system error to the error vocabulary of the
// package. The foreign cause stays in the text only.
func classify(err error) error {
	if errors.Is(err, fs.ErrPermission) || errors.Is(err, syscall.EROFS) || errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: %v", ErrCannotWrite, err)
	}
	return fmt.Errorf("%w: %v", errFile, err)
}

// render returns the file content for e. It builds the text only from the
// typed values, because macOS does not refuse a file with a syntax error:
// it lists the entry, but never applies it. It refuses only an entry that
// it cannot write as a valid file. It does not check that the server can
// answer: the configuration layer accepts only a unicast listen address,
// and that address is the server of every entry.
func render(e reconcile.ResolverEntry) ([]byte, error) {
	a := e.Server.Addr()
	if e.Domain.String() == "" || !a.IsValid() || a.Zone() != "" || e.Server.Port() == 0 {
		return nil, fmt.Errorf("%w: domain %q, server %s", errInvalidEntry, e.Domain, e.Server)
	}
	return fmt.Appendf(nil, "%s\nnameserver %s\nport %d\n", Marker, a, e.Server.Port()), nil
}

// hasMarker reports whether the first line of data is the Marker line.
func hasMarker(data []byte) bool {
	first, _, _ := bytes.Cut(data, []byte("\n"))
	return string(first) == Marker
}

// parseServer returns the server of an ifbound file, or the zero AddrPort
// when data is not exactly what render gives for that server.
func parseServer(d policy.Domain, data []byte) netip.AddrPort {
	var addr netip.Addr
	port := uint64(dnsPort)
	for line := range strings.Lines(string(data)) {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		switch f[0] {
		case "nameserver":
			addr, _ = netip.ParseAddr(f[1]) // an invalid address fails the render check below
		case "port":
			port, _ = strconv.ParseUint(f[1], 10, 16) // an invalid port fails the render check below
		}
	}
	s := netip.AddrPortFrom(addr, uint16(port))
	want, err := render(reconcile.ResolverEntry{Domain: d, Server: s})
	if err != nil || !bytes.Equal(want, data) {
		return netip.AddrPort{}
	}
	return s
}
