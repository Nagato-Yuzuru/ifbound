// Package configstore keeps the applied configuration of ifboundd.
//
// The model is the one of crontab and visudo: only "ifbound apply"
// changes the stored file, and only after the new bytes pass Parse and
// the apply checks. So the stored file is always a valid configuration,
// and the daemons can trust it at start.
//
// Load must accept every file that an earlier version stored. A daemon
// that cannot load its configuration at boot leaves the IP and CIDR
// destinations unblocked. So Load runs only policy.Parse. A check that
// protects only availability, such as policy.Config.CheckUpstreams, runs
// in Store, and a later version can make it stricter without a risk to
// the stored file.
package configstore

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/Nagato-Yuzuru/ifbound/internal/layout"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

// Errors that Load and Store return.
var (
	// ErrNotApplied is the error of Load when the directory of the stored
	// configuration exists and the file does not: "ifbound apply" has not
	// run yet.
	ErrNotApplied = errors.New("no applied configuration: run ifbound apply")
	// ErrNotDurable is the error of Store when the new file is in place
	// but the sync of the directory failed. A crash can still bring back
	// the old file. Store then also returns the new configuration and its
	// digest, and the caller must apply them: the file on disk is the new
	// one.
	ErrNotDurable = errors.New("stored configuration is in place but not durable")
)

// errBadFile marks a stored configuration that is not a plain file that
// only its owner can write.
var errBadFile = errors.New("bad stored configuration file")

// tempInfix is in the name of each temporary file of Store.
const tempInfix = ".tmp-"

// Digest is the SHA-256 of the stored bytes. Two processes that load the
// same file get the same Digest, so they can tell that they enforce the
// same configuration.
type Digest [sha256.Size]byte

// String returns the digest in lower-case hex.
func (d Digest) String() string { return hex.EncodeToString(d[:]) }

// Load reads and parses the stored configuration at path. It does not
// run the apply checks.
//
// The error wraps ErrNotApplied only when the directory of path exists
// and path does not. A missing directory is a different error. Load does
// not follow a symlink at path, reads only a regular file, and refuses a
// file that group or others can write. An invalid file gives an error
// that wraps the *policy.FieldError of Parse.
func Load(path string) (policy.Config, Digest, error) {
	data, err := readStored(path)
	if err != nil {
		return policy.Config{}, Digest{}, fmt.Errorf("load config: %w", err)
	}
	cfg, err := policy.ParseBytes(data)
	if err != nil {
		return policy.Config{}, Digest{}, fmt.Errorf("load config %s: %w", path, err)
	}
	return cfg, sha256.Sum256(data), nil
}

// readStored reads the file at path. It opens the file without following
// a symlink, and without waiting when the file is a FIFO, and then checks
// the open file. So the file that it checks is the file that it reads.
func readStored(path string) (data []byte, err error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, notApplied(path)
	case errors.Is(err, syscall.ELOOP):
		return nil, fmt.Errorf("%w: %s is a symlink", errBadFile, path)
	case err != nil:
		return nil, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s is not a regular file", errBadFile, path)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("%w: group or others can write %s (mode %v)", errBadFile, path, fi.Mode().Perm())
	}
	return io.ReadAll(f)
}

// notApplied is the error for a path that does not exist. It is
// ErrNotApplied only when the directory exists.
func notApplied(path string) error {
	dir := filepath.Dir(path)
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", errBadFile, dir)
	}
	return fmt.Errorf("%w: %s", ErrNotApplied, path)
}

// Store checks data and, only when it is valid, replaces the file at
// path with it. The checks are policy.Parse and
// policy.Config.CheckUpstreams. Store removes the temporary files of
// earlier crashed calls, writes a new temporary file in the same
// directory, gives it group gid and mode layout.StoredConfigMode, syncs
// it, renames it over path, and syncs the directory. A crash leaves the
// old file or the new one at path. It can also leave a temporary file,
// which the next Store removes. A negative gid keeps the group of the
// new file, for tests. Store is not safe for concurrent calls on one
// path: each call removes the temporary files of the others.
//
// Invalid data returns an error that wraps the *policy.FieldError of the
// check, and Store does not change the directory. An error that wraps
// ErrNotDurable comes after the rename: see ErrNotDurable. Every other
// error leaves the old file at path.
func Store(path string, data []byte, gid int) (policy.Config, Digest, error) {
	return store(path, data, gid, os.Rename)
}

// store is Store with the rename as a parameter, so that a test can fail
// the step between the temporary file and the rename.
func store(path string, data []byte, gid int, rename func(oldpath, newpath string) error) (policy.Config, Digest, error) {
	cfg, err := policy.ParseBytes(data)
	if err == nil {
		err = cfg.CheckUpstreams()
	}
	if err != nil {
		return policy.Config{}, Digest{}, fmt.Errorf("store config: %w", err)
	}
	dir := filepath.Dir(path)
	if err := removeTemps(path); err != nil {
		return policy.Config{}, Digest{}, fmt.Errorf("store config: %w", err)
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+tempInfix+"*")
	if err != nil {
		return policy.Config{}, Digest{}, fmt.Errorf("store config: %w", err)
	}
	if err := writeFile(tmp, data, gid); err != nil {
		_ = os.Remove(tmp.Name()) //nolint:errcheck // best-effort cleanup; the next Store removes leftover temp files
		return policy.Config{}, Digest{}, fmt.Errorf("store config: %w", err)
	}
	if err := rename(tmp.Name(), path); err != nil {
		_ = os.Remove(tmp.Name()) //nolint:errcheck // best-effort cleanup; the next Store removes leftover temp files
		return policy.Config{}, Digest{}, fmt.Errorf("store config: %w", err)
	}
	digest := Digest(sha256.Sum256(data))
	if err := syncDir(dir); err != nil {
		return cfg, digest, fmt.Errorf("store config: %w: %w", ErrNotDurable, err)
	}
	return cfg, digest, nil
}

// removeTemps deletes the temporary files that an earlier crashed Store
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

// writeFile writes data to f, sets the group and the mode, syncs f, and
// closes it. It sets the group before the mode, so the group bits never
// apply to a wrong group. The sync comes last, so it also makes the group
// and the mode durable before the rename.
func writeFile(f *os.File, data []byte, gid int) error {
	_, err := f.Write(data)
	if err == nil && gid >= 0 {
		err = f.Chown(-1, gid)
	}
	if err == nil {
		err = f.Chmod(layout.StoredConfigMode)
	}
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
