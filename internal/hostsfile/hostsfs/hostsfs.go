// Package hostsfs reads the host file from the file system. It is the
// platform side of the host file reader that the daemon gets in its
// configuration. Package hostsfile parses the content.
package hostsfs

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/Nagato-Yuzuru/ifbound/internal/hostsfile"
)

var (
	errNotRegular = errors.New("not a regular file")
	errBadPath    = errors.New("path is not absolute")
)

// Reader reads the host file at Path.
type Reader struct {
	Path string
}

// Version returns the version of the file: its modification time and
// size. A missing file gives the zero Version and no error. A path that
// is empty or not absolute gives an error, so that a Reader that nobody
// set up does not look like a missing file. A file that is not a regular
// file gives an error too: a FIFO or a device can block the open or the
// read, and the caller must not wait.
func (r Reader) Version() (hostsfile.Version, error) {
	if !filepath.IsAbs(r.Path) {
		return hostsfile.Version{}, fmt.Errorf("reading host file %q: %w", r.Path, errBadPath)
	}
	fi, err := os.Stat(r.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return hostsfile.Version{}, nil
	}
	if err != nil {
		return hostsfile.Version{}, fmt.Errorf("reading host file: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return hostsfile.Version{}, fmt.Errorf("reading host file %s: %w", r.Path, errNotRegular)
	}
	return hostsfile.Version{Exists: true, ModNano: fi.ModTime().UnixNano(), Size: fi.Size()}, nil
}

// Read parses the file that Version found as v. A version of a missing
// file gives no entries.
func (r Reader) Read(v hostsfile.Version) (hostsfile.Hosts, error) {
	if !v.Exists {
		return hostsfile.Hosts{}, nil
	}
	f, err := os.Open(r.Path)
	if err != nil {
		// Also ErrNotExist: the file went away after Version. The caller
		// then sees a new version.
		return hostsfile.Hosts{}, fmt.Errorf("reading host file: %w", err)
	}
	defer func() { _ = f.Close() }() //nolint:errcheck // a read-only file has no write to lose
	return hostsfile.Parse(f)
}
