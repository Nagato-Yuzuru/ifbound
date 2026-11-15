// Package enforcementlock takes the exclusive lock files of ifbound. It is
// the only package that calls flock. The enforcement writer lock
// (layout.EnforcementLock) is one user. The ipc socket lock and the
// address book lock are the others.
//
// The lock is an exclusive flock on a lock file. The kernel releases it
// when the process exits, also after a crash, so a stale lock file does
// not block the next process. The lock file stays on disk.
package enforcementlock

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// fileMode is the mode of a new lock file.
const fileMode = 0o600

// openFlags make one atomic open. O_NOFOLLOW makes the open fail with
// ELOOP when the last element is a symbolic link, also a dangling one, so
// O_CREATE never creates the target of a link.
const openFlags = unix.O_RDWR | unix.O_CREAT | unix.O_NOFOLLOW | unix.O_CLOEXEC

// ErrHeld means that another holder has the lock.
var ErrHeld = errors.New("another process holds the lock")

// ErrSymlink means that the lock path is a symbolic link.
var ErrSymlink = errors.New("lock file is a symbolic link")

// ErrName means that AcquireIn got a name that is not one file name.
var ErrName = errors.New("lock name is not one file name")

// Lock is a held lock. Build one with Acquire.
type Lock struct{ f *os.File }

// Acquire takes the lock at path. It does not wait: when another holder
// has the lock, it returns an error that wraps ErrHeld at once. A flock
// belongs to the open file, so a second Acquire in the same process also
// gets ErrHeld.
//
// Acquire does not follow a symbolic link at path: it returns an error
// that wraps ErrSymlink. The directory of the lock can be writable by
// others (/var/run is not, but a test directory can be), and a link there
// must not make root create or lock another file.
func Acquire(path string) (*Lock, error) {
	return acquireAt(unix.AT_FDCWD, path)
}

// AcquireIn takes the lock at name inside root, with the same rules as
// Acquire. name is one file name, with no separator: a longer path could
// pass through a link. The open is relative to root, so it stays inside
// the directory.
func AcquireIn(root *os.Root, name string) (*Lock, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsRune(name, '/') {
		return nil, fmt.Errorf("%w: %q", ErrName, name)
	}
	dir, err := root.Open(".")
	if err != nil {
		return nil, fmt.Errorf("opening the directory of lock file %s: %w", name, err)
	}
	defer dir.Close() //nolint:errcheck // a read-only handle
	return acquireAt(int(dir.Fd()), name)
}

// acquireAt opens name relative to dirfd and takes the flock on it.
func acquireAt(dirfd int, name string) (*Lock, error) {
	var fd int
	var err error
	for {
		fd, err = unix.Openat(dirfd, name, openFlags, fileMode)
		if !errors.Is(err, unix.EINTR) {
			break
		}
	}
	switch {
	case errors.Is(err, unix.ELOOP):
		return nil, fmt.Errorf("%w: %s", ErrSymlink, name)
	case err != nil:
		return nil, fmt.Errorf("opening lock file %s: %w", name, err)
	}
	return lock(os.NewFile(uintptr(fd), name), name)
}

// lock takes the flock on f. On failure it closes f.
func lock(f *os.File, name string) (*Lock, error) {
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close() //nolint:errcheck // the lock error is the one to report
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("%w: %s", ErrHeld, name)
		}
		return nil, fmt.Errorf("locking %s: %w", name, err)
	}
	return &Lock{f: f}, nil
}

// Close releases the lock.
func (l *Lock) Close() error {
	return l.f.Close()
}
