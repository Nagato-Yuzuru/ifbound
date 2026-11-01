// Package enforcementlock takes the writer lock of the enforcement: the
// lock that a process holds while it writes the pf anchor and the
// resolver entries. On the host the lock is layout.EnforcementLock.
//
// The lock is an exclusive flock on a lock file. The kernel releases it
// when the process exits, also after a crash, so a stale lock file does
// not block the next process. The lock file stays on disk.
package enforcementlock

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

const fileMode = 0o600

// ErrHeld means that another holder has the lock.
var ErrHeld = errors.New("another process holds the enforcement lock")

// Lock is a held lock. Build one with Acquire.
type Lock struct{ f *os.File }

// Acquire takes the lock at path. It does not wait: when another holder
// has the lock, it returns an error that wraps ErrHeld at once. A flock
// belongs to the open file, so a second Acquire in the same process also
// gets ErrHeld.
//
// Acquire does not follow a symbolic link at path. The directory of the
// lock can be writable by others (/var/run is not, but a test directory
// can be), and a link there must not make root create or lock another
// file.
func Acquire(path string) (*Lock, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|unix.O_NOFOLLOW, fileMode)
	if err != nil {
		return nil, fmt.Errorf("opening lock file %s: %w", path, err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close() //nolint:errcheck // the lock error is the one to report
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("%w: %s", ErrHeld, path)
		}
		return nil, fmt.Errorf("locking %s: %w", path, err)
	}
	return &Lock{f: f}, nil
}

// Close releases the lock.
func (l *Lock) Close() error {
	return l.f.Close()
}
