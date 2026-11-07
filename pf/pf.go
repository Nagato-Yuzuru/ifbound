package pf

//go:generate sh -c "go tool cgo -godefs -- -DPRIVATE -Ixnu defs.go | gofmt > zdefs.go && rm -rf _obj"
//go:generate sh -c "GOARCH=amd64 go tool cgo -godefs -- -DPRIVATE -Ixnu defs.go | gofmt | cmp - zdefs.go && rm -rf _obj"

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
	"unsafe"
)

// Errors that callers can test with errors.Is.
var (
	// ErrNotFound: the table or the anchor does not exist.
	ErrNotFound = errors.New("not found")
	// ErrChanged: the ruleset changed while Handle.Rules read it.
	ErrChanged = errors.New("ruleset changed during the read")
	// ErrLayout: the kernel does not know the ioctl. The struct layout of
	// this package does not agree with the running kernel.
	ErrLayout = errors.New("struct layout does not agree with the kernel")
)

var (
	errName  = errors.New("name is too long or holds a NUL byte")
	errIoctl = errors.New("ioctl failed")
)

// Handle is an open /dev/pf. Its methods are safe for concurrent use.
type Handle struct {
	f *os.File
}

// Close closes the device.
func (h *Handle) Close() error {
	return h.f.Close()
}

// Status is the state of pf.
type Status struct {
	// Running is true when pf is enabled.
	Running bool
}

// Status returns the state of pf.
func (h *Handle) Status() (Status, error) {
	var s pfStatus
	if err := h.ioctl(diocGetStatus, unsafe.Pointer(&s)); err != nil {
		return Status{}, fmt.Errorf("pf: reading status: %w", mapErrno(err, 0))
	}
	return Status{Running: s.Running != 0}, nil
}

// setName copies s into the C char array dst. It leaves room for the NUL.
func setName[T int8 | byte](dst []T, s string) error {
	if len(s) >= len(dst) {
		return errName
	}
	for i := range len(s) {
		if s[i] == 0 {
			return errName
		}
		dst[i] = T(s[i])
	}
	clear(dst[len(s):])
	return nil
}

// cString returns the text of the C char array b up to the first NUL.
func cString[T int8 | byte](b []T) string {
	s := make([]byte, 0, len(b))
	for _, c := range b {
		if c == 0 {
			break
		}
		s = append(s, byte(c))
	}
	return string(s)
}

// mapErrno turns an error of an ioctl into the errors of this package.
// notFound is the errno that means a missing table or anchor for this
// ioctl, or 0.
func mapErrno(err error, notFound syscall.Errno) error {
	errno, ok := errors.AsType[syscall.Errno](err)
	if !ok {
		return err
	}
	switch {
	case notFound != 0 && errno == notFound:
		return ErrNotFound
	case errno == syscall.EBUSY:
		return ErrChanged
	case errno == syscall.ENODEV:
		return ErrLayout
	case errno == syscall.EPERM, errno == syscall.EACCES:
		return fmt.Errorf("%w: %v", fs.ErrPermission, errno)
	default:
		return fmt.Errorf("%w: %v", errIoctl, errno)
	}
}
