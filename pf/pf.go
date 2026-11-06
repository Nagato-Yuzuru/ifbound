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

// ErrLayout: the kernel does not know the ioctl. The struct layout of
// this package does not agree with the running kernel. Callers can test
// it with errors.Is.
var ErrLayout = errors.New("struct layout does not agree with the kernel")

var errIoctl = errors.New("ioctl failed")

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
		return Status{}, fmt.Errorf("pf: reading status: %w", mapErrno(err))
	}
	return Status{Running: s.Running != 0}, nil
}

// mapErrno turns an error of an ioctl into the errors of this package.
func mapErrno(err error) error {
	errno, ok := errors.AsType[syscall.Errno](err)
	if !ok {
		return err
	}
	if errno == syscall.ENODEV {
		return ErrLayout
	}
	if errno == syscall.EPERM || errno == syscall.EACCES {
		return fmt.Errorf("%w: %v", fs.ErrPermission, errno)
	}
	return fmt.Errorf("%w: %v", errIoctl, errno)
}
