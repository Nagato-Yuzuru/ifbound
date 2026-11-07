package pf

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// Open opens /dev/pf for reading and writing. Most ioctls need root.
func Open() (*Handle, error) {
	f, err := os.OpenFile("/dev/pf", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("pf: %w", err)
	}
	return &Handle{f: f}, nil
}

// ioctl runs the ioctl req on the device with the argument arg. The
// returned error is a syscall.Errno, or an error of os.File when the
// Handle is closed.
func (h *Handle) ioctl(req uint, arg unsafe.Pointer) error {
	rc, err := h.f.SyscallConn()
	if err != nil {
		return err
	}
	var errno syscall.Errno
	// Control keeps the file descriptor open until the call returns.
	if err := rc.Control(func(fd uintptr) { errno = ioctl(fd, req, arg) }); err != nil {
		return err
	}
	if errno != 0 {
		return errno
	}
	return nil
}

// ioctl calls ioctl(2) in libc through the trampoline in the assembly
// file, as golang.org/x/sys/unix does. syscall.Syscall would use the libc
// function syscall(2), which Apple deprecated.
func ioctl(fd uintptr, req uint, arg unsafe.Pointer) syscall.Errno {
	_, _, errno := syscallSyscall(libcIoctlTrampolineAddr, fd, uintptr(req), uintptr(arg))
	return errno
}

// syscallSyscall is syscall.syscall of the runtime. The runtime keeps the
// link name for golang.org/x/sys/unix, which calls libc the same way.
//
//go:linkname syscallSyscall syscall.syscall
func syscallSyscall(fn, a1, a2, a3 uintptr) (r1, r2 uintptr, err syscall.Errno)

// libcIoctlTrampolineAddr is the address of the trampoline. The assembly
// file sets it.
//
//nolint:gochecknoglobals // set by the assembly file, read only
var libcIoctlTrampolineAddr uintptr

//go:cgo_import_dynamic libc_ioctl ioctl "/usr/lib/libSystem.B.dylib"
