package pf

import (
	"errors"
	"io/fs"
	"syscall"
	"testing"
	"unsafe"
)

// TestLayout checks the Go structs against the C sizes. An ioctl number
// encodes the size of its C struct (cgo took the numbers from the header),
// so the size in the number must be the size of the Go struct.
func TestLayout(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("the layout is for 64-bit platforms")
	}
	ioctlSize := func(req uint) uintptr { return uintptr(req>>16) & 0x1fff }
	tests := []struct {
		name string
		req  uint
		size uintptr
	}{
		{"DIOCGETSTATUS", diocGetStatus, unsafe.Sizeof(pfStatus{})},
	}
	for _, tt := range tests {
		if got := ioctlSize(tt.req); got != tt.size {
			t.Errorf("%s encodes size %d, Go struct has %d", tt.name, got, tt.size)
		}
	}
}

// TestMapErrno covers the errnos that the e2e tests cannot cause on a
// real kernel.
func TestMapErrno(t *testing.T) {
	tests := []struct {
		err  error
		want error
	}{
		{syscall.ENODEV, ErrLayout},
		{syscall.EPERM, fs.ErrPermission},
		{syscall.EACCES, fs.ErrPermission},
		{fs.ErrClosed, fs.ErrClosed},
	}
	for _, tt := range tests {
		if got := mapErrno(tt.err); !errors.Is(got, tt.want) {
			t.Errorf("mapErrno(%v) = %v, want %v", tt.err, got, tt.want)
		}
	}
	// An errno without a meaning in this package does not become a part
	// of the error contract.
	if got := mapErrno(syscall.ESRCH); errors.Is(got, syscall.ESRCH) {
		t.Errorf("mapErrno(ESRCH) = %v, want an opaque error", got)
	}
}
