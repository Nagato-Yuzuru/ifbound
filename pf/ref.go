package pf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

var errStartRef = errors.New("the kernel returned no token")

// Ref is a reference to pf. While a Ref exists, pf stays enabled.
type Ref struct {
	// Token is the value that StopRef takes.
	Token uint64
	// Created is the time at which the kernel took the reference. The
	// kernel keeps whole seconds.
	Created time.Time
	// PID and Process are the process that took the reference.
	PID     int
	Process string
}

// StartRef takes a reference to pf and returns its token. When pf is
// disabled, it enables pf. It does what "pfctl -E" does. The caller must
// give the reference back with StopRef: pf stays enabled until the last
// reference goes.
func (h *Handle) StartRef() (uint64, error) {
	var token uint64
	if err := h.ioctl(diocStartRef, unsafe.Pointer(&token)); err != nil {
		return 0, fmt.Errorf("pf: taking a reference: %w", mapErrno(err, 0))
	}
	if token == 0 {
		return 0, fmt.Errorf("pf: taking a reference: %w", errStartRef)
	}
	return token, nil
}

// StopRef gives back the reference token. When it is the last reference,
// pf stops. It does what "pfctl -X token" does. The error wraps
// ErrNotFound when the token is not a reference. The kernel gives the same
// answer for a token that never existed, a token that StopRef gave back,
// and a token that "pfctl -d" dropped.
func (h *Handle) StopRef(token uint64) error {
	rt := pfiocRemoveToken{Value: token}
	err := h.ioctl(diocStopRef, unsafe.Pointer(&rt))
	// pf_ioctl.c answers EINVAL for an unknown token. It answers ENOENT
	// when pf is disabled, and then no token is valid.
	if errors.Is(err, syscall.ENOENT) {
		err = syscall.EINVAL
	}
	if err != nil {
		return fmt.Errorf("pf: giving back reference %d: %w", token, mapErrno(err, syscall.EINVAL))
	}
	return nil
}

// Refs returns the references to pf. It does what "pfctl -s References"
// does. The kernel lists the newest reference first.
func (h *Handle) Refs() ([]Ref, error) {
	// The kernel copies at most the bytes of the buffer. A reference
	// that appears between the size query and the read does not fit,
	// so the buffer has one spare slot. A full buffer means that the
	// list can be longer: ask again.
	for {
		n, err := h.refsSize()
		if err != nil {
			return nil, fmt.Errorf("pf: reading references: %w", err)
		}
		if n == 0 {
			return nil, nil
		}
		buf := make([]byte, n+sizeofPfiocToken)
		used, err := h.readRefs(buf)
		if err != nil {
			return nil, fmt.Errorf("pf: reading references: %w", err)
		}
		if used+sizeofPfiocToken <= len(buf) {
			return decodeRefs(buf[:used])
		}
	}
}

// refsSize returns the size in bytes that the list of references needs.
func (h *Handle) refsSize() (int, error) {
	var io pfiocTokens
	if err := h.ioctl(diocGetStarters, unsafe.Pointer(&io)); err != nil {
		return 0, refsErr(err)
	}
	return int(io.Size), nil
}

// readRefs fills buf with the list of references and returns the number
// of bytes that it wrote.
func (h *Handle) readRefs(buf []byte) (int, error) {
	io := pfiocTokens{Size: int32(len(buf))}
	// The union of the struct holds a pointer. The pointer is in a byte
	// array, so KeepAlive holds buf for the GC. Go does not move heap
	// memory.
	binary.NativeEndian.PutUint64(io.U[:], uint64(uintptr(unsafe.Pointer(&buf[0]))))
	err := h.ioctl(diocGetStarters, unsafe.Pointer(&io))
	runtime.KeepAlive(buf)
	if err != nil {
		return 0, refsErr(err)
	}
	return int(io.Size), nil
}

// refsErr turns the error of DIOCGETSTARTERS into an error of this package.
// ENOENT means that the kernel holds no reference. The caller then reads
// the size 0.
func refsErr(err error) error {
	if errors.Is(err, syscall.ENOENT) {
		return nil
	}
	return mapErrno(err, 0)
}

// decodeRefs decodes the struct pfioc_token entries in b.
func decodeRefs(b []byte) ([]Ref, error) {
	if len(b)%sizeofPfiocToken != 0 {
		return nil, fmt.Errorf("%d bytes is not a whole number of entries: %w", len(b), ErrLayout)
	}
	refs := make([]Ref, 0, len(b)/sizeofPfiocToken)
	for ; len(b) > 0; b = b[sizeofPfiocToken:] {
		refs = append(refs, Ref{
			Token:   binary.NativeEndian.Uint64(b),
			Created: time.Unix(int64(binary.NativeEndian.Uint64(b[offTokenTimestamp:])), 0),
			PID:     int(int32(binary.NativeEndian.Uint32(b[offTokenPid:]))),
			Process: cString(b[offTokenProcName : offTokenProcName+tokenProcNameSize]),
		})
	}
	return refs, nil
}
