//go:build !darwin

package pf

import (
	"errors"
	"fmt"
	"unsafe"
)

// Open returns an error that wraps errors.ErrUnsupported: the package
// supports only macOS.
func Open() (*Handle, error) {
	return nil, fmt.Errorf("pf: %w", errors.ErrUnsupported)
}

func (h *Handle) ioctl(uint, unsafe.Pointer) error {
	return errors.ErrUnsupported
}
