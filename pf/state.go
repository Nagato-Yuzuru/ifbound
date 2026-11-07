package pf

import (
	"fmt"
	"net/netip"
	"unsafe"
)

// KillStates ends every state whose destination is in dst, from any
// source. It does what "pfctl -k 0.0.0.0/0 -k dst" does (with ::/0 for an
// IPv6 dst).
func (h *Handle) KillStates(dst netip.Prefix) error {
	if !dst.IsValid() {
		return fmt.Errorf("pf: ending states to %s: %w", dst, errPrefix)
	}
	var k pfiocStateKill
	dst = dst.Masked()
	k.Af = afOf(dst.Addr())
	k.Dst.Addr.V = addrMask(dst)
	if err := h.ioctl(diocKillStates, unsafe.Pointer(&k)); err != nil {
		return fmt.Errorf("pf: ending states to %s: %w", dst, mapErrno(err, 0))
	}
	return nil
}

// addrMask returns the address and the mask of p in the layout of the
// union of struct pf_addr_wrap: a 16-byte address, then a 16-byte mask.
func addrMask(p netip.Prefix) [32]byte {
	var v [32]byte
	a := p.Addr().AsSlice()
	copy(v[:16], a)
	bits := p.Bits()
	for i := 16; bits > 0; i++ {
		n := min(bits, 8)
		v[i] = byte(0xff << (8 - n))
		bits -= n
	}
	return v
}
