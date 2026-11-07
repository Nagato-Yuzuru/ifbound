package pf

import (
	"net/netip"
	"testing"
)

func TestAddrMask(t *testing.T) {
	tests := []struct {
		prefix string
		addr   []byte
		mask   []byte
	}{
		{"198.51.100.0/24", []byte{198, 51, 100, 0}, []byte{0xff, 0xff, 0xff, 0}},
		{"198.51.100.8/29", []byte{198, 51, 100, 8}, []byte{0xff, 0xff, 0xff, 0xf8}},
		{"0.0.0.0/0", []byte{0, 0, 0, 0}, []byte{0, 0, 0, 0}},
		{"2001:db8::/33", []byte{0x20, 0x01, 0x0d, 0xb8, 0}, []byte{0xff, 0xff, 0xff, 0xff, 0x80, 0}},
	}
	for _, tt := range tests {
		v := addrMask(netip.MustParsePrefix(tt.prefix))
		var addr, mask [16]byte
		copy(addr[:], tt.addr)
		copy(mask[:], tt.mask)
		if [16]byte(v[:16]) != addr || [16]byte(v[16:]) != mask {
			t.Errorf("addrMask(%s) = % x, want address % x and mask % x", tt.prefix, v, addr, mask)
		}
	}
}
