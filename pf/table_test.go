package pf

import (
	"errors"
	"net/netip"
	"testing"
)

func TestAddrEncode(t *testing.T) {
	var raw pfrAddr
	a := Addr{Prefix: netip.MustParsePrefix("198.51.100.9/24"), Negated: true}
	if err := a.encode(&raw); err != nil {
		t.Fatal(err)
	}
	want := pfrAddr{U: [16]byte{198, 51, 100, 0}, Af: afInet, Net: 24, Not: 1}
	if raw != want {
		t.Errorf("encode(%v) = %+v, want %+v (the host bits are cleared)", a, raw, want)
	}
	if err := (Addr{}).encode(&raw); !errors.Is(err, errPrefix) {
		t.Errorf("encode of the zero Addr: got %v, want errPrefix", err)
	}
}

func TestDecodeAddrRejects(t *testing.T) {
	for _, raw := range []pfrAddr{
		{Af: 0},
		{Af: afInet, Net: 33},
		{Af: afInet6, Net: 129},
	} {
		if _, err := decodeAddr(&raw); !errors.Is(err, errPrefix) {
			t.Errorf("decode(%+v): got %v, want errPrefix", raw, err)
		}
	}
}

func TestTableEncodeRejectsEmptyName(t *testing.T) {
	var raw pfrTable
	if err := (Table{Anchor: "a"}).encode(&raw); !errors.Is(err, errName) {
		t.Errorf("got %v, want errName", err)
	}
}
