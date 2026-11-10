package addrbook

import (
	"bytes"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/blockable"
)

func zeroBook(t *testing.T) (*AddrBook, blockable.Addr) {
	t.Helper()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	b := New(time.Hour, func() time.Time { return now })
	good, ok := blockable.New(netip.MustParseAddr("192.0.2.1"))
	if !ok {
		t.Fatal("blockable.New refused 192.0.2.1")
	}
	if _, err := b.Observe("web", []blockable.Addr{good}, 0); err != nil {
		t.Fatal(err)
	}
	return b, good
}

// The zero Addr comes from a bug upstream. Observe refuses the whole
// call, so the book does not get the valid address next to it either.
func TestObserveRefusesZeroAddr(t *testing.T) {
	b, good := zeroBook(t)
	other, _ := blockable.New(netip.MustParseAddr("192.0.2.2"))

	_, err := b.Observe("web", []blockable.Addr{other, {}}, time.Minute)

	if !errors.Is(err, blockable.ErrZero) {
		t.Fatalf("Observe(zero Addr) = %v, want ErrZero", err)
	}
	if got := b.Addrs("web"); !slices.Equal(got, []blockable.Addr{good}) {
		t.Errorf("web = %v, want [%v]", got, good)
	}
	if r := b.entries["web"][good]; r.ttl != 0 {
		t.Errorf("ttl of %v = %v, want 0: the refused call changed it", good, r.ttl)
	}
}

// Save never writes an empty address: the next Load would fail, and the
// daemon would not start. It refuses before it touches the file.
func TestSaveRefusesZeroAddr(t *testing.T) {
	b, good := zeroBook(t)
	path := filepath.Join(t.TempDir(), "book.json")
	if err := b.Save(path); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	r := *b.entries["web"][good]
	b.entries["web"][blockable.Addr{}] = &r

	err = b.Save(path)

	if !errors.Is(err, blockable.ErrZero) {
		t.Fatalf("Save(zero Addr) = %v, want ErrZero", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("snapshot = %s, want the old one %s", after, before)
	}
	temps, err := filepath.Glob(path + tempInfix + "*")
	if err != nil {
		t.Fatal(err)
	}
	if len(temps) != 0 {
		t.Errorf("temporary files next to the snapshot: %v", temps)
	}
}
