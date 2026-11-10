package addrbook_test

import (
	"fmt"
	"os"
	"testing"
	"time"
)

// An earlier ifboundd can have saved a loopback or unspecified address.
// Load drops such an entry, so the book does not count it and the next
// Save does not write it again. The other entries stay.
func TestLoadDropsRefusedAddress(t *testing.T) {
	path := snapPath(t)
	entry := func(policy, addr string) string {
		return fmt.Sprintf(`{"policy":%q,"addr":%q,"last_seen_unix_nano":%d,"ttl_nano":0,"expiry_unix_nano":%d}`,
			policy, addr, ns(0), ns(time.Hour))
	}
	doc := `{"version":1,"entries":[` + entry("web", "127.0.0.1") + "," + entry("web", "192.0.2.1") + "," +
		entry("web", "0.0.0.0") + "," + entry("ads", "::1") + "," + entry("ads", "::") + `]}`
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}

	b := hourBook(genT0)
	if err := b.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}

	if got := fmt.Sprint(b.Addrs("web")); got != "[192.0.2.1]" {
		t.Errorf("web = %s, want [192.0.2.1]", got)
	}
	if n := b.Len("ads"); n != 0 {
		t.Errorf("ads has %d addresses, want 0", n)
	}
	save(t, b, path)
	_, saved := readSaved(t, path)
	if len(saved) != 1 || saved[0].Addr != "192.0.2.1" {
		t.Errorf("saved entries = %v, want only web 192.0.2.1", saved)
	}
}
