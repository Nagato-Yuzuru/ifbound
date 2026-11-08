package addrbook_test

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

// TestSaveGolden records the exact bytes that Save writes. Load of an
// older or newer ifboundd reads these bytes, so a change here is a format
// change. Make it on purpose only.
func TestSaveGolden(t *testing.T) {
	type obs struct {
		name policy.Name
		ttl  time.Duration
		addr netip.Addr
	}
	tests := []struct {
		name string
		obs  []obs
		want string
	}{
		{
			name: "empty",
			want: `{"version":1,"entries":[]}`,
		},
		{
			name: "entries",
			obs:  []obs{{"web", time.Minute, a1}, {"ads", 30 * 24 * time.Hour, a2}},
			want: `{"version":1,"entries":[` +
				`{"policy":"ads","addr":"2001:db8::1","last_seen_unix_nano":1767225600000000000,"ttl_nano":2592000000000000,"expiry_unix_nano":1769817600000000000},` +
				`{"policy":"web","addr":"192.0.2.1","last_seen_unix_nano":1767225600000000000,"ttl_nano":60000000000,"expiry_unix_nano":1767830400000000000}` +
				`]}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, _ := newBook(t)
			for _, o := range tt.obs {
				observe(t, b, o.name, o.ttl, o.addr)
			}
			path := filepath.Join(t.TempDir(), "book.json")
			save(t, b, path)
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want {
				t.Errorf("snapshot\n got %s\nwant %s", got, tt.want)
			}
		})
	}
}
