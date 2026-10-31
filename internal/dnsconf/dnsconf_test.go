package dnsconf

import (
	"errors"
	"flag"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/coredns/caddy/caddyfile"

	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

var update = flag.Bool("update", false, "rewrite the golden files")

func up(addr, name string) policy.Upstream {
	d, err := policy.ParseDomain(name)
	if err != nil {
		panic(err) // a test literal
	}
	return policy.Upstream{Addr: netip.MustParseAddrPort(addr), ServerName: d}
}

func mustNew(t *testing.T, socket, ca string) Renderer {
	t.Helper()
	r, err := New(socket, ca)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestCorefileGolden(t *testing.T) {
	tests := []struct {
		name string
		dns  policy.DNS
		ca   string
	}{
		{"two_upstreams", policy.DNS{
			Listen:   netip.MustParseAddrPort("127.0.0.1:10053"),
			Upstream: []policy.Upstream{up("9.9.9.9:853", "dns.quad9.net"), up("[2606:4700:4700::1111]:853", "one.one.one.one")},
		}, ""},
		{"ipv6_listen_test_ca", policy.DNS{
			Listen:   netip.MustParseAddrPort("[::1]:5353"),
			Upstream: []policy.Upstream{up("127.0.0.1:8853", "dot.test")},
		}, "/tmp/ca.pem"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mustNew(t, "/var/run/ifbound/report.sock", tt.ca).Corefile(tt.dns)
			path := filepath.Join("testdata", tt.name+".golden")
			if *update {
				if err := os.WriteFile(path, got, 0o644); err != nil { //nolint:gosec // golden file, not a secret
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != string(want) {
				t.Errorf("Corefile:\n%s\nwant:\n%s", got, want)
			}
		})
	}
}

// parse reads a Corefile the way CoreDNS does and returns the server block.
func parse(t *testing.T, corefile []byte) caddyfile.ServerBlock {
	t.Helper()
	blocks, err := caddyfile.Parse("Corefile", strings.NewReader(string(corefile)), nil)
	if err != nil {
		t.Fatalf("parse: %v\n%s", err, corefile)
	}
	if len(blocks) != 1 {
		t.Fatalf("server blocks = %d, want 1", len(blocks))
	}
	return blocks[0]
}

func testDNS() policy.DNS {
	return policy.DNS{Listen: netip.MustParseAddrPort("127.0.0.1:10053"), Upstream: []policy.Upstream{up("9.9.9.9:853", "dns.quad9.net")}}
}

func TestCorefilePluginList(t *testing.T) {
	block := parse(t, mustNew(t, "/s.sock", "").Corefile(testDNS()))
	got := slices.Sorted(maps.Keys(block.Tokens))
	want := []string{"bind", "cache", "errors", "forward", "ifbound"}
	if !slices.Equal(got, want) {
		t.Errorf("plugins = %v, want %v (and no log)", got, want)
	}
}

func TestPathsAreQuotedTokens(t *testing.T) {
	const socket = "/tmp/x#y z/report.sock"
	const ca = "/tmp/ca # 1/ca.pem"
	block := parse(t, mustNew(t, socket, ca).Corefile(testDNS()))
	if got := block.Tokens["ifbound"]; len(got) != 2 || got[1].Text != socket {
		t.Errorf("ifbound tokens = %v, want the socket %q as one token", got, socket)
	}
	fwd := block.Tokens["forward"]
	var tlsArg string
	for i, tok := range fwd {
		if tok.Text == "tls" && i+1 < len(fwd) {
			tlsArg = fwd[i+1].Text
		}
	}
	if tlsArg != ca {
		t.Errorf("forward tls argument = %q, want %q", tlsArg, ca)
	}
}

func TestNewRefusesPathsTheCorefileCannotCarry(t *testing.T) {
	for _, bad := range []string{"/a\"b/s.sock", "/a{$HOME}/s.sock", "/a}/s.sock", "/a\nb/s.sock", "/a/s\\"} {
		if _, err := New(bad, ""); !errors.Is(err, ErrBadPath) {
			t.Errorf("New(socket %q) = %v, want ErrBadPath", bad, err)
		}
		if _, err := New("/s.sock", bad); !errors.Is(err, ErrBadPath) {
			t.Errorf("New(CA %q) = %v, want ErrBadPath", bad, err)
		}
	}
}

func TestNewRefusesALongSocketPath(t *testing.T) {
	ok := "/" + strings.Repeat("a", 102) // 103 bytes
	if _, err := New(ok, ""); err != nil {
		t.Errorf("New(103 bytes) = %v", err)
	}
	if _, err := New(ok+"a", ""); !errors.Is(err, ErrSocketTooLong) {
		t.Errorf("New(104 bytes) = %v, want ErrSocketTooLong", err)
	}
}
