//go:build darwin && !netgo

package syslookup

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The own LocalHostName under .local resolves only through mDNSResponder
// (multicast DNS). The hosts file does not have it, and a DNS client that
// sends its own queries does not find it.
func TestResolveOwnLocalHostNameThroughMDNSResponder(t *testing.T) {
	out, err := exec.CommandContext(t.Context(), "/usr/sbin/scutil", "--get", "LocalHostName").Output()
	host := strings.TrimSpace(string(out))
	if err != nil || host == "" {
		t.Skipf("cannot read LocalHostName with scutil (%v), so there is no name that only mDNSResponder can resolve", err)
	}
	addrs, err := Resolver{}.Resolve(t.Context(), host+".local")
	if err != nil {
		t.Fatalf("Resolve(%s.local): %v", host, err)
	}
	if len(addrs) == 0 {
		t.Fatalf("Resolve(%s.local) gave no addresses and no error", host)
	}
}

const childEnv = "SYSLOOKUP_PURE_GO_CHILD"

// With GODEBUG=netdns=go, the net package selects its pure-Go resolver.
// Resolve must then fail and must not give addresses. The setting applies
// at process start, so the check runs in a child process.
func TestResolveFailsWithPureGoResolver(t *testing.T) {
	if os.Getenv(childEnv) == "1" {
		addrs, err := Resolver{}.Resolve(t.Context(), "ifbound-syslookup-test.invalid.")
		if !errors.Is(err, errGoResolver) || addrs != nil {
			t.Fatalf("Resolve = %v, %v; want nil, errGoResolver", addrs, err)
		}
		return
	}
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestResolveFailsWithPureGoResolver$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), childEnv+"=1", "GODEBUG=netdns=go")
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "--- PASS: TestResolveFailsWithPureGoResolver") {
		t.Fatalf("child process: %v\n%s", err, out)
	}
}
