package pfrules

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"os/exec"
	"testing"

	"github.com/Nagato-Yuzuru/ifbound/internal/testenv"
)

// pfctl is the absolute path, because /sbin is not always in PATH.
const pfctl = "/sbin/pfctl"

// TestPfctlAcceptsRulesets checks the syntax of compiled rulesets with
// "pfctl -n", which parses a ruleset and loads nothing. It needs no root.
// The rulesets hold numeric IDs only, so they do not depend on the
// accounts of the host.
func TestPfctlAcceptsRulesets(t *testing.T) {
	testenv.RequireOS(t, "darwin")
	testenv.RequireCommand(t, pfctl)
	type ruleset struct{ name, text string }
	var all []ruleset
	for _, g := range goldenCases {
		all = append(all, ruleset{g.name, compileText(t, parsePolicies(t, g.config), g.ifaces)})
	}
	for seed := range 60 {
		w := randomWorld(t, rand.New(rand.NewPCG(uint64(seed), 0x5eed)))
		rs, err := w.compile()
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, ruleset{fmt.Sprintf("random seed %d", seed), string(rs.Body())})
	}
	for _, rs := range all {
		cmd := exec.CommandContext(t.Context(), pfctl, "-n", "-a", "com.apple/000.ifbound", "-f", "-")
		cmd.Stdin = bytes.NewReader([]byte(rs.text))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("%s: pfctl -n: %v\n%s\nruleset:\n%s", rs.name, err, out, rs.text)
		}
	}
}
