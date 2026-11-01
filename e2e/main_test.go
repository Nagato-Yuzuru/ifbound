//go:build e2e

package e2e

import (
	"os"
	"testing"

	"github.com/Nagato-Yuzuru/ifbound/internal/testenv"
)

// TestMain runs the tests only on a disposable host. The check is here,
// not in each test, so that no test, cleanup, or helper process of this
// binary reaches the host before it.
func TestMain(m *testing.M) {
	os.Exit(testenv.RunOnDisposableHost(m))
}
