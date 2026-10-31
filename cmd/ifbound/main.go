// Command ifbound is the command line of ifbound.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/Nagato-Yuzuru/ifbound/internal/ipc"
	"github.com/Nagato-Yuzuru/ifbound/internal/layout"
)

// version is the build version. A release build sets it with
// -ldflags "-X main.version=...".
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	l := layout.Default()
	// ifboundd runs as root, so the client trusts a server of uid 0 only.
	code := run(ctx, os.Args[1:], deps{
		admin:       ipc.NewControlClient(l.AdminSocket(), 0),
		public:      ipc.NewControlClient(l.ControlSocket(), 0),
		stdout:      os.Stdout,
		stderr:      os.Stderr,
		inputConfig: l.InputConfig(),
		version:     version,
	})
	stop()
	os.Exit(code)
}

// run executes one command line and returns the exit code. It prints the
// error of the command one time.
func run(ctx context.Context, args []string, d deps) int {
	root, started := newRootCmd(d) //nolint:contextcheck // ExecuteContext hands ctx to each verb
	root.SetArgs(args)
	err := root.ExecuteContext(ctx)
	if err != nil && !started() {
		err = &codeError{code: exitUsage, err: err}
	}
	if err != nil {
		if msg := err.Error(); msg != "" {
			_, _ = fmt.Fprintln(d.stderr, "ifbound:", msg) //nolint:errcheck // nothing to do when stderr fails
		}
	}
	return exitCode(err)
}
