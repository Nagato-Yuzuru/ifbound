package main

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Nagato-Yuzuru/ifbound/internal/ipc"
)

// Exit codes. The control API of the design fixes them.
const (
	exitError    = 1
	exitUsage    = 2
	exitDegraded = 3
	exitUnenf    = 4
	exitStarting = 5
	// exitLost means that the reply to an Apply was lost after the
	// request went out. The daemon can have applied the file.
	exitLost = 6
)

// deps holds what the verbs need from the outside. A test gives clients
// that talk to a fake server, and buffers for the output.
type deps struct {
	// admin serves Apply. Only root can reach its socket.
	admin *ipc.ControlClient
	// public serves Status for every local user.
	public *ipc.ControlClient
	stdout io.Writer
	stderr io.Writer
	// inputConfig is the default file of apply.
	inputConfig string
	// version is the build version of this binary.
	version string
}

// codeError carries an exit code. A nil err means that the verb has
// printed everything and run prints nothing more.
type codeError struct {
	code int
	err  error
}

func (e *codeError) Error() string {
	if e.err == nil {
		return ""
	}
	return e.err.Error()
}

func (e *codeError) Unwrap() error { return e.err }

// exitCode maps the error of Execute to the exit code.
func exitCode(err error) int {
	var ce *codeError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &ce):
		return ce.code
	default:
		return exitError
	}
}

// newRootCmd builds a new command tree. It holds no global state, so each
// test builds its own. The returned function reports whether a verb has
// started. cobra checks the arguments and the flags before it runs
// PersistentPreRunE, so an error that comes before the start is a usage
// error. This holds for the commands that cobra adds too.
func newRootCmd(d deps) (root *cobra.Command, started func() bool) {
	var began bool
	root = &cobra.Command{
		Use:           "ifbound",
		Short:         "Bind destinations to network interfaces",
		Version:       d.version,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(*cobra.Command, []string) error {
			began = true
			return nil
		},
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	root.SetOut(d.stdout)
	root.SetErr(d.stderr)
	root.SetVersionTemplate("ifbound {{.Version}}\n")
	root.SetHelpCommand(newHelpCmd(root))
	root.AddCommand(newApplyCmd(d), newVersionCmd(d))
	root.InitDefaultCompletionCmd()
	for _, c := range root.Commands() {
		if c.Name() == "completion" {
			groupOnly(c)
		}
	}
	return root, func() bool { return began }
}

// groupOnly makes a command that only groups subcommands refuse
// arguments. Without this, cobra prints the help and exits 0 for
// "completion zhs".
func groupOnly(c *cobra.Command) {
	c.Args = cobra.NoArgs
	c.RunE = func(cmd *cobra.Command, _ []string) error { return cmd.Help() }
}

// newHelpCmd replaces the help command of cobra, which prints "Unknown
// help topic" and succeeds.
func newHelpCmd(root *cobra.Command) *cobra.Command {
	return &cobra.Command{
		Use:   "help [command]",
		Short: "Help about a command",
		Args: func(_ *cobra.Command, args []string) error {
			_, err := helpTarget(root, args)
			return err
		},
		RunE: func(_ *cobra.Command, args []string) error {
			target, err := helpTarget(root, args)
			if err != nil {
				return err
			}
			return target.Help()
		},
	}
}

var errUnknownTopic = errors.New("unknown help topic")

// helpTarget finds the command that args name.
func helpTarget(root *cobra.Command, args []string) (*cobra.Command, error) {
	target, rest, err := root.Find(args)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("%w %q", errUnknownTopic, strings.Join(args, " "))
	}
	return target, nil
}
