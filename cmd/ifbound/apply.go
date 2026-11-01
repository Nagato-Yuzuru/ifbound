package main

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Nagato-Yuzuru/ifbound/internal/ipc"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

func newApplyCmd(d deps) *cobra.Command {
	return &cobra.Command{
		Use:   "apply [file]",
		Short: "Send a configuration file to ifboundd and print the new status",
		Long: "Apply checks the file and prints its errors. A valid file goes to ifboundd, " +
			"which stores it and reconfigures. The default file is " + d.inputConfig + ". " +
			"Apply needs root.\n\n" +
			"Exit codes: 0 ready, 1 error, 2 usage, 3 degraded, 4 unenforced, 5 starting, " +
			"6 reply lost (the daemon can have applied the file).",
		Args:              cobra.MaximumNArgs(1),
		ValidArgsFunction: completeToml,
		RunE: func(cmd *cobra.Command, args []string) error {
			path := d.inputConfig
			if len(args) == 1 {
				path = args[0]
			}
			data, err := readInput(cmd.Context(), path)
			if err != nil {
				return err
			}
			// The server checks again, because only its result counts. This
			// check spares a round trip when the file is bad.
			cfg, err := policy.ParseBytes(data)
			if err == nil {
				err = cfg.CheckUpstreams()
			}
			if err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
			rep, err := d.admin.Apply(cmd.Context(), data)
			if err != nil {
				return applyError(err)
			}
			if err := printStatus(d.stdout, rep); err != nil {
				// The state code is the result of the verb: keep it.
				_, _ = fmt.Fprintln(d.stderr, "ifbound:", err) //nolint:errcheck // nothing to do when stderr fails
			}
			return stateExit(rep.State)
		},
	}
}

// completeToml completes the one file argument with .toml files. It never
// calls the daemon.
func completeToml(_ *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return []string{"toml"}, cobra.ShellCompDirectiveFilterFileExt
}

// applyError adds the next step for the errors that the operator can fix.
// A request that was sent without a reply gets its own exit code.
func applyError(err error) error {
	err = fmt.Errorf("apply: %w", err)
	switch {
	case errors.Is(err, ipc.ErrNoReply):
		return &codeError{code: exitLost, err: fmt.Errorf("%w: the daemon can have applied the file; run \"ifbound status\" to see it", err)}
	case errors.Is(err, ipc.ErrDenied):
		return fmt.Errorf("%w (run as root)", err)
	case errors.Is(err, ipc.ErrUnavailable):
		return fmt.Errorf("%w (is ifboundd running as root?)", err)
	case errors.Is(err, ipc.ErrProtocol):
		return fmt.Errorf("%w (ifbound and ifboundd can be of different versions: run \"ifbound version\")", err)
	default:
		return err
	}
}
