package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/Nagato-Yuzuru/ifbound/internal/ipc"
)

// versionWait bounds the question to ifboundd. The verb must stay quick
// when the daemon is down.
const versionWait = 3 * time.Second

func newVersionCmd(d deps) *cobra.Command {
	return &cobra.Command{
		Use:               "version",
		Short:             "Print the version of ifbound and of ifboundd",
		Args:              cobra.NoArgs,
		ValidArgsFunction: cobra.NoFileCompletions,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), versionWait)
			defer cancel()
			rep, err := d.public.Status(ctx)
			_, werr := fmt.Fprint(d.stdout, versionText(d, rep, err))
			return werr
		},
	}
}

// versionText renders the output of version. The lines to act on come
// after the versions.
func versionText(d deps, rep ipc.StatusReport, err error) string {
	text := fmt.Sprintf("ifbound %s\n", d.version)
	switch {
	case errors.Is(err, ipc.ErrProtocol):
		return text + fmt.Sprintf("ifboundd: speaks another protocol (%v)\nwarning: ifbound and ifboundd differ\n", err)
	case err != nil:
		return text + fmt.Sprintf("ifboundd: not reachable (%v)\n", err)
	case rep.Daemon == "":
		return text + "ifboundd: version unknown\n"
	}
	text += fmt.Sprintf("ifboundd %s\n", rep.Daemon)
	if rep.Daemon != d.version {
		text += fmt.Sprintf("warning: ifbound %s and ifboundd %s differ\n", d.version, rep.Daemon)
	}
	return text
}
