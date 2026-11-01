package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"

	"github.com/Nagato-Yuzuru/ifbound/internal/configstore"
	"github.com/Nagato-Yuzuru/ifbound/internal/ipc"
)

var errUnknownState = errors.New("unknown daemon state")

// printStatus writes a status report as lines of text, in one write.
func printStatus(w io.Writer, r ipc.StatusReport) error {
	var b bytes.Buffer
	// A bytes.Buffer never fails to write.
	fmt.Fprintf(&b, "state: %s\n", r.State)
	for _, reason := range r.Reasons {
		fmt.Fprintf(&b, "reason: %s\n", reason)
	}
	for _, warn := range r.Warnings {
		fmt.Fprintf(&b, "warning: %s: %s\n", warn.Source, warn.Text)
	}
	for _, p := range r.Policies {
		fmt.Fprintf(&b, "policy %s: %d learned addresses\n", p.Name, p.Addrs)
	}
	if r.RetainRestart {
		b.WriteString("retain changes after a restart of ifboundd\n")
	}
	if r.Config != "" {
		fmt.Fprintf(&b, "config: %s\n", r.Config)
	}
	_, err := w.Write(b.Bytes())
	return err
}

// stateExit maps a daemon state to the exit code of a verb that reports it.
// A nil result means exit 0.
func stateExit(s ipc.State) error {
	switch s {
	case ipc.StateReady:
		return nil
	case ipc.StateDegraded:
		return &codeError{code: exitDegraded}
	case ipc.StateUnenforced:
		return &codeError{code: exitUnenf}
	case ipc.StateStarting:
		return &codeError{code: exitStarting}
	default:
		return fmt.Errorf("%w %d", errUnknownState, s)
	}
}

// unapplied reports whether the file at path differs from the applied
// configuration, whose digest is applied (empty when none is applied). A
// missing file has nothing to apply, so it is not a change. The status verb
// shows "unapplied changes in <file>" when this is true.
func unapplied(path, applied string) (bool, error) {
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	case err != nil:
		return false, err
	}
	return configstore.Digest(sha256.Sum256(data)).String() != applied, nil
}
