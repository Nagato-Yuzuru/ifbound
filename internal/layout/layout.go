// Package layout defines the paths, launchd labels, account names, and
// file modes of an ifbound installation, so that the binaries and the
// install steps can take them from one place. Not every package uses it
// yet.
//
// A Layout holds the directories and the host file. The file names inside
// the directories are fixed, so a test that moves a directory moves every
// file in it.
package layout

import (
	"io/fs"
	"path/filepath"
)

// The launchd labels of the two daemons.
const (
	DaemonLabel = "io.github.nagato-yuzuru.ifboundd"
	DNSLabel    = "io.github.nagato-yuzuru.ifbound-dns"
)

// User and Group are the account of ifbound-dns. The group can read the
// stored configuration and connect to the report socket.
const (
	User  = "_ifbound"
	Group = "_ifbound"
)

// EnforcementLock is the lock that a process holds while it writes the
// enforcement: the pf anchor and the resolver entries. It is not a
// Layout field. These resources are global to the host, so a process
// with a test layout must contend for the same lock.
const EnforcementLock = "/var/run/ifbound-enforcement.lock"

// The modes of the files and sockets.
const (
	InputConfigMode   fs.FileMode = 0o644 // root:wheel
	StoredConfigMode  fs.FileMode = 0o640 // root:_ifbound
	SnapshotMode      fs.FileMode = 0o600
	ReportSocketMode  fs.FileMode = 0o660 // root:_ifbound
	ControlSocketMode fs.FileMode = 0o666
)

// Layout holds the directories and the host file of an installation.
// Start from Default and change fields for a test. The zero Layout is not
// usable: all its paths are relative.
type Layout struct {
	// ConfigDir holds the input configuration that the administrator
	// edits. The daemon does not read it.
	ConfigDir string
	// StateDir holds the stored configuration and the address book
	// snapshot. Only ifboundd writes in it.
	StateDir string
	// RunDir holds the sockets.
	RunDir string
	// LogDir holds the log files of the two daemons.
	LogDir string
	// LibexecDir holds the daemon binaries.
	LibexecDir string
	// PlistDir holds the launchd property lists.
	PlistDir string
	// HostsFile is the host file that the daemon reads.
	HostsFile string
}

// Default returns the layout of the real system.
func Default() Layout {
	return Layout{
		ConfigDir:  "/etc/ifbound",
		StateDir:   "/var/db/ifbound",
		RunDir:     "/var/run/ifbound",
		LogDir:     "/var/log/ifbound",
		LibexecDir: "/usr/local/libexec/ifbound",
		PlistDir:   "/Library/LaunchDaemons",
		HostsFile:  "/etc/hosts",
	}
}

// InputConfig is the default input of "ifbound apply".
func (l Layout) InputConfig() string { return filepath.Join(l.ConfigDir, "config.toml") }

// StoredConfig is the applied configuration. Only ifboundd writes it.
func (l Layout) StoredConfig() string { return filepath.Join(l.StateDir, "config.toml") }

// Snapshot is the address book snapshot.
func (l Layout) Snapshot() string { return filepath.Join(l.StateDir, "addrbook.json") }

// ReportSocket is the socket where ifbound-dns reports DNS answers to
// ifboundd.
func (l Layout) ReportSocket() string { return filepath.Join(l.RunDir, "report.sock") }

// ControlSocket is the socket where the CLI sends commands to ifboundd.
func (l Layout) ControlSocket() string { return filepath.Join(l.RunDir, "control.sock") }

// DaemonLog is the log file of ifboundd.
func (l Layout) DaemonLog() string { return filepath.Join(l.LogDir, "ifboundd.log") }

// DNSLog is the log file of ifbound-dns.
func (l Layout) DNSLog() string { return filepath.Join(l.LogDir, "ifbound-dns.log") }
