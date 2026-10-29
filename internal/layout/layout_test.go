package layout

import (
	"io/fs"
	"testing"
)

// TestDefaultPaths pins the paths of the real system. The launchd
// property lists and the install steps use the same paths, so a change
// here must be a deliberate one.
func TestDefaultPaths(t *testing.T) {
	l := Default()
	tests := []struct{ got, want string }{
		{l.InputConfig(), "/etc/ifbound/config.toml"},
		{l.StoredConfig(), "/var/db/ifbound/config.toml"},
		{l.Snapshot(), "/var/db/ifbound/addrbook.json"},
		{l.ReportSocket(), "/var/run/ifbound/report.sock"},
		{l.ControlSocket(), "/var/run/ifbound/control.sock"},
		{l.DaemonLog(), "/var/log/ifbound/ifboundd.log"},
		{l.DNSLog(), "/var/log/ifbound/ifbound-dns.log"},
		{l.LibexecDir, "/usr/local/libexec/ifbound"},
		{l.PlistDir, "/Library/LaunchDaemons"},
		{l.HostsFile, "/etc/hosts"},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("path = %q, want %q", tt.got, tt.want)
		}
	}
}

// TestFixedNames pins the names and modes that do not depend on a
// Layout.
func TestFixedNames(t *testing.T) {
	names := []struct{ got, want string }{
		{DaemonLabel, "io.github.nagato-yuzuru.ifboundd"},
		{DNSLabel, "io.github.nagato-yuzuru.ifbound-dns"},
		{User, "_ifbound"},
		{Group, "_ifbound"},
		{EnforcementLock, "/var/run/ifbound-enforcement.lock"},
	}
	for _, tt := range names {
		if tt.got != tt.want {
			t.Errorf("name = %q, want %q", tt.got, tt.want)
		}
	}
	modes := []struct {
		name string
		got  fs.FileMode
		want fs.FileMode
	}{
		{"input config", InputConfigMode, 0o644},
		{"stored config", StoredConfigMode, 0o640},
		{"snapshot", SnapshotMode, 0o600},
		{"report socket", ReportSocketMode, 0o660},
		{"control socket", ControlSocketMode, 0o666},
	}
	for _, tt := range modes {
		if tt.got != tt.want {
			t.Errorf("%s mode = %v, want %v", tt.name, tt.got, tt.want)
		}
	}
}
