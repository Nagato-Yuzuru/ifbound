package testenv

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// notRootFile returns a file whose owner uid is not 0 and whose group is
// 0, so that a check of the group in place of the owner fails the tests.
func notRootFile(t *testing.T) string {
	t.Helper()
	// On macOS a new file takes the group of its directory, and /tmp has
	// group 0. On Linux the group is the group of the process.
	f, err := os.CreateTemp("/tmp", "testenv-not-root-")
	if err != nil {
		t.Fatal(err)
	}
	p := f.Name()
	t.Cleanup(func() { _ = os.Remove(p) }) //nolint:errcheck // a left file in /tmp changes nothing
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		// Root makes a file that root owns. In a user namespace the chown
		// can fail; the case then has no meaning there.
		if err := os.Chown(p, 1, 0); err != nil {
			t.Skipf("cannot give the file to uid 1: %v", err)
		}
	}
	return p
}

// /etc/hosts exists and root owns it on macOS and Linux.
const rootFile = "/etc/hosts"

func TestCheckMarker(t *testing.T) {
	tests := []struct {
		name string
		path string
		want error // nil: the marker is valid
	}{
		{"missing", filepath.Join(t.TempDir(), "missing"), fs.ErrNotExist},
		{"not owned by root", notRootFile(t), errMarkerOwner},
		{"owned by root", rootFile, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkMarker(tt.path)
			if tt.want == nil {
				if err != nil {
					t.Fatalf("checkMarker(%s) = %v, want nil", tt.path, err)
				}
				return
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("checkMarker(%s) = %v, want %v", tt.path, err, tt.want)
			}
		})
	}
}

type fakeRunner struct{ ran bool }

func (r *fakeRunner) Run() int {
	r.ran = true
	return 7
}

func TestRunOnDisposableHost(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	tests := []struct {
		name    string
		marker  string
		strict  bool
		wantRun bool
		want    int
	}{
		{"no marker", missing, false, false, 0},
		{"no marker, strict", missing, true, false, 1},
		{"marker not owned by root, strict", notRootFile(t), true, false, 1},
		{"valid marker", rootFile, true, true, 7},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var r fakeRunner
			var out strings.Builder
			got := runOnDisposableHost(&r, tt.marker, tt.strict, &out)
			if got != tt.want || r.ran != tt.wantRun {
				t.Fatalf("exit %d, ran %v; want exit %d, ran %v", got, r.ran, tt.want, tt.wantRun)
			}
			if !tt.wantRun && !strings.Contains(out.String(), "not marked disposable") {
				t.Fatalf("output %q does not give the reason", out.String())
			}
		})
	}
}

// The exported entry checks DisposableMarker. A unit test host is not
// disposable, so no test of m runs there.
func TestRunOnDisposableHostChecksTheMarker(t *testing.T) {
	if checkMarker(DisposableMarker) == nil {
		t.Skip("this host holds the marker")
	}
	t.Setenv(EnvStrict, "")
	var r fakeRunner
	if got := RunOnDisposableHost(&r); got != 0 || r.ran {
		t.Fatalf("exit %d, ran %v; want exit 0, ran false", got, r.ran)
	}
}
