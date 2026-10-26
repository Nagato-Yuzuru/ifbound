//go:build darwin

// Package testnet creates disposable network interfaces for end-to-end tests
// on macOS. It uses only native features: utun through the kernel control
// socket, and feth through ifconfig. Each helper registers a cleanup that
// removes what it created. All helpers need root.
package testnet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// From <sys/kern_control.h> and <net/if_utun.h>; x/sys/unix does not export them.
const (
	sysprotoControl = 2
	utunOptIfname   = 2
	utunControlName = "com.apple.net.utun_control"
	// utun prefixes each packet with the address family in network byte order.
	utunHeaderLen = 4
)

var errShortPacket = errors.New("packet shorter than the utun header")

// UTUN is a utun interface that the test owns. Packets that the kernel sends
// out through the interface arrive at ReadPacket, so a test can prove that a
// packet left through this interface. Closing the descriptor destroys the
// interface.
type UTUN struct {
	Name string
	file *os.File
}

// NewUTUN creates a utun interface and registers its removal with t.Cleanup.
func NewUTUN(t testing.TB) *UTUN {
	t.Helper()
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, sysprotoControl)
	if err != nil {
		t.Fatalf("open kernel control socket: %v", err)
	}
	info := &unix.CtlInfo{}
	copy(info.Name[:], utunControlName)
	if err := unix.IoctlCtlInfo(fd, info); err != nil {
		_ = unix.Close(fd) //nolint:errcheck // the test fails on the ioctl error below
		t.Fatalf("resolve %s: %v", utunControlName, err)
	}
	// Unit 0 asks the kernel to choose the next free utunN.
	if err := unix.Connect(fd, &unix.SockaddrCtl{ID: info.Id, Unit: 0}); err != nil {
		_ = unix.Close(fd) //nolint:errcheck // the test fails on the connect error below
		t.Fatalf("create utun: %v", err)
	}
	name, err := unix.GetsockoptString(fd, sysprotoControl, utunOptIfname)
	if err != nil {
		_ = unix.Close(fd) //nolint:errcheck // the test fails on the getsockopt error below
		t.Fatalf("read utun name: %v", err)
	}
	// A non-blocking descriptor joins the runtime poller, so read deadlines work.
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd) //nolint:errcheck // the test fails on the fcntl error below
		t.Fatalf("set %s non-blocking: %v", name, err)
	}
	u := &UTUN{Name: name, file: os.NewFile(uintptr(fd), name)}
	t.Cleanup(func() {
		if err := u.file.Close(); err != nil {
			t.Errorf("close %s: %v", u.Name, err)
		}
	})
	return u
}

// SetAddr gives the interface a point-to-point IPv4 address pair and brings
// it up. Traffic to peer then leaves through this interface.
func (u *UTUN) SetAddr(t testing.TB, local, peer netip.Addr) {
	t.Helper()
	Ifconfig(t, u.Name, "inet", local.String(), peer.String(), "up")
}

// ReadPacket returns the next IP packet that left through the interface,
// without the utun header. It fails when no packet arrives before timeout.
func (u *UTUN) ReadPacket(t testing.TB, timeout time.Duration) []byte {
	t.Helper()
	if err := u.file.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatalf("set read deadline on %s: %v", u.Name, err)
	}
	buf := make([]byte, 64*1024)
	n, err := u.file.Read(buf)
	if err != nil {
		t.Fatalf("read packet from %s: %v", u.Name, err)
	}
	if n < utunHeaderLen {
		t.Fatalf("read packet from %s: %v (%d bytes)", u.Name, errShortPacket, n)
	}
	return buf[utunHeaderLen:n]
}

// FethPair is two connected fake Ethernet interfaces. A packet sent out
// through A arrives at B. They stand in for non-tunnel interfaces.
type FethPair struct {
	A, B string
}

// NewFethPair creates a feth pair and registers its removal with t.Cleanup.
func NewFethPair(t testing.TB) FethPair {
	t.Helper()
	units := freeUnits(t, "feth", 2)
	p := FethPair{A: "feth" + strconv.Itoa(units[0]), B: "feth" + strconv.Itoa(units[1])}
	for _, name := range []string{p.A, p.B} {
		Ifconfig(t, name, "create")
		t.Cleanup(func() {
			// t.Context is already canceled when cleanups run.
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if out, err := exec.CommandContext(ctx, "ifconfig", name, "destroy").CombinedOutput(); err != nil {
				t.Errorf("destroy %s: %v: %s", name, err, out)
			}
		})
	}
	Ifconfig(t, p.A, "peer", p.B)
	Ifconfig(t, p.A, "up")
	Ifconfig(t, p.B, "up")
	return p
}

// Ifconfig runs ifconfig with args and fails the test on error.
func Ifconfig(t testing.TB, args ...string) {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), "ifconfig", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("ifconfig %s: %v: %s", strings.Join(args, " "), err, out)
	}
}

// freeUnits returns n unit numbers that no interface named prefix<unit> uses.
func freeUnits(t testing.TB, prefix string, n int) []int {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("list interfaces: %v", err)
	}
	used := make(map[int]bool, len(ifaces))
	for _, ifc := range ifaces {
		if rest, ok := strings.CutPrefix(ifc.Name, prefix); ok {
			if unit, err := strconv.Atoi(rest); err == nil {
				used[unit] = true
			}
		}
	}
	units := make([]int, 0, n)
	for unit := 0; len(units) < n; unit++ {
		if !used[unit] {
			units = append(units, unit)
		}
	}
	return units
}

// String implements fmt.Stringer for test logs.
func (p FethPair) String() string { return fmt.Sprintf("%s<->%s", p.A, p.B) }
