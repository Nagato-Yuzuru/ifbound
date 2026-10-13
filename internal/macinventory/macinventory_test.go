//go:build darwin

package macinventory

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math/rand/v2"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"

	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

// Flags and types as a macOS 27 host reports them.
const (
	flagsUTUN  = unix.IFF_UP | unix.IFF_POINTOPOINT | unix.IFF_RUNNING | unix.IFF_MULTICAST
	flagsEther = unix.IFF_UP | unix.IFF_BROADCAST | unix.IFF_RUNNING | unix.IFF_SIMPLEX | unix.IFF_MULTICAST
	flagsLoop  = unix.IFF_UP | unix.IFF_LOOPBACK | unix.IFF_RUNNING | unix.IFF_MULTICAST
	flagsGIF   = unix.IFF_POINTOPOINT | unix.IFF_MULTICAST
	flagsPPP   = unix.IFF_UP | unix.IFF_POINTOPOINT | unix.IFF_RUNNING | unix.IFF_MULTICAST
)

// Families of other drivers (IFNET_FAMILY_* in net/kpi_interface.h of xnu).
const (
	familyLoopback = 1
	familyEthernet = 2
	familyPPP      = 6
	familySTF      = 12
	familyCellular = 15
)

func TestClassify(t *testing.T) {
	tests := []struct {
		name string
		l    link
		want policy.Class
	}{
		{"utun is a tunnel", link{"utun3", flagsUTUN, unix.IFT_OTHER, familyUTUN}, policy.ClassTunnel},
		{"utun that is down is a tunnel", link{"utun4", unix.IFF_POINTOPOINT, unix.IFT_OTHER, familyUTUN}, policy.ClassTunnel},
		{"ipsec is a tunnel", link{"ipsec0", flagsUTUN, unix.IFT_OTHER, familyIPSEC}, policy.ClassTunnel},
		{"gif is a tunnel", link{"gif0", flagsGIF, unix.IFT_GIF, familyGIF}, policy.ClassTunnel},
		{"Wi-Fi is hardware", link{"en0", flagsEther, unix.IFT_ETHER, familyEthernet}, policy.ClassHardware},
		{"Ethernet that is down is hardware", link{"en7", unix.IFF_BROADCAST, unix.IFT_ETHER, familyEthernet}, policy.ClassHardware},
		{"VLAN is hardware", link{"vlan0", flagsEther, unix.IFT_L2VLAN, 5}, policy.ClassHardware},
		{"bond is hardware", link{"bond0", flagsEther, unix.IFT_IEEE8023ADLAG, 14}, policy.ClassHardware},
		{"bridge is hardware", link{"bridge0", flagsEther, unix.IFT_BRIDGE, familyEthernet}, policy.ClassHardware},
		// Not sure: no class.
		{"loopback", link{"lo0", flagsLoop, unix.IFT_LOOP, familyLoopback}, 0},
		{"ppp can be PPPoE", link{"ppp0", flagsPPP, unix.IFT_PPP, familyPPP}, 0},
		{"stf", link{"stf0", 0, unix.IFT_STF, familySTF}, 0},
		{"pktap", link{"pktap0", unix.IFF_UP, unix.IFT_PKTAP, familyLoopback}, 0},
		// IFT_OTHER is the type of every interface without a better one.
		{"IFT_OTHER point-to-point of another family", link{"wwan0", flagsUTUN, unix.IFT_OTHER, familyCellular}, 0},
		{"IFT_OTHER point-to-point without a family", link{"x0", flagsUTUN, unix.IFT_OTHER, 0}, 0},
		{"tunnel family that is not point-to-point", link{"x1", flagsEther, unix.IFT_OTHER, familyUTUN}, 0},
		{"Ethernet type that is point-to-point", link{"x2", flagsUTUN, unix.IFT_ETHER, familyEthernet}, 0},
		{"bridge that is point-to-point", link{"x3", flagsUTUN, unix.IFT_BRIDGE, familyEthernet}, 0},
		{"unknown type", link{"x4", flagsEther, 0xfd, familyEthernet}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classify(tt.l); got != tt.want {
				t.Errorf("classify(%+v) = %v, want %v", tt.l, got, tt.want)
			}
		})
	}
}

// TestClassComesFromPropertiesNotName gives the same properties under
// names of all classes. Each name gets the class of the properties.
func TestClassComesFromPropertiesNotName(t *testing.T) {
	names := []string{"en0", "utun0", "lo0", "ppp0", "bridge100", "gif0", "x", "feth7", "ipsec3", "vmenet0"}
	tests := []struct {
		name string
		l    link // without a name
		want policy.Class
	}{
		{"VPN utun", link{flags: flagsUTUN, typ: unix.IFT_OTHER, family: familyUTUN}, policy.ClassTunnel},
		{"Wi-Fi or Ethernet", link{flags: flagsEther, typ: unix.IFT_ETHER, family: familyEthernet}, policy.ClassHardware},
		{"loopback", link{flags: flagsLoop, typ: unix.IFT_LOOP, family: familyLoopback}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			links := make([]link, len(names))
			for i, n := range names {
				links[i] = tt.l
				links[i].name = n
			}
			got, err := newInventory(func() ([]link, error) { return links, nil }).Interfaces(t.Context())
			if err != nil {
				t.Fatalf("Interfaces: %v", err)
			}
			if len(got) != len(names) {
				t.Fatalf("Interfaces returned %d interfaces, want %d", len(got), len(names))
			}
			for _, i := range got {
				if i.Class != tt.want {
					t.Errorf("class of %q = %v, want %v for the same properties", i.Name, i.Class, tt.want)
				}
			}
		})
	}
}

// TestInterfacesStableOrder gives the interfaces in many orders. Each
// order gives the same list, sorted by the bytes of the names.
func TestInterfacesStableOrder(t *testing.T) {
	base := []link{
		{"utun10", unix.IFF_POINTOPOINT, unix.IFT_OTHER, familyUTUN},
		{"utun2", unix.IFF_POINTOPOINT, unix.IFT_OTHER, familyUTUN},
		{"en0", unix.IFF_BROADCAST, unix.IFT_ETHER, familyEthernet},
		{"en10", unix.IFF_BROADCAST, unix.IFT_ETHER, familyEthernet},
		{"lo0", unix.IFF_LOOPBACK, unix.IFT_LOOP, familyLoopback},
		{"Z0", 0, unix.IFT_OTHER, 0},
		{"bridge100", unix.IFF_BROADCAST, unix.IFT_BRIDGE, familyEthernet},
	}
	// Sorted by hand.
	want := []string{"Z0", "bridge100", "en0", "en10", "lo0", "utun10", "utun2"}
	r := rand.New(rand.NewPCG(1, 2))
	for n := range 200 {
		in := slices.Clone(base)
		r.Shuffle(len(in), func(i, j int) { in[i], in[j] = in[j], in[i] })
		got, err := newInventory(func() ([]link, error) { return in, nil }).Interfaces(t.Context())
		if err != nil {
			t.Fatalf("Interfaces: %v", err)
		}
		names := make([]string, len(got))
		for i, g := range got {
			names[i] = g.Name
		}
		if !slices.Equal(names, want) {
			t.Fatalf("order %d: Interfaces names = %v, want %v", n, names, want)
		}
	}
	for _, size := range []int{0, 1} {
		got, err := newInventory(func() ([]link, error) { return base[:size], nil }).Interfaces(t.Context())
		if err != nil || len(got) != size {
			t.Errorf("Interfaces of %d links = %v, %v, want %d interfaces", size, got, err, size)
		}
	}
}

func TestInterfacesReturnsListError(t *testing.T) {
	inv := newInventory(func() ([]link, error) { return nil, errList })
	got, err := inv.Interfaces(t.Context())
	if !errors.Is(err, errList) || got != nil {
		t.Errorf("Interfaces = %v, %v, want nil and %v", got, err, errList)
	}
}

// TestSystemInterfacesMatchIfconfig compares the real list with the list
// of ifconfig -l, a second source. It needs no root.
func TestSystemInterfacesMatchIfconfig(t *testing.T) {
	out, err := exec.CommandContext(t.Context(), "/sbin/ifconfig", "-l").Output()
	if err != nil {
		t.Fatalf("ifconfig -l: %v", err)
	}
	want := strings.Fields(string(out))
	slices.Sort(want)
	got, err := New().Interfaces(t.Context())
	if err != nil {
		t.Fatalf("Interfaces: %v", err)
	}
	names := make([]string, len(got))
	for i, g := range got {
		names[i] = g.Name
		switch {
		case strings.HasPrefix(g.Name, "utun") && g.Class != policy.ClassTunnel:
			t.Errorf("host %s has class %v, want %v", g.Name, g.Class, policy.ClassTunnel)
		case g.Name == "lo0" && g.Class != 0:
			t.Errorf("host lo0 has class %v, want no class", g.Class)
		}
	}
	if !slices.Equal(names, want) {
		t.Errorf("Interfaces names = %v, ifconfig -l = %v", names, want)
	}
}

// TestParseLinksRejectsSkippedInterface removes the name address
// (RTA_IFP) from one RTM_IFINFO message of the real list. The parser of
// golang.org/x/net/route then skips the message without an error.
func TestParseLinksRejectsSkippedInterface(t *testing.T) {
	rib, err := route.FetchRIB(unix.AF_UNSPEC, route.RIBTypeInterface, 0)
	if err != nil {
		t.Fatalf("FetchRIB: %v", err)
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	if _, err := parseLinks(rib, fd); err != nil {
		t.Fatalf("parseLinks of the real list: %v", err)
	}

	for b := rib; len(b) >= 8; b = b[binary.NativeEndian.Uint16(b):] {
		if b[3] == unix.RTM_IFINFO {
			// ifm_addrs follows rtm_msglen, rtm_version, and rtm_type.
			addrs := binary.NativeEndian.Uint32(b[4:])
			binary.NativeEndian.PutUint32(b[4:], addrs&^unix.RTA_IFP)
			break
		}
	}
	if links, err := parseLinks(rib, fd); !errors.Is(err, errList) {
		t.Errorf("parseLinks without one name = %v, %v, want an error that wraps %v", links, err, errList)
	}
}

// header returns a routing message header of the given version and type.
func header(version, typ byte) []byte {
	return []byte{112, 0, version, typ, 0, 0, 0, 0}
}

func TestChanges(t *testing.T) {
	tests := []struct {
		name string
		msg  []byte
		want bool
	}{
		{"RTM_IFINFO", header(unix.RTM_VERSION, unix.RTM_IFINFO), true},
		{"RTM_NEWADDR", header(unix.RTM_VERSION, unix.RTM_NEWADDR), true},
		{"RTM_DELADDR", header(unix.RTM_VERSION, unix.RTM_DELADDR), true},
		{"RTM_ADD", header(unix.RTM_VERSION, unix.RTM_ADD), false},
		{"RTM_DELETE", header(unix.RTM_VERSION, unix.RTM_DELETE), false},
		{"RTM_NEWMADDR", header(unix.RTM_VERSION, unix.RTM_NEWMADDR), false},
		{"unknown version", header(unix.RTM_VERSION+1, unix.RTM_ADD), true},
		{"empty", nil, true},
		{"three bytes", []byte{4, 0, unix.RTM_VERSION}, true},
		{"four bytes", []byte{4, 0, unix.RTM_VERSION, unix.RTM_ADD}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := changes(tt.msg); got != tt.want {
				t.Errorf("changes(%v) = %v, want %v", tt.msg, got, tt.want)
			}
		})
	}
}

// drain takes the signals that wait on ch and returns their number.
func drain(ch <-chan struct{}) int {
	n := 0
	for {
		select {
		case <-ch:
			n++
		default:
			return n
		}
	}
}

// fakeSocket gives the messages and errors that a test sends, one for each
// Read. A Read blocks until the test sends one, or until done closes, as
// the deadline ends a real read.
type fakeSocket struct {
	done <-chan struct{}
	msgs chan []byte
	errs chan error
}

func (s *fakeSocket) Read(p []byte) (int, error) {
	select {
	case m := <-s.msgs:
		return copy(p, m), nil
	case err := <-s.errs:
		return 0, err
	case <-s.done:
		return 0, os.ErrDeadlineExceeded
	}
}

var _ io.Reader = (*fakeSocket)(nil)

// startWatch runs watch on a fake socket. The returned channel receives
// the result of watch.
func startWatch(ctx context.Context, inv *Inventory) (*fakeSocket, <-chan error) {
	s := &fakeSocket{done: ctx.Done(), msgs: make(chan []byte), errs: make(chan error)}
	done := make(chan error, 1)
	go func() { done <- inv.watch(ctx, s) }()
	return s, done
}

// TestWatchSignalsDebounceAfterFirstChange checks the time of the
// signal: Debounce after the first message of a change, not after the
// last one.
func TestWatchSignalsDebounceAfterFirstChange(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		inv := newInventory(nil)
		s, _ := startWatch(ctx, inv)

		s.msgs <- header(unix.RTM_VERSION, unix.RTM_IFINFO)
		time.Sleep(Debounce / 2)
		s.msgs <- header(unix.RTM_VERSION, unix.RTM_NEWADDR)
		time.Sleep(Debounce/2 - time.Nanosecond)
		synctest.Wait()
		if n := drain(inv.Changes()); n != 0 {
			t.Fatalf("signal before Debounce from the first change")
		}
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		if n := drain(inv.Changes()); n != 1 {
			t.Fatalf("got %d signals at Debounce after the first change, want 1", n)
		}

		// A change after the signal starts a new window.
		s.msgs <- header(unix.RTM_VERSION, unix.RTM_DELADDR)
		time.Sleep(Debounce)
		synctest.Wait()
		if n := drain(inv.Changes()); n != 1 {
			t.Fatalf("got %d signals for a change after the first signal, want 1", n)
		}
	})
}

// TestDebounceMergesChanges checks that Debounce is short, that the
// messages of one change give one signal, that route messages give none,
// and that the signals nobody received merge into one value.
func TestDebounceMergesChanges(t *testing.T) {
	if Debounce <= 0 || Debounce > time.Second {
		t.Fatalf("Debounce = %v, want a short positive delay", Debounce)
	}
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		inv := newInventory(nil)
		s, _ := startWatch(ctx, inv)

		// The consumer receives at once, as the daemon loop does, so the
		// channel buffer cannot hide a second signal.
		n := 0
		for _, typ := range []byte{unix.RTM_NEWADDR, unix.RTM_ADD, unix.RTM_IFINFO, unix.RTM_IFINFO} {
			s.msgs <- header(unix.RTM_VERSION, typ)
			synctest.Wait()
			n += drain(inv.Changes())
			time.Sleep(Debounce / 10)
		}
		time.Sleep(2 * Debounce)
		synctest.Wait()
		if n += drain(inv.Changes()); n != 1 {
			t.Fatalf("got %d signals for one change, want 1", n)
		}

		for range 50 {
			s.msgs <- header(unix.RTM_VERSION, unix.RTM_ADD)
			s.msgs <- header(unix.RTM_VERSION, unix.RTM_DELETE)
			s.msgs <- header(unix.RTM_VERSION, unix.RTM_GET)
		}
		time.Sleep(2 * Debounce)
		synctest.Wait()
		if n := drain(inv.Changes()); n != 0 {
			t.Fatalf("got %d signals for route messages, want 0", n)
		}

		for _, typ := range []byte{unix.RTM_IFINFO, unix.RTM_DELADDR, unix.RTM_NEWADDR} {
			s.msgs <- header(unix.RTM_VERSION, typ)
			time.Sleep(3 * Debounce)
		}
		synctest.Wait()
		if n := drain(inv.Changes()); n != 1 {
			t.Fatalf("got %d waiting signals for three changes that nobody received, want 1", n)
		}
	})
}

func TestWatchReportsReadError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		inv := newInventory(nil)
		s, done := startWatch(t.Context(), inv)
		s.errs <- unix.EBADF
		err := <-done
		if !errors.Is(err, errWatch) || !strings.Contains(err.Error(), unix.EBADF.Error()) {
			t.Errorf("watch = %v, want an error that wraps %v and names %v", err, errWatch, unix.EBADF)
		}
	})
}

// TestWatchSignalsNothingAfterReturn sends a change, and then stops watch
// before the signal is due. No signal comes after watch returns.
func TestWatchSignalsNothingAfterReturn(t *testing.T) {
	tests := []struct {
		name string
		stop func(cancel context.CancelFunc, s *fakeSocket)
		want error
	}{
		{"read error", func(_ context.CancelFunc, s *fakeSocket) { s.errs <- unix.EBADF }, errWatch},
		{"cancel", func(cancel context.CancelFunc, _ *fakeSocket) { cancel() }, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				inv := newInventory(nil)
				s, done := startWatch(ctx, inv)
				s.msgs <- header(unix.RTM_VERSION, unix.RTM_IFINFO)
				tt.stop(cancel, s)
				if err := <-done; !errors.Is(err, tt.want) {
					t.Fatalf("watch = %v, want %v", err, tt.want)
				}
				time.Sleep(2 * Debounce)
				synctest.Wait()
				if n := drain(inv.Changes()); n != 0 {
					t.Errorf("got %d signals after watch returned, want 0", n)
				}
			})
		})
	}
}

// TestRunSignalsWhenOpenAndStopsWithContext reads a real routing socket.
// It needs no root.
func TestRunSignalsWhenOpenAndStopsWithContext(t *testing.T) {
	inv := New()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- inv.Run(ctx) }()

	select {
	case <-inv.Changes():
	case <-time.After(5 * time.Second):
		t.Fatal("no signal after Run opened the socket")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run after cancel = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop after cancel")
	}
}

func TestRunStopsWithEndedContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	done := make(chan error, 1)
	go func() { done <- New().Run(ctx) }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run with an ended ctx = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run with an ended ctx did not return")
	}
}

// sendRTMGet writes n RTM_GET requests for 127.0.0.1 on a new routing
// socket. The kernel copies each reply to every routing socket. It needs
// no root.
func sendRTMGet(t *testing.T, n int) {
	t.Helper()
	w, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	defer func() { _ = unix.Close(w) }()
	for i := range n {
		m := route.RouteMessage{
			Version: unix.RTM_VERSION, Type: unix.RTM_GET, ID: uintptr(os.Getpid()), Seq: i + 1,
			Addrs: []route.Addr{unix.RTAX_DST: &route.Inet4Addr{IP: [4]byte{127, 0, 0, 1}}},
		}
		b, err := m.Marshal()
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if _, err := unix.Write(w, b); err != nil {
			t.Fatalf("write RTM_GET: %v", err)
		}
	}
}

// TestRunIgnoresRouteTraffic sends route replies to a real Run. They are
// not interface changes, so no signal comes after the start signal.
func TestRunIgnoresRouteTraffic(t *testing.T) {
	inv := New()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- inv.Run(ctx) }()
	select {
	case <-inv.Changes():
	case <-time.After(5 * time.Second):
		t.Fatal("no start signal")
	}
	sendRTMGet(t, 15)
	select {
	case <-inv.Changes():
		t.Error("a signal for RTM_GET replies, want none")
	case <-time.After(5 * Debounce):
	}
	cancel()
	if err := <-done; err != nil {
		t.Errorf("Run after cancel = %v, want nil", err)
	}
}

// TestSocketKeepsBurst sends a burst of route replies while nobody reads
// the socket. The kernel drops a message that does not fit in the
// receive buffer and gives no error, so the buffer must hold the burst.
func TestSocketKeepsBurst(t *testing.T) {
	f, err := openSocket()
	if err != nil {
		t.Fatalf("openSocket: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	const sent = 2000
	sendRTMGet(t, sent)

	if err := f.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, readSize)
	pid := uint32(os.Getpid())
	received := 0
	for received < sent {
		n, err := f.Read(buf)
		if err != nil {
			t.Fatalf("received %d of %d replies, then: %v", received, sent, err)
		}
		// rt_msghdr: rtm_pid is at byte 16.
		if n >= 20 && buf[3] == unix.RTM_GET && binary.NativeEndian.Uint32(buf[16:]) == pid {
			received++
		}
	}
}
