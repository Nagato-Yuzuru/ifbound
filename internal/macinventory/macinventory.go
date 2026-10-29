//go:build darwin

// Package macinventory lists the network interfaces of macOS, gives each
// one its class, and reports changes. It implements reconcile.IfInventory.
//
// The class of an interface comes from its properties, never from its
// name. The properties are the interface flags in the interface list of
// the kernel, and the interface type (IFT_*) and family (IFNET_FAMILY_*)
// that the kernel gives for SIOCGIFTYPE. The driver that makes the
// interface sets the family:
//
//   - @tunnel: a point-to-point interface of the family utun, ipsec, or
//     gif. utun carries VPN clients and WireGuard. A packet that goes into
//     such an interface leaves the host only inside a new packet, and pf
//     checks that new packet on its own interface. The type is not
//     enough: utun has the type IFT_OTHER, and the kernel gives IFT_OTHER
//     to every interface that has no better type.
//   - @hardware: an interface that is not point-to-point, of an Ethernet
//     type: IFT_ETHER (wired Ethernet and Wi-Fi), IFT_L2VLAN,
//     IFT_IEEE8023ADLAG (bond), or IFT_BRIDGE. macOS gives the same type
//     to virtual Ethernet interfaces, for example feth and the vmenet
//     interfaces of virtual machines, so they are in @hardware too.
//   - No class: an interface that sends no packet out of the host. Only
//     two interfaces are in this list, each with the family loopback and
//     one type. The loopback interface (lo0, type IFT_LOOP) gives each
//     packet back to the input of the host (lo_output in bsd/net/if_loop.c
//     of xnu). pktap (type IFT_PKTAP) is a capture interface, and its
//     output drops each packet (pktap_if_output in bsd/net/pktap.c). No
//     class selects these interfaces.
//   - @hardware or @tunnel, not certain: every other interface. Its
//     properties do not show its class, so both classes are possible
//     (reconcile.Uncertain): deny_via = ["@hardware"] and deny_via =
//     ["@tunnel"] both block it, and an only_via class never allows it. A
//     policy can allow it by name or glob.
//
// Examples of an uncertain class:
//
//   - ppp (the family ppp or the type IFT_PPP) can be a VPN (L2TP) or a
//     direct link (PPPoE). This rule comes before the @tunnel and
//     @hardware rules, so a ppp property always makes the class
//     uncertain.
//   - stf (6to4) sends IPv6 packets inside IPv4 packets to a public relay.
//     That is a tunnel but not a VPN, so only_via = ["@tunnel"] must not
//     allow it.
//   - The cellular interface pdp_ip, and the redirect interface rd. rd
//     sends its packets to a delegate interface, which can be a cellular,
//     Ethernet, utun, or ipsec interface (bsd/net/if_redirect.c), and pf
//     sees only rd.
//   - An interface with a combination of the properties above that this
//     package does not know, or with an unknown type or family, for
//     example FireWire or an interface of a driver outside xnu. A block
//     rule on an interface that sends no packet blocks nothing.
//
// The uncertain class changes no rule for lo0, and none for the bridge
// and vmenet interfaces of virtual machines: lo0 has no class, and the
// others are @hardware. A rule blocks only the packets to the
// destinations of its policy.
//
// Changes come from a routing socket (AF_ROUTE). macOS has no
// RTM_IFANNOUNCE message. It sends RTM_IFINFO when the flags of an
// interface change, also when an interface that is up goes away, and
// RTM_NEWADDR or RTM_DELADDR when an address changes. A utun that comes
// up through its first address sends RTM_NEWADDR only. An interface that
// is down sends nothing when it appears or goes away, but it also
// carries no traffic. When the receive buffer of the socket is full, the
// kernel drops a message and tells nobody. A large buffer makes this
// rare. The Reconciler reads the interface list again at each self-heal,
// so a dropped change is late, not lost.
package macinventory

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"

	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
)

// Debounce is the time from the first change message to the signal on
// Changes. The messages of one change, for example the address, route,
// and flag messages of a new VPN interface, come within a few
// milliseconds, so they share one signal.
const Debounce = 100 * time.Millisecond

// readSize holds the largest routing message: a header and at most eight
// socket addresses.
const readSize = 4096

// rcvBuf is the receive buffer of the routing socket. The default buffer
// (8 KiB) holds about 20 messages, and the kernel drops the messages that
// do not fit without an error. 1 MiB holds thousands of messages.
const rcvBuf = 1 << 20

// Interface families (IFNET_FAMILY_* in net/kpi_interface.h of xnu).
const (
	familyLoopback = 1
	familyPPP      = 6
	familyGIF      = 10
	familyUTUN     = 17
	familyIPSEC    = 18
)

// siocgiftype is SIOCGIFTYPE, _IOWR('i', 159, struct ifreq) in
// sys/sockio_private.h of xnu. The SDK does not declare it. It needs no
// root.
const siocgiftype = 0xc020699f

var (
	errList  = errors.New("cannot list the network interfaces")
	errWatch = errors.New("cannot read the routing socket")
)

// Inventory reports the network interfaces of macOS. Build one with New.
// Interfaces and Changes are safe for concurrent use.
type Inventory struct {
	list    func() ([]link, error)
	changes chan struct{}
}

var _ reconcile.IfInventory = (*Inventory)(nil)

// link is one interface as the kernel gives it.
type link struct {
	name   string
	flags  int // IFF_* flags
	typ    int // IFT_* type
	family int // IFNET_FAMILY_* family
}

// New returns an inventory of the interfaces of this host. Changes
// receives nothing until Run reads the routing socket.
func New() *Inventory { return newInventory(systemLinks) }

func newInventory(list func() ([]link, error)) *Inventory {
	return &Inventory{list: list, changes: make(chan struct{}, 1)}
}

// Interfaces implements reconcile.IfInventory. It returns every interface
// of the host, also the interfaces that are down, sorted by name. An
// interface has a certain class when its properties show the class, no
// class when it sends no packet out of the host, and both classes as
// possible classes in all other cases (see the package documentation).
// The error wraps errList when
// the kernel cannot give the list, or the type and family of an
// interface in it.
func (i *Inventory) Interfaces(context.Context) ([]reconcile.Interface, error) {
	links, err := i.list()
	if err != nil {
		return nil, err
	}
	out := make([]reconcile.Interface, 0, len(links))
	for _, l := range links {
		out = append(out, classify(l))
	}
	slices.SortFunc(out, func(a, b reconcile.Interface) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

// Changes implements reconcile.IfInventory. The channel holds at most one
// signal: the signals that nobody has received yet merge into one.
func (i *Inventory) Changes() <-chan struct{} { return i.changes }

// Run reads the routing socket until ctx ends, and sends a signal on
// Changes Debounce after the first message of a change. It also sends one
// signal when the socket is open, because the interfaces can have changed
// before Run started to read. The caller owns the goroutine that runs
// Run. Run returns nil when ctx ends, and an error that wraps errWatch
// when it cannot open or read the socket. After Run returns, Changes
// receives nothing more.
func (i *Inventory) Run(ctx context.Context) error {
	f, err := openSocket()
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }() //nolint:errcheck // the socket is read-only: a close error loses nothing
	stop := context.AfterFunc(ctx, func() {
		_ = f.SetReadDeadline(time.Unix(1, 0)) //nolint:errcheck // a failure means that the file is closed and the read is done
	})
	defer stop()
	i.signal()
	return i.watch(ctx, f)
}

// openSocket opens a routing socket with a receive buffer of rcvBuf.
func openSocket() (*os.File, error) {
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return nil, fmt.Errorf("%w: opening the socket: %v", errWatch, err)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, rcvBuf); err != nil {
		_ = unix.Close(fd) //nolint:errcheck // the error below is the cause
		return nil, fmt.Errorf("%w: setting the receive buffer: %v", errWatch, err)
	}
	// A non-blocking descriptor joins the runtime poller, so a read
	// deadline can stop a blocked read.
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd) //nolint:errcheck // the error below is the cause
		return nil, fmt.Errorf("%w: setting the socket non-blocking: %v", errWatch, err)
	}
	return os.NewFile(uintptr(fd), "route"), nil
}

// read is the result of one Read of the routing socket.
type read struct {
	change bool // the message can mean that the interface list changed
	err    error
}

// watch reads routing messages from r until ctx ends or a read fails,
// and sends a signal Debounce after the first change message since the
// last signal. It sends every signal itself, so no signal comes after it
// returns.
func (i *Inventory) watch(ctx context.Context, r io.Reader) error {
	reads := make(chan read)
	var wg sync.WaitGroup
	defer wg.Wait()
	// The reader stops after its first error, and watch returns only
	// after it receives that error.
	wg.Go(func() { readAll(r, reads) })

	var due <-chan time.Time // not nil while a signal is pending
	for {
		select {
		case rd := <-reads:
			switch {
			case rd.err == nil:
				if rd.change && due == nil {
					due = time.After(Debounce)
				}
			case ctx.Err() != nil:
				return nil
			default:
				return fmt.Errorf("%w: %v", errWatch, rd.err)
			}
		case <-due:
			due = nil
			i.signal()
		}
	}
}

// readAll sends the result of each Read of r to out, until a Read fails.
func readAll(r io.Reader, out chan<- read) {
	buf := make([]byte, readSize)
	for {
		n, err := r.Read(buf)
		out <- read{change: err == nil && changes(buf[:n]), err: err}
		if err != nil {
			return
		}
	}
}

func (i *Inventory) signal() {
	select {
	case i.changes <- struct{}{}:
	default: // a signal is waiting already
	}
}

// changes reports whether a routing message can mean that the interface
// list changed. It skips only a well-formed message of another type, so a
// message that it cannot read gives a signal. golang.org/x/net/route does
// not help here: its parser drops an RTM_IFINFO message without
// addresses, which is the form that the socket sends.
func changes(msg []byte) bool {
	// Every routing message starts with rtm_msglen (2 bytes),
	// rtm_version, and rtm_type.
	if len(msg) < 4 || msg[2] != unix.RTM_VERSION {
		return true
	}
	switch msg[3] {
	case unix.RTM_IFINFO, unix.RTM_NEWADDR, unix.RTM_DELADDR:
		return true
	default:
		return false
	}
}

// classify returns the interface l with its class by the rules in the
// package documentation: a certain class, no class, or both classes as
// possible classes. A link that the rules do not know gets the possible
// classes, so that each constraint blocks more (fail closed).
func classify(l link) reconcile.Interface {
	p2p := l.flags&unix.IFF_POINTOPOINT != 0
	switch {
	// The ppp rule comes first: a ppp link that also has the properties
	// of a certain class stays uncertain.
	case l.family == familyPPP || l.typ == unix.IFT_PPP:
		return reconcile.Uncertain(l.name, policy.ClassHardware, policy.ClassTunnel)
	case p2p && slices.Contains([]int{familyUTUN, familyIPSEC, familyGIF}, l.family):
		return reconcile.Interface{Name: l.name, Class: policy.ClassTunnel}
	case !p2p && slices.Contains([]int{unix.IFT_ETHER, unix.IFT_L2VLAN, unix.IFT_IEEE8023ADLAG, unix.IFT_BRIDGE}, l.typ):
		return reconcile.Interface{Name: l.name, Class: policy.ClassHardware}
	case l.family == familyLoopback && (l.typ == unix.IFT_LOOP || l.typ == unix.IFT_PKTAP):
		return reconcile.Interface{Name: l.name}
	default:
		return reconcile.Uncertain(l.name, policy.ClassHardware, policy.ClassTunnel)
	}
}

// systemLinks reads the interface list of the kernel, and the type and
// family of each interface.
func systemLinks() ([]link, error) {
	rib, err := route.FetchRIB(unix.AF_UNSPEC, route.RIBTypeInterface, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errList, err)
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: opening a socket for SIOCGIFTYPE: %v", errList, err)
	}
	defer func() { _ = unix.Close(fd) }() //nolint:errcheck // nothing was written to the socket
	return parseLinks(rib, fd)
}

// parseLinks reads the links of an interface list (NET_RT_IFLIST), and
// gets the type and family of each with SIOCGIFTYPE on fd.
func parseLinks(rib []byte, fd int) ([]link, error) {
	msgs, err := route.ParseRIB(route.RIBTypeInterface, rib)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errList, err)
	}
	var links []link
	for _, m := range msgs {
		im, ok := m.(*route.InterfaceMessage)
		if !ok {
			continue // an address of the interface before it
		}
		l, err := linkOf(fd, im)
		if err != nil {
			return nil, err
		}
		links = append(links, l)
	}
	// ParseRIB skips an RTM_IFINFO message that it cannot read, for
	// example one without a name, and gives no error. A rule cannot apply
	// to an interface that the list does not have.
	if n := ifInfoCount(rib); n != len(links) {
		return nil, fmt.Errorf("%w: the kernel gave %d interfaces, the parser %d", errList, n, len(links))
	}
	return links, nil
}

// ifreqType is struct ifreq with the ifru_type member of the union.
type ifreqType struct {
	name      [unix.IFNAMSIZ]byte
	typ       uint32
	family    uint32
	subfamily uint32
	_         uint32
}

// linkOf completes m with the type and family that SIOCGIFTYPE on fd
// gives.
func linkOf(fd int, m *route.InterfaceMessage) (link, error) {
	var req ifreqType
	if m.Name == "" || len(m.Name) >= len(req.name) {
		return link{}, fmt.Errorf("%w: interface %d has the name %q", errList, m.Index, m.Name)
	}
	copy(req.name[:], m.Name)
	// golang.org/x/sys/unix has no ioctl call that takes any request and
	// any pointer. IoctlSetWinsize gives its pointer to the ioctl of
	// libSystem without a change, and the kernel reads and writes the
	// full ifreqType through it. Winsize is smaller than ifreqType, so the
	// conversion is valid.
	if err := unix.IoctlSetWinsize(fd, siocgiftype, (*unix.Winsize)(unsafe.Pointer(&req))); err != nil {
		return link{}, fmt.Errorf("%w: getting the type of %s: %v", errList, m.Name, err)
	}
	return link{name: m.Name, flags: m.Flags, typ: int(req.typ), family: int(req.family)}, nil
}

// ifInfoCount returns the number of RTM_IFINFO messages in rib.
func ifInfoCount(rib []byte) int {
	n := 0
	for len(rib) >= 4 {
		l := int(binary.NativeEndian.Uint16(rib)) // rtm_msglen
		if l < 4 || l > len(rib) {
			return -1 // the parser gave no error for this, so no count can match
		}
		if rib[3] == unix.RTM_IFINFO {
			n++
		}
		rib = rib[l:]
	}
	return n
}
