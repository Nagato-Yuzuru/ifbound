package core

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/blockable"
	"github.com/Nagato-Yuzuru/ifbound/internal/hostsfile"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

// TestStepHostReadsModel gives Step random sequences of host events, as
// the shell gives them: a read that a convergence wants, the result of
// each read at once, and stale results between them. It checks the
// determinism, that a failed read keeps the host addresses (fail closed),
// that a good read of a changed version gives a new HostFile, that the
// kernel entries count until the first good read, and that a stale result
// changes nothing.
func TestStepHostReadsModel(t *testing.T) {
	for seed := range uint64(300) {
		m := hostModel{rng: rand.New(rand.NewPCG(seed, 1)), now: t0}
		for i := range 300 {
			if err := m.next(); err != nil {
				t.Fatalf("seed %d, event %d: %v", seed, i, err)
			}
		}
	}
}

// hostModel is what the test knows of the host reads: the read that Step
// started and that has no result yet, and the last good host file.
type hostModel struct {
	rng *rand.Rand
	s   State
	now time.Time
	// hosts and kernel are the reads in flight.
	hosts  *ReadHosts
	kernel *ReadKernelHosts
	// file is the last good host file, and read is true after the first
	// good read. failing is true when a read failed after it.
	file    HostFile
	read    bool
	failing bool
	// version is the version of the host file on disk.
	version hostsfile.Version
}

func (m *hostModel) next() error {
	m.now = m.now.Add(time.Duration(m.rng.IntN(3)) * time.Second)
	if m.rng.IntN(3) == 0 {
		return m.stale()
	}
	switch {
	case m.hosts != nil:
		return m.hostsResult()
	case m.kernel != nil:
		return m.kernelResult()
	case m.rng.IntN(4) == 0:
		_, err := m.step(Tick{At: m.now})
		return err
	default:
		return m.want()
	}
}

func (m *hostModel) want() error {
	effects, err := m.step(HostsWanted{At: m.now})
	if err != nil {
		return err
	}
	if m.hosts == nil {
		return fmt.Errorf("HostsWanted without a read in flight started no host read: %v", effects)
	}
	if want := m.read && !m.failing; m.hosts.Known != want || (want && m.hosts.Last != m.file.Version) {
		return fmt.Errorf("ReadHosts = %+v; want Known %v with the version %v of the last good read", *m.hosts, want, m.file.Version)
	}
	return nil
}

// hostsResult gives a random result for the host read in flight: a
// failure, the known version, a moved version, or new content.
func (m *hostModel) hostsResult() error {
	id, known := m.hosts.ID, m.hosts.Known && m.hosts.Last == m.version
	if m.rng.IntN(3) == 0 {
		m.version = hostsfile.Version{Exists: m.rng.IntN(4) > 0, ModNano: int64(m.rng.IntN(4)), Size: 10}
	}
	ev := HostsRead{At: m.now, ID: id}
	switch m.rng.IntN(4) {
	case 0:
		ev.Err = errRead
	case 1:
		// The version is the known one, or it moved during the read: the
		// shell keeps nothing.
	default:
		if known {
			break
		}
		ev.New, ev.Version, ev.Hosts = true, m.version, randomHosts(m.rng)
	}
	before, beforeOK := m.s.HostFile()
	wasFailing := m.failing
	m.hosts = nil
	effects, err := m.step(ev)
	if err != nil {
		return err
	}
	after, afterOK := m.s.HostFile()
	switch {
	case ev.Err != nil || !ev.New:
		if afterOK != beforeOK || !reflect.DeepEqual(after, before) {
			return fmt.Errorf("a read with no new content (err %v) changed the host file from %+v, %v to %+v, %v", ev.Err, before, beforeOK, after, afterOK)
		}
	case !afterOK || after.ID != id || after.Version != ev.Version || !reflect.DeepEqual(after.Hosts, ev.Hosts):
		return fmt.Errorf("a good read %d of version %v gave the host file %+v, %v", id, ev.Version, after, afterOK)
	case beforeOK && before.Version != ev.Version && after.ID == before.ID:
		return fmt.Errorf("a changed version %v kept the ID %d, so the shell does not map it again", ev.Version, after.ID)
	}
	switch {
	case ev.Err != nil:
		m.failing = true
	case ev.New:
		m.file, m.read, m.failing = after, true, false
	}
	if got, want := countOf[HostsReadFailed](effects), m.failing && !wasFailing; got != b2i(want) {
		return fmt.Errorf("%d HostsReadFailed for a read with err %v after a failing %v, want %v", got, ev.Err, wasFailing, want)
	}
	if p, ok := HostsProblem(m.s); ok != m.failing || (ok && p.Text == "") {
		return fmt.Errorf("HostsProblem = %+v, %v; want a problem %v", p, ok, m.failing)
	}
	if m.read != (m.kernel == nil) {
		return fmt.Errorf("after a host read with a good read %v, the kernel read in flight is %v; want one exactly before the first good read", m.read, m.kernel)
	}
	return nil
}

// kernelResult gives a random result for the kernel read in flight.
func (m *hostModel) kernelResult() error {
	ev := KernelRead{At: m.now, ID: m.kernel.ID}
	if m.rng.IntN(3) == 0 {
		ev.Err = errRead
	} else {
		ev.Addrs = randomAddrs(m.rng)
	}
	before := m.s.KernelHosts()
	m.kernel = nil
	effects, err := m.step(ev)
	if err != nil {
		return err
	}
	after := m.s.KernelHosts()
	switch {
	case ev.Err != nil && !reflect.DeepEqual(after, before):
		return fmt.Errorf("a failed kernel read changed the kernel host entries from %v to %v", before, after)
	case ev.Err == nil && !reflect.DeepEqual(after, ev.Addrs):
		return fmt.Errorf("a good kernel read gave %v, want %v", after, ev.Addrs)
	}
	if got := countOf[KernelHostsFailed](effects); got != b2i(ev.Err != nil) {
		return fmt.Errorf("%d KernelHostsFailed for a kernel read with err %v", got, ev.Err)
	}
	return nil
}

// stale gives a result whose ID is not the one of a read in flight, at
// the current time. It must change nothing.
func (m *hostModel) stale() error {
	id := ReqID(m.rng.IntN(int(m.s.nextID) + 2))
	var ev Event = HostsRead{At: m.s.now, ID: id, New: true, Hosts: randomHosts(m.rng)}
	if m.rng.IntN(2) == 0 {
		ev = KernelRead{At: m.s.now, ID: id, Addrs: randomAddrs(m.rng)}
	}
	if (m.hosts != nil && m.hosts.ID == id) || (m.kernel != nil && m.kernel.ID == id) {
		return nil
	}
	got, effects := Step(m.s, ev)
	if !reflect.DeepEqual(got, m.s) || len(effects) > 0 {
		return fmt.Errorf("stale result %#v changed the state or gave %v", ev, effects)
	}
	return nil
}

// step runs Step twice on the same state, checks that the output is
// equal and that at most one read of each kind is in flight, and records
// the reads that it started.
func (m *hostModel) step(ev Event) ([]Effect, error) {
	s1, effects := Step(m.s, ev)
	s2, again := Step(m.s, ev)
	if !reflect.DeepEqual(s1, s2) || !reflect.DeepEqual(effects, again) {
		return nil, fmt.Errorf("two Step calls on equal input gave different output for %#v", ev)
	}
	m.s = s1
	for _, e := range effects {
		switch e := e.(type) {
		case ReadHosts:
			if m.hosts != nil {
				return nil, fmt.Errorf("a second host read %v started while %v is in flight", e, *m.hosts)
			}
			m.hosts = &e
		case ReadKernelHosts:
			if m.kernel != nil {
				return nil, fmt.Errorf("a second kernel read %v started while %v is in flight", e, *m.kernel)
			}
			m.kernel = &e
		case Converge, ReadAccounts, AccountsOverdue, AccountLookupsFailed, HostsReadFailed, KernelHostsFailed:
		}
	}
	return effects, nil
}

func countOf[T Effect](effects []Effect) int {
	n := 0
	for _, e := range effects {
		if _, ok := e.(T); ok {
			n++
		}
	}
	return n
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// hostAddrs is the pool of host addresses that the random content uses.
var hostAddrs = []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("2001:db8::1")}

func randomHosts(rng *rand.Rand) hostsfile.Hosts {
	var h hostsfile.Hosts
	for range rng.IntN(3) {
		h.Entries = append(h.Entries, hostsfile.Entry{Addr: hostAddrs[rng.IntN(len(hostAddrs))]})
	}
	return h
}

func randomAddrs(rng *rand.Rand) map[policy.Name][]blockable.Addr {
	out := make(map[policy.Name][]blockable.Addr)
	for _, p := range []policy.Name{"work", "home"} {
		if rng.IntN(2) == 0 {
			continue
		}
		a, ok := blockable.New(hostAddrs[rng.IntN(len(hostAddrs))])
		if !ok {
			panic("a pool address is not blockable")
		}
		out[p] = []blockable.Addr{a}
	}
	return out
}
