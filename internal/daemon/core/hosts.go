package core

import (
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/blockable"
	"github.com/Nagato-Yuzuru/ifbound/internal/hostsfile"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
)

// HostFile is the content of one good read of the host file. macOS
// answers a name from the host file before it asks DNS, so a host entry
// for a protected name never reaches ifbound-dns. Its address goes into
// the table of each matching policy instead. The file is the source of
// truth for these addresses: they do not expire and are not in the book.
type HostFile struct {
	// ID is the read that gave the content. Each good read that reads
	// the content has a new ID, so the shell maps the entries again.
	ID      ReqID
	Version hostsfile.Version
	// Hosts is the content. A missing file is a good read with no
	// entries.
	Hosts hostsfile.Hosts
}

// HostsWanted asks for a read of the host file. Each convergence asks
// for it first: adoption and the tables must know the host addresses.
type HostsWanted struct{ At time.Time }

// HostsRead is the result of the host file read ID. Err is the error of
// Version or of Read: the reader cannot tell the content of the file. A
// file that exists and cannot be read keeps the last good content: other
// readers can still read it, so its entries can be in use.
//
// With a nil Err, New tells that the shell read content that it keeps:
// Version and Hosts then hold it. New is false when the file has the
// known version of ReadHosts, or when the version moved during the read:
// a writer that is not done can leave a part of the file or no file, and
// the next read reads again. Then nothing changes.
type HostsRead struct {
	At      time.Time
	ID      ReqID
	New     bool
	Version hostsfile.Version
	Hosts   hostsfile.Hosts
	Err     error
}

// KernelRead is the result of the read ID of the kernel host entries:
// the learned-looking entries of the tables of each policy.
type KernelRead struct {
	At    time.Time
	ID    ReqID
	Addrs map[policy.Name][]blockable.Addr
	Err   error
}

func (e HostsWanted) at() time.Time { return e.At }
func (e HostsRead) at() time.Time   { return e.At }
func (e KernelRead) at() time.Time  { return e.At }

// ReadHosts starts the read ID of the host file. Its result is a
// HostsRead with the same ID. When Known is true, Last is the version of
// a good read with no failed read after it: the shell then does not read
// the content of that version again.
type ReadHosts struct {
	ID    ReqID
	Last  hostsfile.Version
	Known bool
}

// ReadKernelHosts starts the read ID of the learned-looking kernel
// entries of the configured policies. Its result is a KernelRead with the
// same ID.
type ReadKernelHosts struct{ ID ReqID }

// HostsReadFailed tells that a host file read failed, at the first
// failure after a good read or at start.
type HostsReadFailed struct{ Err error }

// KernelHostsFailed tells that a read of the kernel host entries failed.
// The kernel host entries of the last good read stay.
type KernelHostsFailed struct{ Err error }

func (ReadHosts) isEffect()         {}
func (ReadHosts) isSync()           {}
func (ReadKernelHosts) isEffect()   {}
func (ReadKernelHosts) isSync()     {}
func (HostsReadFailed) isEffect()   {}
func (HostsReadFailed) isOut()      {}
func (KernelHostsFailed) isEffect() {}
func (KernelHostsFailed) isOut()    {}

// syncBudget is the budget of a sync read. The loop waits for the read,
// so nothing checks its deadline.
const syncBudget = 0

// HostFile returns the content of the last good host file read. It
// reports false before the first good read.
func (s State) HostFile() (HostFile, bool) {
	last, ok := s.hosts.Last()
	return last.Value, ok
}

// KernelHosts returns the kernel host entries of the last good kernel
// read, or nil before it. They count as host addresses until a read of
// the host file is good: the last run can have put host addresses in the
// tables, and the file can still have their entries.
func (s State) KernelHosts() map[policy.Name][]blockable.Addr {
	last, _ := s.kernelHosts.Last()
	return last.Value
}

// HostsProblem returns the Problem of a failed host file read, if there
// is one. It does not void enforcement: the tables keep the host
// addresses that they have.
func HostsProblem(s State) (reconcile.Problem, bool) {
	f, failing := s.hosts.Failing()
	if !failing {
		return reconcile.Problem{}, false
	}
	return reconcile.Problem{Text: "the host file cannot be read, so changes to its entries for protected names are not applied: " + f.Err.Error()}, true
}

// readHosts starts a read of the host file. During a read it starts
// nothing: the next read starts when the read in flight ends.
func (s State) readHosts(out []Effect) (State, []Effect) {
	id := s.nextID + 1
	o, started := s.hosts.Start(id, s.now, syncBudget)
	s.hosts = o
	if !started {
		return s, out
	}
	s.nextID = id
	e := ReadHosts{ID: id}
	if last, ok := o.Last(); ok {
		_, failing := o.Failing()
		e.Last, e.Known = last.Value.Version, !failing
	}
	return s, append(out, e)
}

// applyHosts ends the host file read of ev. While no read of the host
// file is good, it then starts a read of the kernel host entries. It
// changes nothing for the result of another read.
func (s State) applyHosts(ev HostsRead, out []Effect) (State, []Effect) {
	_, wasFailing := s.hosts.Failing()
	var (
		o  Observed[HostFile]
		ok bool
	)
	switch {
	case ev.Err != nil:
		o, ok = s.hosts.Finish(ev.ID, HostFile{}, ev.Err, s.now)
	case ev.New:
		o, ok = s.hosts.Finish(ev.ID, HostFile{ID: ev.ID, Version: ev.Version, Hosts: ev.Hosts}, nil, s.now)
	default:
		o, ok = s.hosts.Keep(ev.ID, s.now)
	}
	if !ok {
		return s, out
	}
	s.hosts = o
	if f, failing := o.Failing(); failing && !wasFailing {
		out = append(out, HostsReadFailed{Err: f.Err})
	}
	if o.Again() {
		return s.readHosts(out)
	}
	if _, read := o.Last(); !read {
		return s.readKernelHosts(out)
	}
	return s, out
}

// readKernelHosts starts a read of the kernel host entries. During a
// read it starts nothing: the next read starts when the read in flight
// ends.
func (s State) readKernelHosts(out []Effect) (State, []Effect) {
	id := s.nextID + 1
	o, started := s.kernelHosts.Start(id, s.now, syncBudget)
	s.kernelHosts = o
	if !started {
		return s, out
	}
	s.nextID = id
	return s, append(out, ReadKernelHosts{ID: id})
}

// applyKernelHosts ends the kernel read of ev. A failed read keeps the
// kernel host entries of the last good one. It changes nothing for the
// result of another read.
func (s State) applyKernelHosts(ev KernelRead, out []Effect) (State, []Effect) {
	o, ok := s.kernelHosts.Finish(ev.ID, ev.Addrs, ev.Err, s.now)
	if !ok {
		return s, out
	}
	s.kernelHosts = o
	if ev.Err != nil {
		out = append(out, KernelHostsFailed{Err: ev.Err})
	}
	if o.Again() {
		return s.readKernelHosts(out)
	}
	return s, out
}
