package pf

import (
	"errors"
	"io/fs"
	"syscall"
	"testing"
	"unsafe"
)

// TestLayout checks the Go structs against the C sizes. An ioctl number
// encodes the size of its C struct (cgo took the numbers from the header),
// so the size in the number must be the size of the Go struct.
func TestLayout(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("the layout is for 64-bit platforms")
	}
	ioctlSize := func(req uint) uintptr { return uintptr(req>>16) & 0x1fff }
	tests := []struct {
		name string
		req  uint
		size uintptr
	}{
		{"DIOCGETSTATUS", diocGetStatus, unsafe.Sizeof(pfStatus{})},
		{"DIOCRADDTABLES", diocRAddTables, unsafe.Sizeof(pfiocTable{})},
		{"DIOCRCLRADDRS", diocRClrAddrs, unsafe.Sizeof(pfiocTable{})},
		{"DIOCRADDADDRS", diocRAddAddrs, unsafe.Sizeof(pfiocTable{})},
		{"DIOCRDELADDRS", diocRDelAddrs, unsafe.Sizeof(pfiocTable{})},
		{"DIOCRGETADDRS", diocRGetAddrs, unsafe.Sizeof(pfiocTable{})},
		{"DIOCKILLSTATES", diocKillStates, unsafe.Sizeof(pfiocStateKill{})},
		{"DIOCGETRULES", diocGetRules, unsafe.Sizeof(pfiocRule{})},
		{"DIOCGETRULE", diocGetRule, unsafe.Sizeof(pfiocRule{})},
		{"DIOCGETRULESETS", diocGetRulesets, unsafe.Sizeof(pfiocRuleset{})},
		{"DIOCGETRULESET", diocGetRuleset, unsafe.Sizeof(pfiocRuleset{})},
		{"DIOCSTARTREF", diocStartRef, unsafe.Sizeof(uint64(0))},
		{"DIOCSTOPREF", diocStopRef, unsafe.Sizeof(pfiocRemoveToken{})},
		{"DIOCGETSTARTERS", diocGetStarters, unsafe.Sizeof(pfiocTokens{})},
	}
	for _, tt := range tests {
		if got := ioctlSize(tt.req); got != tt.size {
			t.Errorf("%s encodes size %d, Go struct has %d", tt.name, got, tt.size)
		}
	}
	// The kernel reads the address and the mask of psk_dst from the start
	// of the union of struct pf_addr_wrap.
	if got := unsafe.Sizeof(pfAddrWrap{}.V); got != 32 {
		t.Errorf("the union of pf_addr_wrap has size %d, want 32", got)
	}
	if got := unsafe.Sizeof(pfiocRule{}); got != sizeofPfiocRule {
		t.Errorf("pfiocRule has size %d, C has %d", got, sizeofPfiocRule)
	}
	if offIocRuleRule+sizeofPfRule != sizeofPfiocRule {
		t.Errorf("struct pf_rule is not the last field of struct pfioc_rule")
	}
}

func TestSetName(t *testing.T) {
	var dst [8]int8
	for i := range dst {
		dst[i] = 'x'
	}
	if err := setName(dst[:], "abc"); err != nil {
		t.Fatal(err)
	}
	if got := cString(dst[:]); got != "abc" {
		t.Errorf("cString after setName = %q, want %q", got, "abc")
	}
	if dst[7] != 0 {
		t.Errorf("setName left old bytes after the name: %v", dst)
	}
	if err := setName(dst[:], "1234567"); err != nil {
		t.Errorf("setName of the longest name: %v", err)
	}
	for _, bad := range []string{"12345678", "a\x00b"} {
		if err := setName(dst[:], bad); !errors.Is(err, errName) {
			t.Errorf("setName(%q): got %v, want errName", bad, err)
		}
	}
	full := [3]byte{'a', 'b', 'c'}
	if got := cString(full[:]); got != "abc" {
		t.Errorf("cString of an array with no NUL = %q, want %q", got, "abc")
	}
}

// TestMapErrno covers the errnos that the e2e tests cannot cause on a
// real kernel. The e2e tests check ESRCH and EINVAL.
func TestMapErrno(t *testing.T) {
	tests := []struct {
		err  error
		want error
	}{
		// DIOCGETRULE with a stale ticket.
		{syscall.EBUSY, ErrChanged},
		{syscall.ENODEV, ErrLayout},
		{syscall.EPERM, fs.ErrPermission},
		{syscall.EACCES, fs.ErrPermission},
		{fs.ErrClosed, fs.ErrClosed},
	}
	for _, tt := range tests {
		if got := mapErrno(tt.err, 0); !errors.Is(got, tt.want) {
			t.Errorf("mapErrno(%v) = %v, want %v", tt.err, got, tt.want)
		}
	}
	// An errno without a meaning in this package does not become a part
	// of the error contract.
	if got := mapErrno(syscall.ESRCH, 0); errors.Is(got, syscall.ESRCH) || errors.Is(got, ErrNotFound) {
		t.Errorf("mapErrno(ESRCH, 0) = %v, want an opaque error", got)
	}
}
