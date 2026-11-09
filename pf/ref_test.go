package pf

import (
	"encoding/binary"
	"errors"
	"slices"
	"testing"
	"time"
)

// token builds one struct pfioc_token in the layout of the kernel.
func token(value, stamp uint64, pid int32, name string) []byte {
	b := make([]byte, sizeofPfiocToken)
	binary.NativeEndian.PutUint64(b, value)
	binary.NativeEndian.PutUint64(b[offTokenTimestamp:], stamp)
	binary.NativeEndian.PutUint32(b[offTokenPid:], uint32(pid))
	copy(b[offTokenProcName:], name)
	return b
}

func TestDecodeRefs(t *testing.T) {
	b := slices.Concat(
		token(1<<63+5, 1700000000, 796, "pfctl"),
		token(7, 1700000009, 1, "name with spaces"),
	)
	got, err := decodeRefs(b)
	if err != nil {
		t.Fatal(err)
	}
	want := []Ref{
		{Token: 1<<63 + 5, Created: time.Unix(1700000000, 0), PID: 796, Process: "pfctl"},
		{Token: 7, Created: time.Unix(1700000009, 0), PID: 1, Process: "name with spaces"},
	}
	if !slices.EqualFunc(got, want, func(a, b Ref) bool {
		return a.Token == b.Token && a.Created.Equal(b.Created) && a.PID == b.PID && a.Process == b.Process
	}) {
		t.Errorf("decodeRefs = %+v, want %+v", got, want)
	}
}

func TestDecodeRefsFullName(t *testing.T) {
	// A name of 64 bytes has no NUL. It ends at the end of the field, and
	// the next entry must not leak into it.
	name := make([]byte, tokenProcNameSize)
	for i := range name {
		name[i] = 'a'
	}
	got, err := decodeRefs(slices.Concat(token(1, 0, 2, string(name)), token(2, 0, 3, "b")))
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Process != string(name) || got[1].Process != "b" {
		t.Errorf("names = %q and %q", got[0].Process, got[1].Process)
	}
}

func TestDecodeRefsEmpty(t *testing.T) {
	got, err := decodeRefs(nil)
	if err != nil || len(got) != 0 {
		t.Errorf("decodeRefs(nil) = %v, %v; want no entries", got, err)
	}
}

func TestDecodeRefsPartialEntry(t *testing.T) {
	_, err := decodeRefs(make([]byte, sizeofPfiocToken+1))
	if !errors.Is(err, ErrLayout) {
		t.Errorf("a partial entry: got %v, want ErrLayout", err)
	}
}

func TestRefLayout(t *testing.T) {
	// The struct is packed: 8 + 8 + 4 + 64 bytes, with no padding.
	if sizeofPfiocToken != 84 || offTokenTimestamp != 8 || offTokenPid != 16 || offTokenProcName != 20 {
		t.Errorf("struct pfioc_token: size %d, offsets %d, %d, %d; want 84 and 8, 16, 20",
			sizeofPfiocToken, offTokenTimestamp, offTokenPid, offTokenProcName)
	}
}
