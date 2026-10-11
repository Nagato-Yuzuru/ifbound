package dnsname

import (
	"strings"
	"testing"
)

// escapedName spells n labels of the given lengths with every octet as
// "\DDD" and a final dot: the longest text for these labels.
func escapedName(lens []int) string {
	var b strings.Builder
	for _, l := range lens {
		b.WriteString(strings.Repeat(`\097`, l))
		b.WriteByte('.')
	}
	return b.String()
}

// spread splits total octets over n labels of at most 63 octets.
func spread(n, total int) []int {
	lens := make([]int, n)
	for i := range lens {
		lens[i] = min(maxLabelLen, total-(n-1-i)) // leave one octet per later label
		total -= lens[i]
	}
	return lens
}

// For each label count, the name with the most octets that the wire
// limit allows, fully escaped, is valid and fits the bound. One octet
// more is invalid. The longest of them is exactly the bound.
func TestMaxTextLenIsTight(t *testing.T) {
	t.Parallel()
	longest := 0
	for n := 1; n <= (maxWireLen-1)/2; n++ {
		octets := min(maxLabelLen*n, maxWireLen-1-n)
		s := escapedName(spread(n, octets))
		labels, err := Split(s)
		if err != nil || len(labels) != n {
			t.Fatalf("n=%d: Split of %d bytes = %d labels, %v", n, len(s), len(labels), err)
		}
		if len(s) > maxTextLen {
			t.Fatalf("n=%d: valid text of %d bytes exceeds the bound %d", n, len(s), maxTextLen)
		}
		longest = max(longest, len(s))
		if octets < maxLabelLen*n {
			if _, err := split(escapedName(spread(n, octets+1))); err == nil {
				t.Fatalf("n=%d: %d octets passed the wire limit", n, octets+1)
			}
		}
	}
	if longest != maxTextLen {
		t.Fatalf("longest valid text = %d, bound = %d", longest, maxTextLen)
	}
}

// Every one-byte insertion into the longest valid text is invalid even
// without the early length check. So the check refuses no valid name at
// that length.
func TestOneByteOverBoundIsInvalid(t *testing.T) {
	t.Parallel()
	s := escapedName([]int{63, 63, 63, 61})
	if len(s) != maxTextLen {
		t.Fatalf("len = %d, want %d", len(s), maxTextLen)
	}
	if _, err := Split(s); err != nil {
		t.Fatalf("Split at the bound: %v", err)
	}
	for i := range len(s) + 1 {
		for _, c := range []string{"a", ".", `\`, "0", "9"} {
			over := s[:i] + c + s[i:]
			if _, err := split(over); err == nil {
				t.Fatalf("valid text of %d bytes: %q", len(over), over)
			}
			if _, err := Split(over); err == nil {
				t.Fatalf("Split accepted %d bytes", len(over))
			}
		}
	}
}

// A huge input is refused before any work that grows with it.
func TestSplitRefusesHugeInputEarly(t *testing.T) {
	huge := strings.Repeat("a.", 5<<20)
	allocs := testing.AllocsPerRun(10, func() {
		if _, err := Split(huge); err == nil {
			t.Fatal("Split accepted a huge input")
		}
	})
	if allocs != 0 {
		t.Fatalf("Split allocated %v times", allocs)
	}
}

// No text that split accepts is longer than the bound.
func FuzzSplitBound(f *testing.F) {
	f.Add(escapedName([]int{63, 63, 63, 61}))
	f.Add(escapedName([]int{63, 63, 63, 61}) + "a")
	f.Add(strings.Repeat("a.", 127))
	f.Fuzz(func(t *testing.T, s string) {
		if _, err := split(s); err == nil && len(s) > maxTextLen {
			t.Fatalf("split accepted %d bytes", len(s))
		}
	})
}
