package hostsfile

import (
	"fmt"
	"strings"
	"testing"
)

// BenchmarkParseBlocklist parses a block list of 150k lines, the size of
// a large ad-blocking host file.
func BenchmarkParseBlocklist(b *testing.B) {
	var sb strings.Builder
	for i := range 150_000 {
		fmt.Fprintf(&sb, "0.0.0.0 ads%d.tracker%d.example.com\n", i, i%977)
	}
	s := sb.String()
	b.ReportAllocs()
	b.SetBytes(int64(len(s)))
	for b.Loop() {
		if _, err := Parse(strings.NewReader(s)); err != nil {
			b.Fatal(err)
		}
	}
}
