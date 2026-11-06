package pf_test

import (
	"errors"
	"fmt"
	"log"
	"net/netip"

	"github.com/Nagato-Yuzuru/ifbound/pf"
)

// The example needs root and pf, so the tests compile it but do not run
// it.
func Example() {
	h, err := pf.Open()
	if err != nil {
		log.Fatal(err)
	}

	tbl := pf.Table{Anchor: "example", Name: "blocked"}
	if err := h.CreateTable(tbl); err != nil {
		log.Fatal(err)
	}
	dst := netip.MustParsePrefix("192.0.2.0/24")
	fb, err := h.AddAddrs(tbl, []pf.Addr{{Prefix: dst}})
	if err != nil {
		log.Fatal(err)
	}
	if fb[0] == pf.FeedbackConflict {
		log.Fatalf("the table holds !%s", dst)
	}
	// Connections that pf let through before keep their states. End them.
	if err := h.KillStates(dst); err != nil {
		log.Fatal(err)
	}

	if _, err := h.Addrs(pf.Table{Anchor: "example", Name: "missing"}); errors.Is(err, pf.ErrNotFound) {
		fmt.Println("no such table")
	}
	if err := h.Close(); err != nil {
		log.Fatal(err)
	}
}
