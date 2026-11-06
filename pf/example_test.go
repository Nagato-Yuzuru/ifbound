package pf_test

import (
	"fmt"
	"log"

	"github.com/Nagato-Yuzuru/ifbound/pf"
)

// The example needs root and pf, so the tests compile it but do not run
// it.
func Example() {
	h, err := pf.Open()
	if err != nil {
		log.Fatal(err)
	}
	s, err := h.Status()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("pf enabled:", s.Running)
	if err := h.Close(); err != nil {
		log.Fatal(err)
	}
}
