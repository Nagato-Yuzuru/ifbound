//go:build !e2e

package main

// upstreamCA returns the CA file for the upstream TLS check. A production
// build always uses the system roots.
func upstreamCA() string { return "" }
