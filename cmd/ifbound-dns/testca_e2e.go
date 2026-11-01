//go:build e2e

package main

import "os"

// testCAEnv names the environment variable with the path of a CA file.
const testCAEnv = "IFBOUND_TEST_UPSTREAM_CA"

// upstreamCA returns the CA file for the upstream TLS check. Only a build
// with the e2e tag has this code, so a test can trust its own upstream.
func upstreamCA() string { return os.Getenv(testCAEnv) }
