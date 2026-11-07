// Package pf controls the pf packet filter of macOS through ioctl calls on
// /dev/pf, without the pfctl command. An ioctl costs microseconds; a start
// of pfctl costs about a millisecond.
//
// The package does only these operations:
//
//   - tables: create a table, add, delete, clear, and list addresses;
//   - states: end the states to a destination prefix;
//   - status: whether pf is enabled;
//   - rules: the rules of a ruleset (the action, the label, and the anchor
//     call of each rule), and the child anchors of an anchor.
//
// It cannot load rules. Most operations need root.
//
// # Platforms
//
// The package supports only macOS (darwin/arm64 and darwin/amd64). The
// pf structs of FreeBSD and OpenBSD are different. On other platforms the
// package compiles, and Open returns an error that wraps
// errors.ErrUnsupported.
//
// The build does not use cgo. The package calls ioctl in libc, as
// golang.org/x/sys/unix does on darwin.
//
// # Struct layout
//
// Apple does not publish the pf structs in the macOS SDK and can change
// them in any release. The Go structs come from the XNU headers in the
// directory xnu/ (the file NOTICE of the repository names the XNU
// release), through cgo -godefs. When a struct size changes, the kernel
// does not know the ioctl number, and the operations return ErrLayout. A
// change of the field order without a size change is not detected at
// runtime: only the comparison tests with pfctl find it.
//
// Tested on:
//
//   - macOS 15 and 26: darwin/arm64 and darwin/amd64, on the GitHub
//     Actions runners;
//   - macOS 27.0: darwin/arm64, and darwin/amd64 under Rosetta.
//
// # Related projects
//
// pfctl-rs (https://github.com/mullvad/pfctl-rs) is a Rust library for pf
// on macOS. It loads rules, but it has no table operations.
package pf
