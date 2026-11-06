# pf

A Go package for the pf packet filter of macOS. It uses ioctl calls on
`/dev/pf`, not the `pfctl` command.

```sh
go get github.com/Nagato-Yuzuru/ifbound/pf
```

It works only on macOS, and most operations need root. The package
documentation on
[pkg.go.dev](https://pkg.go.dev/github.com/Nagato-Yuzuru/ifbound/pf) tells
which operations it has, which macOS versions are tested, and the risk of a
struct layout change in a new macOS release.

Related project: [pfctl-rs](https://github.com/mullvad/pfctl-rs), a Rust
library for pf on macOS.
