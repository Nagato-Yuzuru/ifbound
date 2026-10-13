package macresolver

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"
)

var errConfig = errors.New("cannot read the resolver configuration")

const (
	scutilPath = "/usr/sbin/scutil"
	// scutilWait is the upper bound of one scutil call. It is a backstop:
	// the caller passes its own budget as the deadline of ctx.
	scutilWait = 5 * time.Second
	// The headers of the sections in the output of "scutil --dns". The
	// first section holds the resolvers for unscoped queries. The later
	// sections, for example the one for scoped queries, start with
	// sectionPrefix and apply only to queries for one interface or
	// service.
	sectionMain   = "DNS configuration"
	sectionPrefix = "DNS configuration ("
)

// Scutil reads the resolver configuration with "scutil --dns", which
// prints what dns_configuration_copy returns. A command keeps the build
// free of cgo, as the release and the end-to-end builds need. The zero
// value is ready to use.
type Scutil struct{}

var _ ConfigSource = Scutil{}

// Resolvers implements ConfigSource.
func (Scutil) Resolvers(ctx context.Context) ([]ConfigEntry, error) {
	ctx, cancel := context.WithTimeout(ctx, scutilWait)
	defer cancel()
	out, err := exec.CommandContext(ctx, scutilPath, "--dns").Output()
	if err != nil {
		return nil, fmt.Errorf("%w: %s --dns: %v", errConfig, scutilPath, err)
	}
	return parseScutil(out)
}

// parseScutil reads the resolvers of the first section of the output of
// "scutil --dns". It refuses output that does not start with that
// section or that has a line without a "key : value" shape in a resolver
// block, so a change of the format gives an error, not a missed resolver.
// A value that it cannot read gives a safe value instead of an error, so
// one odd value does not hide every other resolver: see ConfigEntry.
func parseScutil(out []byte) ([]ConfigEntry, error) {
	var res []ConfigEntry
	started := false
	for line := range strings.Lines(string(out)) {
		line = strings.TrimRight(line, "\r\n")
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "":
			continue
		case !started:
			if line != sectionMain {
				return nil, fmt.Errorf("%w: unexpected first line %q", errConfig, line)
			}
			started = true
		case strings.HasPrefix(line, sectionPrefix):
			return res, nil
		case strings.HasPrefix(line, "resolver #"):
			res = append(res, ConfigEntry{Port: dnsPort})
		case len(res) == 0:
			return nil, fmt.Errorf("%w: line before the first resolver: %q", errConfig, line)
		default:
			if err := setField(&res[len(res)-1], trimmed); err != nil {
				return nil, err
			}
		}
	}
	if !started {
		return nil, fmt.Errorf("%w: empty output", errConfig)
	}
	return res, nil
}

// setField applies one "key : value" line to c. It ignores keys that do
// not matter for routing by domain. It refuses a line without a key. A
// value that it cannot read never makes c look like an ifbound file or
// like a resolver that loses against one.
func setField(c *ConfigEntry, line string) error {
	key, val, ok := strings.Cut(line, ":")
	if !ok {
		return fmt.Errorf("%w: line without a key: %q", errConfig, line)
	}
	key, val = strings.TrimSpace(key), strings.TrimSpace(val)
	switch {
	case key == "domain":
		c.Domain = strings.ToLower(strings.TrimSuffix(val, "."))
	case strings.HasPrefix(key, "nameserver["):
		a, err := netip.ParseAddr(val)
		if err != nil {
			a = netip.Addr{}
		}
		c.Servers = append(c.Servers, a)
	case key == "port":
		p, err := strconv.ParseUint(val, 10, 16)
		if err != nil {
			p = 0
		}
		c.Port = uint16(p)
	case key == "order":
		o, err := strconv.ParseUint(val, 10, 32)
		if err != nil {
			o = 0
		}
		c.Order = uint32(o)
	case key == "flags":
		c.Supplemental = slices.Contains(strings.Split(val, ", "), "Supplemental")
	}
	return nil
}
