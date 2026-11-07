package osnet

// FreeBSD and OpenBSD interface setup (F-143, ADR-0090). The logic lives in
// this untagged file so that it is tested on every platform with a fake
// command runner; osnet_bsd.go only wires it to the real system.

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
)

// bsdRunner executes name with args (never through a shell) and returns the
// combined output. Tests replace it with a recorder.
type bsdRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

// runBSDCommand is the real bsdRunner. name is always an absolute path;
// the environment is fixed so nothing the caller's shell left behind
// reaches the tool, and messages stay in English for the checks below.
func runBSDCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{"PATH=/sbin:/bin:/usr/sbin:/usr/bin", "LANG=C", "LC_ALL=C"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// bsdFlavor selects the differences between the two systems.
type bsdFlavor int

const (
	flavorFreeBSD bsdFlavor = iota
	flavorOpenBSD
)

// The BSD tools live in /sbin on both systems. Absolute paths keep a
// manipulated PATH from choosing the program (same reasoning as F-125).
const (
	bsdIfconfig = "/sbin/ifconfig"
	bsdRoute    = "/sbin/route"
)

// configureBSD assigns MTU and addresses and brings the interface up.
//
// FreeBSD: wireguard-go switches the tun out of point-to-point mode
// (IFF_BROADCAST), so "inet A/len" creates the connected route for the
// whole overlay by itself.
//
// OpenBSD: the tun stays point-to-point, so the kernel only installs a host
// route; the overlay prefixes are added explicitly through the interface
// address, the way wg-quick does it on OpenBSD. A route that already
// exists is not an error.
func configureBSD(ctx context.Context, run bsdRunner, flavor bsdFlavor, c Config) error {
	steps := [][]string{
		{c.Interface, "mtu", strconv.Itoa(c.MTU)},
		{c.Interface, "inet", c.IPv4.String(), "alias"},
		{c.Interface, "inet6", c.IPv6.Addr().String(), "prefixlen", strconv.Itoa(c.IPv6.Bits()), "alias"},
		{c.Interface, "up"},
	}
	for _, args := range steps {
		if _, err := run(ctx, bsdIfconfig, args...); err != nil {
			return err
		}
	}
	if flavor != flavorOpenBSD {
		return nil
	}
	routes := []struct {
		family string
		prefix netip.Prefix
		via    netip.Addr
	}{
		{"-inet", c.IPv4.Masked(), c.IPv4.Addr()},
		{"-inet6", c.IPv6.Masked(), c.IPv6.Addr()},
	}
	for _, r := range routes {
		out, err := run(ctx, bsdRoute, "-q", "-n", "add", r.family, r.prefix.String(), "-iface", r.via.String())
		if err != nil && !bytes.Contains(out, []byte("File exists")) {
			return err
		}
	}
	return nil
}

// defaultGatewaysBSD asks the routing socket through route(8) for the IPv4
// default route. It changes nothing. No default route is not an error.
func defaultGatewaysBSD(ctx context.Context, run bsdRunner) ([]netip.Addr, error) {
	out, err := run(ctx, bsdRoute, "-n", "get", "-inet", "default")
	if err != nil {
		if bytes.Contains(out, []byte("not in table")) || bytes.Contains(out, []byte("network is unreachable")) {
			return nil, nil
		}
		return nil, err
	}
	if gw, ok := parseRouteGetGateway(out); ok {
		return []netip.Addr{gw}, nil
	}
	return nil, nil
}

// parseRouteGetGateway reads the "gateway:" line of `route -n get`. An
// interface route (gateway is a link name) has no IPv4 next hop.
func parseRouteGetGateway(out []byte) (netip.Addr, bool) {
	s := bufio.NewScanner(bytes.NewReader(out))
	for s.Scan() {
		key, value, ok := strings.Cut(strings.TrimSpace(s.Text()), ":")
		if !ok || strings.TrimSpace(key) != "gateway" {
			continue
		}
		a, err := netip.ParseAddr(strings.TrimSpace(value))
		if err != nil || !a.Is4() || a.IsUnspecified() {
			return netip.Addr{}, false
		}
		return a, true
	}
	return netip.Addr{}, false
}

// openBSDTUNName maps the requested interface name to one OpenBSD accepts.
// OpenBSD tun devices cannot be renamed: wireguard-go only takes "tunN" or
// "tun" (first free unit). Any other name (such as the default
// "OpenScale") picks the first free unit; the caller reads the real name
// back from the device.
func openBSDTUNName(name string) string {
	if n, ok := strings.CutPrefix(name, "tun"); ok {
		if n == "" {
			return name
		}
		if v, err := strconv.Atoi(n); err == nil && v >= 0 && strconv.Itoa(v) == n {
			return name
		}
	}
	return "tun"
}
