package osnet

// macOS interface setup, routes and gateway lookup (#159, ADR-0100). The
// logic lives in this untagged file so that it is tested on every
// platform with a fake command runner; the *_darwin.go files only wire it
// to the real system.

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

// darwinRunner executes name (an absolute path) with args, never through a
// shell, feeding stdin when it is not nil, and returns the combined
// output. Tests replace it with a recorder.
type darwinRunner func(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error)

// runDarwinCommand is the real darwinRunner. The environment is fixed so
// nothing the caller's shell or an installer left behind reaches a tool
// that runs as root (F-125), and messages stay in English for the checks
// below.
func runDarwinCommand(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C"}
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// macOS system tools by absolute path. All of them live on the sealed,
// read-only system volume, so neither PATH nor a writable folder can
// replace them.
const (
	darwinIfconfig     = "/sbin/ifconfig"
	darwinRoute        = "/sbin/route"
	darwinPfctl        = "/sbin/pfctl"
	darwinNetstat      = "/usr/sbin/netstat"
	darwinNetworksetup = "/usr/sbin/networksetup"
	darwinLaunchctl    = "/bin/launchctl"
	darwinDscacheutil  = "/usr/bin/dscacheutil"
	darwinKillall      = "/usr/bin/killall"
)

// darwinStateDir holds the files OpenScale needs to undo or restore its
// macOS changes (kill switch, exit node DNS). /var/db is the system's
// place for daemon state; only root can write it.
const darwinStateDir = "/var/db/openscale"

// darwinTUNName maps the requested interface name to one macOS accepts:
// wireguard-go creates only "utun" (first free unit) or "utunN". Any other
// name (such as the default "OpenScale") picks the first free unit; the
// caller reads the real name back from the device.
func darwinTUNName(name string) string {
	if n, ok := strings.CutPrefix(name, "utun"); ok && n != "" {
		if v, err := strconv.Atoi(n); err == nil && v >= 0 && strconv.Itoa(v) == n {
			return name
		}
	}
	return "utun"
}

// validDarwinIface reports whether name is a utun interface name, the only
// kind OpenScale creates on macOS. It is also safe inside pf rules and
// command arguments.
func validDarwinIface(name string) bool {
	n, ok := strings.CutPrefix(name, "utun")
	if !ok || n == "" || len(n) > 4 {
		return false
	}
	v, err := strconv.Atoi(n)
	return err == nil && v >= 0 && strconv.Itoa(v) == n
}

// routeExists reports whether route(8) refused to add a route because it
// is already there.
func routeExists(out []byte) bool { return bytes.Contains(out, []byte("File exists")) }

// configureDarwin assigns MTU and addresses, brings the utun interface up
// and routes the overlay prefixes into it. utun is point-to-point, so the
// kernel only installs a host route for the address; the prefixes are
// added explicitly, the way wg-quick does it on macOS. A route that is
// already there is not an error.
func configureDarwin(ctx context.Context, run darwinRunner, c Config) error {
	if !validDarwinIface(c.Interface) {
		return fmt.Errorf("macOS tünel arayüzü utunN olmalı: %q", c.Interface)
	}
	steps := [][]string{
		{c.Interface, "mtu", strconv.Itoa(c.MTU)},
		{c.Interface, "inet", c.IPv4.String(), c.IPv4.Addr().String(), "alias"},
		{c.Interface, "inet6", c.IPv6.Addr().String(), "prefixlen", strconv.Itoa(c.IPv6.Bits()), "alias"},
		{c.Interface, "up"},
	}
	for _, args := range steps {
		if _, err := run(ctx, nil, darwinIfconfig, args...); err != nil {
			return err
		}
	}
	routes := []struct {
		family string
		prefix netip.Prefix
	}{
		{"-inet", c.IPv4.Masked()},
		{"-inet6", c.IPv6.Masked()},
	}
	for _, r := range routes {
		out, err := run(ctx, nil, darwinRoute, "-q", "-n", "add", r.family, r.prefix.String(), "-interface", c.Interface)
		if err != nil && !routeExists(out) {
			return err
		}
	}
	return nil
}

// darwinDefaultRoute is one "default" line of `netstat -rn -f inet`.
type darwinDefaultRoute struct {
	Gateway string
	Flags   string
	Netif   string
}

// scoped reports an interface-scoped default route (flag I): macOS keeps
// one per interface for sockets bound to it; the unscoped one is the
// system's choice.
func (r darwinDefaultRoute) scoped() bool { return strings.Contains(r.Flags, "I") }

// parseDarwinDefaultRoutes reads the default routes of `netstat -rn -f
// inet` (or inet6). Columns: Destination Gateway Flags Netif [Expire].
// Routes through a utun interface (OpenScale or another VPN) are skipped:
// they never lead to the physical network.
func parseDarwinDefaultRoutes(out []byte) []darwinDefaultRoute {
	var routes []darwinDefaultRoute
	s := bufio.NewScanner(bytes.NewReader(out))
	for s.Scan() {
		f := strings.Fields(s.Text())
		if len(f) < 4 || f[0] != "default" {
			continue
		}
		if strings.HasPrefix(f[3], "utun") || strings.HasPrefix(f[3], "lo") {
			continue
		}
		routes = append(routes, darwinDefaultRoute{Gateway: f[1], Flags: f[2], Netif: f[3]})
	}
	return routes
}

// darwinPhysicalDefault returns the default route the system uses for the
// physical network: the first unscoped one, else the first scoped one.
func darwinPhysicalDefault(routes []darwinDefaultRoute) (darwinDefaultRoute, bool) {
	for _, r := range routes {
		if !r.scoped() {
			return r, true
		}
	}
	if len(routes) > 0 {
		return routes[0], true
	}
	return darwinDefaultRoute{}, false
}

// defaultRoutesDarwin asks netstat for the IPv4 default routes. It changes
// nothing.
func defaultRoutesDarwin(ctx context.Context, run darwinRunner) ([]darwinDefaultRoute, error) {
	out, err := run(ctx, nil, darwinNetstat, "-rn", "-f", "inet")
	if err != nil {
		return nil, err
	}
	return parseDarwinDefaultRoutes(out), nil
}

// defaultGatewaysDarwin returns the IPv4 next hops of the physical default
// routes, the system's choice first. Interface routes (gateway is a link
// such as "link#6") have no next hop. No default route is not an error.
func defaultGatewaysDarwin(ctx context.Context, run darwinRunner) ([]netip.Addr, error) {
	routes, err := defaultRoutesDarwin(ctx, run)
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	add := func(r darwinDefaultRoute) {
		a, err := netip.ParseAddr(r.Gateway)
		if err != nil || !a.Is4() || a.IsUnspecified() {
			return
		}
		for _, have := range out {
			if have == a {
				return
			}
		}
		out = append(out, a)
	}
	if r, ok := darwinPhysicalDefault(routes); ok {
		add(r)
	}
	for _, r := range routes {
		add(r)
	}
	return out, nil
}
