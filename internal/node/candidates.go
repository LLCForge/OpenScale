package node

import (
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/openscale/openscale/internal/control"
)

// Endpoint candidates (ADR-0025, F-002, F-012): the addresses other devices
// may try to reach this device's WireGuard port at. The coordinator adds
// the address it observes; this device adds its interface addresses and the
// owner's static endpoints.

// defaultSkipInterfaces are name prefixes of virtual interfaces whose
// addresses no other device can reach (container bridges, hypervisors,
// other VPNs). Matching is case-insensitive.
var defaultSkipInterfaces = []string{
	"docker", "br-", "veth", "virbr", "vmnet", "vboxnet", "vethernet", "virtualbox", "vmware",
	"tailscale", "zt", "wg", "utun", "tun", "tap", "lxc", "lxd", "cni", "flannel", "cali", "podman",
}

// pathClass ranks how a peer is reached; higher is better (ADR-0025:
// LAN > IPv6 > public IPv4 > relay).
type pathClass int

const (
	classNone pathClass = iota
	classRelay
	classPublic4
	classIPv6
	classLAN
)

func (c pathClass) String() string {
	switch c {
	case classRelay:
		return "aktarıcı"
	case classPublic4:
		return "dış IPv4"
	case classIPv6:
		return "IPv6"
	case classLAN:
		return "yerel ağ"
	default:
		return "yok"
	}
}

// classify ranks a direct endpoint.
func classify(ap netip.AddrPort) pathClass {
	if !ap.IsValid() {
		return classNone
	}
	a := ap.Addr().Unmap()
	switch {
	case a.IsPrivate() || a.IsLoopback():
		return classLAN
	case a.Is6():
		return classIPv6
	default:
		return classPublic4
	}
}

// skipInterface reports whether an interface's addresses are left out.
func skipInterface(name string, extra []string) bool {
	n := strings.ToLower(name)
	for _, p := range defaultSkipInterfaces {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	for _, p := range extra {
		if p != "" && strings.HasPrefix(n, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

// interfaceAddr is one address of an interface that is up.
type interfaceAddr struct {
	iface string
	addr  netip.Addr
}

// listInterfaceAddrs returns the addresses of every interface that is up,
// except loopback. Replaced in tests.
var listInterfaceAddrs = func() ([]interfaceAddr, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []interfaceAddr
	for _, ifi := range ifs {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if addr, ok := netip.AddrFromSlice(ipn.IP); ok {
				out = append(out, interfaceAddr{iface: ifi.Name, addr: addr.Unmap()})
			}
		}
	}
	return out, nil
}

// localCandidates picks up to max interface addresses with port: private
// IPv4 first, then global IPv6 (at most two per interface, since privacy
// addresses multiply), then public IPv4. Tunnel, overlay, link-local and
// skipped interfaces are left out.
func localCandidates(addrs []interfaceAddr, port uint16, tunnel string, overlay []netip.Prefix, skip []string, maxN int) []netip.AddrPort {
	var lan, v6, pub []netip.AddrPort
	perIface6 := map[string]int{}
	for _, ia := range addrs {
		a := ia.addr
		if ia.iface == tunnel || skipInterface(ia.iface, skip) || inAny(overlay, a) {
			continue
		}
		if a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsUnspecified() || a.Zone() != "" {
			continue
		}
		ap := netip.AddrPortFrom(a, port)
		switch {
		case a.Is4() && a.IsPrivate():
			lan = append(lan, ap)
		case a.Is6():
			if perIface6[ia.iface] >= 2 {
				continue
			}
			perIface6[ia.iface]++
			v6 = append(v6, ap)
		default:
			pub = append(pub, ap)
		}
	}
	var all []netip.AddrPort
	for _, ap := range slices.Concat(lan, v6, pub) {
		if !slices.Contains(all, ap) {
			all = append(all, ap)
		}
	}
	if len(all) > maxN {
		all = all[:maxN]
	}
	return all
}

// gatherCandidates returns what this device reports to the coordinator:
// the owner's static endpoints first (F-012), then, unless hidden, its
// interface addresses on the WireGuard port.
func (e *Engine) gatherCandidates(port uint16) []netip.AddrPort {
	out := slices.Clone(e.cfg.StaticEndpoints)
	for _, ap := range e.p03.names.current() { // #387
		if !slices.Contains(out, ap) {
			out = append(out, ap)
		}
	}
	if len(out) > control.MaxCandidates {
		out = out[:control.MaxCandidates]
	}
	// The router-mapped public address (ADR-0042) is not a local address:
	// it is reported even when local candidates are hidden.
	if ap, ok := e.mappedCandidate(); ok && len(out) < control.MaxCandidates && !slices.Contains(out, ap) {
		out = append(out, ap)
	}
	if e.cfg.HideLocalCandidates || len(out) >= control.MaxCandidates {
		return out
	}
	addrs, err := listInterfaceAddrs()
	if err != nil {
		return out
	}
	tunName, _ := e.cfg.TUN.Name()
	doc := e.cfg.Store.Document()
	for _, c := range localCandidates(addrs, port, tunName, []netip.Prefix{doc.IPv4Prefix, doc.IPv6Prefix}, e.cfg.CandidateSkipInterfaces, control.MaxCandidates) {
		if len(out) >= control.MaxCandidates {
			break
		}
		if !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	return out
}
