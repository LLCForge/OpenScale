package osnet

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
)

// Subnet routing in the operating system (ADR-0133, #70, F-032), plus the
// destinations kept out of the exit node (#79) and route conflict
// detection (#165, F-040).
//
// A client routes the approved subnets of its peers into the tunnel. A
// router (Linux only) forwards members' traffic to its own approved
// subnets and masquerades it behind its LAN address, sharing the exit
// node's forwarding and netfilter code. Windows does not act as a router:
// forwarding there needs RRAS or WinNAT, both system services OpenScale
// would have to configure and could not undo reliably (ADR-0133).

// ErrRouterUnsupported is returned when this system cannot be a subnet
// router.
var ErrRouterUnsupported = errors.New("bu işletim sistemi alt ağ yönlendirici olamaz (yalnızca Linux)")

// SubnetForwardMark marks forwarded subnet traffic on a Linux router so
// the exit node table lets it pass to private destinations (ADR-0133).
const SubnetForwardMark = 0x4f55

// RouteConfig is the routing the engine wants from the system.
type RouteConfig struct {
	Interface string
	// Client are subnets of peers this device reaches through the tunnel.
	Client []netip.Prefix
	// Own are the subnets this device forwards (its approved routes).
	Own []netip.Prefix
	// Overlay4 and Overlay6 are the network prefixes (members' sources).
	Overlay4, Overlay6 netip.Prefix
	// ExitRole: this device is also an exit node; its forwarding is not
	// limited to Own then.
	ExitRole bool
	// NoMasquerade forwards with the members' own addresses; the LAN then
	// needs a route back to the overlay (F-032 SNAT option).
	NoMasquerade bool
	// ExitActive: this device sends its internet traffic to an exit node.
	// ExitExcept are destinations kept out of it (#79).
	ExitActive bool
	ExitExcept []netip.Prefix
}

// Empty reports whether the configuration asks for nothing.
func (c RouteConfig) Empty() bool {
	return len(c.Client) == 0 && len(c.Own) == 0 && (!c.ExitActive || len(c.ExitExcept) == 0)
}

func (c RouteConfig) validate() error {
	if c.Empty() {
		return nil
	}
	if c.Interface == "" || strings.ContainsAny(c.Interface, " \"'\t\n;&|/\\=$`") || len(c.Interface) > 64 {
		return fmt.Errorf("invalid interface name %q", c.Interface)
	}
	for _, list := range [][]netip.Prefix{c.Client, c.Own, c.ExitExcept} {
		for _, p := range list {
			if !p.IsValid() || p != p.Masked() || p.Addr().Zone() != "" || p.Bits() == 0 {
				return fmt.Errorf("invalid route %s", p)
			}
		}
	}
	if len(c.Own) > 0 && (!c.Overlay4.IsValid() || !c.Overlay4.Addr().Is4() || !c.Overlay6.IsValid() || !c.Overlay6.Addr().Is6()) {
		return errors.New("invalid overlay prefixes")
	}
	return nil
}

// LocalNet is a network directly attached to this computer.
type LocalNet struct {
	Interface string       `json:"interface"`
	Prefix    netip.Prefix `json:"prefix"`
	// VPN marks an interface that looks like another VPN.
	VPN bool `json:"vpn"`
}

// RouteConflict describes an overlap the owner should know about (#165).
type RouteConflict struct {
	// Kind is "overlay" (the network prefix overlaps a local network) or
	// "route" (an approved subnet overlaps one).
	Kind      string       `json:"kind"`
	Prefix    netip.Prefix `json:"prefix"`
	Local     LocalNet     `json:"local"`
	Message   string       `json:"message"`
	Skipped   bool         `json:"skipped"`
	RouteFrom string       `json:"routeFrom,omitempty"`
}

// vpnNames are interface name prefixes of other VPNs and tunnels.
var vpnNames = []string{"tun", "tap", "wg", "utun", "ppp", "ipsec", "zt", "tailscale", "nordlynx", "proton", "mullvad", "openvpn", "wireguard"}

func looksLikeVPN(name string) bool {
	n := strings.ToLower(name)
	for _, p := range vpnNames {
		if strings.HasPrefix(n, p) || strings.Contains(n, " "+p) || strings.Contains(n, p+" ") {
			return true
		}
	}
	return strings.Contains(n, "vpn")
}

// LocalNetworks lists the networks of this computer's interfaces except
// the tunnel itself and loopback. It only reads the interface table.
func LocalNetworks(tunnel string) ([]LocalNet, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []LocalNet
	for _, ifi := range ifaces {
		if ifi.Name == tunnel || ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
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
			ip, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			if ip.IsLinkLocalUnicast() || ip.IsLoopback() {
				continue
			}
			ones, _ := ipn.Mask.Size()
			p, err := ip.Prefix(ones)
			if err != nil {
				continue
			}
			out = append(out, LocalNet{Interface: ifi.Name, Prefix: p, VPN: looksLikeVPN(ifi.Name)})
		}
	}
	return out, nil
}

// RouteConflicts compares the network prefixes and the approved subnets a
// device would route with its local networks (#165). A subnet that
// overlaps a local network is marked Skipped: the device does not route it
// into the tunnel, because the local network (often the very LAN the
// router serves) must keep working. routes maps a subnet to its router.
func RouteConflicts(overlay []netip.Prefix, routes map[netip.Prefix]string, locals []LocalNet) []RouteConflict {
	var out []RouteConflict
	for _, l := range locals {
		other := "yerel ağ"
		if l.VPN {
			other = "başka bir VPN"
		}
		for _, o := range overlay {
			if o.IsValid() && o.Overlaps(l.Prefix) {
				out = append(out, RouteConflict{Kind: "overlay", Prefix: o, Local: l,
					Message: fmt.Sprintf("Ağ aralığı %s, %s arayüzündeki %s (%s) ile çakışıyor; bu aralıktaki adreslere erişim karışabilir.", o, l.Interface, l.Prefix, other)})
			}
		}
		keys := make([]netip.Prefix, 0, len(routes))
		for p := range routes {
			keys = append(keys, p)
		}
		slices.SortFunc(keys, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
		for _, p := range keys {
			if p.Overlaps(l.Prefix) {
				out = append(out, RouteConflict{Kind: "route", Prefix: p, Local: l, Skipped: true, RouteFrom: routes[p],
					Message: fmt.Sprintf("Alt ağ %s (%s üzerinden), %s arayüzündeki %s (%s) ile çakışıyor; bu cihazda tünele yönlendirilmedi.", p, routes[p], l.Interface, l.Prefix, other)})
			}
		}
	}
	return out
}

// SkipConflicting removes the subnets that overlap a local network.
func SkipConflicting(prefixes []netip.Prefix, locals []LocalNet) []netip.Prefix {
	return slices.DeleteFunc(slices.Clone(prefixes), func(p netip.Prefix) bool {
		for _, l := range locals {
			if p.Overlaps(l.Prefix) {
				return true
			}
		}
		return false
	})
}

// prefixDiff returns the prefixes of want missing from have and those of
// have missing from want.
func prefixDiff(have, want []netip.Prefix) (add, del []netip.Prefix) {
	for _, p := range want {
		if !slices.Contains(have, p) {
			add = append(add, p)
		}
	}
	for _, p := range have {
		if !slices.Contains(want, p) {
			del = append(del, p)
		}
	}
	return add, del
}

func split46(ps []netip.Prefix) (v4, v6 []netip.Prefix) {
	for _, p := range ps {
		if p.Addr().Is4() {
			v4 = append(v4, p)
		} else {
			v6 = append(v6, p)
		}
	}
	return v4, v6
}

// Rate limit bounds.
const (
	// MinExitRateLimit is 64 kB/s; anything lower would break TCP.
	MinExitRateLimit = 64 * 1024
	// MaxExitRateLimit is 10 GB/s.
	MaxExitRateLimit = 10 * 1024 * 1024 * 1024
)

// ValidateExitRateLimit checks a per-member limit in bytes per second.
func ValidateExitRateLimit(bytesPerSecond uint64) error {
	if bytesPerSecond != 0 && (bytesPerSecond < MinExitRateLimit || bytesPerSecond > MaxExitRateLimit) {
		return fmt.Errorf("çıkış hız sınırı %d B/s ile %d B/s arasında olmalı", MinExitRateLimit, uint64(MaxExitRateLimit))
	}
	return nil
}
