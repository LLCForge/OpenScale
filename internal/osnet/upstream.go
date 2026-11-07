package osnet

import "net/netip"

// Upstream exit (ADR-0142): the exit node sends members' internet traffic
// through a second WireGuard tunnel to an outside provider. Only Linux
// exit nodes support it.

const (
	// UpstreamForwardMark marks members' internet packets on the exit node
	// so policy routing sends them into the upstream tunnel ("OV").
	UpstreamForwardMark = 0x4f56
	// UpstreamInterface is the default name of the upstream TUN.
	UpstreamInterface = "os-up0"
)

// UpstreamRoute is the routing state an upstream exit needs.
type UpstreamRoute struct {
	// Interface is the upstream TUN name. It is named even before the
	// tunnel exists, so the drop rules refer to it.
	Interface string
	MTU       int
	// Address4 and Address6 are the provider's tunnel addresses. An invalid
	// Address4 means no tunnel is up: only the drop routes are installed
	// (fail closed). Address6 is invalid when the provider gave none;
	// members' IPv6 internet traffic is then refused rather than sent from
	// this host.
	Address4 netip.Addr
	Address6 netip.Addr
	// Overlay is the OpenScale interface and its network prefixes.
	Overlay   string
	OverlayV4 netip.Prefix
	OverlayV6 netip.Prefix
	// FailOpen lets members' traffic leave from this host while the tunnel
	// is down (SetDirect). The default drops it.
	FailOpen bool
}

// TunnelUp reports whether the route carries a tunnel address.
func (r UpstreamRoute) TunnelUp() bool { return r.Address4.IsValid() }
