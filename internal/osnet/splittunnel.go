package osnet

import "errors"

// Per-application split tunnel (#78, F-049, ADR-0134). Programs started in
// OpenScale's bypass group leave through the normal network instead of the
// exit node; everything else keeps using the exit node.
//
// Linux: a cgroup v2 group (/sys/fs/cgroup/openscale-bypass) and an
// nftables output route chain that gives sockets of that group the tunnel
// bypass mark. The exit node routing already sends marked packets to the
// main table, and the kill switch already lets them pass: excluding a
// program is the owner's explicit choice to let it leave unprotected.
//
// Windows: excluding a program from the exit node needs per-connection
// route selection. WFP can only permit or block by application in user
// mode; redirecting a connection to the physical interface needs a
// ALE_CONNECT_REDIRECT callout, which is a signed kernel driver. That is
// out of scope (ADR-0134), so Windows reports ErrSplitTunnelUnsupported.

// ErrSplitTunnelUnsupported is returned where per-application split
// tunneling is not available.
var ErrSplitTunnelUnsupported = errors.New("uygulama bazlı bölünmüş tünel bu işletim sisteminde yok (Windows için çekirdek sürücüsü gerekir, ADR-0134)")

// BypassCgroup is the cgroup v2 group of programs that skip the exit node.
const BypassCgroup = "openscale-bypass"
