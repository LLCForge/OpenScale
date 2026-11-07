package node

import (
	"syscall"

	"github.com/openscale/openscale/internal/osnet"
)

// captiveControl gives the captive portal check's socket OpenScale's
// bypass mark on Linux, the same as the WireGuard sockets: it then reaches
// the local gateway past the exit node routes and the persistent kill
// switch (ADR-0023, #85). Setting the mark needs CAP_NET_ADMIN; without it
// the check simply runs unmarked. Elsewhere this does nothing (Windows
// permits the OpenScale program itself).
func captiveControl(network, _ string, c syscall.RawConn) error {
	_ = tcpSocketControl(network, c, osnet.TunnelBypassMark, 0)
	return nil
}
