//go:build darwin

package node

import (
	"net/netip"

	"golang.zx2c4.com/wireguard/conn"
)

// On macOS the engine uses plainBind (ADR-0100): wireguard-go's StdNetBind
// ignores SetMark there, while plainBind passes it to setSocketMark, which
// binds the sockets to the physical interface while an exit node is used.
// Without GSO/GRO on macOS the default bind has no throughput advantage.
// Tests (bind_test.go, loaded after this file) and other packages still
// replace DefaultBind with the loopback bind.
func init() {
	DefaultBind = func() conn.Bind {
		return newPlainBind(netip.IPv4Unspecified(), netip.IPv6Unspecified())
	}
}
