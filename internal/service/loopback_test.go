package service

import (
	"net"

	"github.com/openscale/openscale/internal/coordinator"
	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/testnet"
)

// Test binaries listen on loopback only, so Windows Defender Firewall never
// asks the user to allow them.
func init() {
	node.DefaultBind = testnet.NewLoopbackBind
	coordinator.DefaultBind = testnet.NewLoopbackBind
	listenUDP = func(network string, laddr *net.UDPAddr) (*net.UDPConn, error) {
		local := *laddr
		local.IP = net.IPv4(127, 0, 0, 1)
		if network == "udp6" {
			local.IP = net.IPv6loopback
		}
		return net.ListenUDP(network, &local)
	}
}
