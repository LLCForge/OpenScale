package cli

import (
	"github.com/openscale/openscale/internal/coordinator"
	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/testnet"
)

// Test binaries listen on loopback only, so Windows Defender Firewall never
// asks the user to allow them.
func init() {
	node.DefaultBind = testnet.NewLoopbackBind
	coordinator.DefaultBind = testnet.NewLoopbackBind
}
