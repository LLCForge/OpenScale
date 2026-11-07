package node

import (
	"github.com/openscale/openscale/internal/coordinator"
	"github.com/openscale/openscale/internal/testnet"
)

// Test binaries listen on loopback only, so Windows Defender Firewall never
// asks the user to allow them. Node tests also start coordinators.
func init() {
	DefaultBind = testnet.NewLoopbackBind
	coordinator.DefaultBind = testnet.NewLoopbackBind
}
