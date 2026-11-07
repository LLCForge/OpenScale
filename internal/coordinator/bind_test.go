package coordinator

import "github.com/openscale/openscale/internal/testnet"

func init() { DefaultBind = testnet.NewLoopbackBind }
