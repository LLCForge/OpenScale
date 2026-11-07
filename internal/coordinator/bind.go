package coordinator

import "golang.zx2c4.com/wireguard/conn"

// DefaultBind creates the UDP bind used when the config has none. Tests
// (here and in packages that start engines) replace it with
// testnet.NewLoopbackBind so test binaries listen on 127.0.0.1 only.
var DefaultBind = conn.NewDefaultBind
