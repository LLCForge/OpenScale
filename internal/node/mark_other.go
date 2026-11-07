//go:build !linux && !darwin

package node

import "net"

// Socket marks exist only on Linux.
func setSocketMark(*net.UDPConn, uint32) error { return nil }
