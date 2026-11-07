//go:build !linux && !windows

package node

import "syscall"

// tcpSocketControl does nothing here: no exit router binds sockets on this
// system yet.
func tcpSocketControl(string, syscall.RawConn, uint32, uint32) error { return nil }
