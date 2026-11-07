//go:build linux

package node

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// tcpSocketControl gives the TCP transport's socket the mark the exit
// router set on the UDP sockets, so it bypasses the tunnel the same way.
func tcpSocketControl(_ string, c syscall.RawConn, mark, _ uint32) error {
	if mark == 0 {
		return nil
	}
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
	}); err != nil {
		return err
	}
	return serr
}
