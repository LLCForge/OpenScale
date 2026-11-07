//go:build linux

package node

import (
	"net"

	"golang.org/x/sys/unix"
)

func setSocketMark(c *net.UDPConn, mark uint32) error {
	rc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := rc.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
	}); err != nil {
		return err
	}
	return serr
}
