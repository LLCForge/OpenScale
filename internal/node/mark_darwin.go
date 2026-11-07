//go:build darwin

package node

import (
	"errors"
	"math"
	"net"

	"golang.org/x/sys/unix"
)

// setSocketMark binds the socket to an interface on macOS (ADR-0100).
// macOS has no socket marks; the exit router hands the index of the
// physical interface through the same SetMark path instead, and
// IP_BOUND_IF / IPV6_BOUND_IF make the kernel route the socket's packets
// out of that interface whatever the routing table says, so WireGuard
// never loops into its own tunnel. 0 removes the binding.
func setSocketMark(c *net.UDPConn, mark uint32) error {
	if mark > math.MaxInt32 {
		return errors.New("interface index out of range")
	}
	v6 := false
	if a, ok := c.LocalAddr().(*net.UDPAddr); ok && a.IP != nil && a.IP.To4() == nil {
		v6 = true
	}
	rc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := rc.Control(func(fd uintptr) {
		if v6 {
			serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, int(mark))
			return
		}
		serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, int(mark))
	}); err != nil {
		return err
	}
	return serr
}
