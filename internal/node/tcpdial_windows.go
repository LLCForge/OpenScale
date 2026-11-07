//go:build windows

package node

import (
	"encoding/binary"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

// IP_UNICAST_IF and IPV6_UNICAST_IF (ws2ipdef.h).
const (
	sockoptIPUnicastIf   = 31
	sockoptIPv6UnicastIf = 31
)

// tcpSocketControl binds the TCP transport's socket to the interface the
// exit router chose for the UDP sockets, so it bypasses the tunnel.
func tcpSocketControl(network string, c syscall.RawConn, _, ifIndex uint32) error {
	if ifIndex == 0 {
		return nil
	}
	var serr error
	if err := c.Control(func(fd uintptr) {
		if strings.HasSuffix(network, "6") {
			serr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, sockoptIPv6UnicastIf, int(ifIndex))
			return
		}
		// IPv4 wants the index in network byte order.
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], ifIndex)
		serr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, sockoptIPUnicastIf, int(binary.NativeEndian.Uint32(b[:])))
	}); err != nil {
		return err
	}
	return serr
}
