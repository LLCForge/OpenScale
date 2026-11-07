//go:build linux

package openscale

import (
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
)

// tunFromFD wraps the descriptor VpnService.Builder.establish returned
// (the app detaches it, so this package owns it). The interface already
// has its addresses, routes and MTU from the Builder; nothing is
// configured here, and no netlink monitor is started.
func tunFromFD(fd int) (tun.Device, error) {
	dev, _, err := tun.CreateUnmonitoredTUNFromFD(fd)
	return dev, err
}

// closeFD closes a descriptor that never became a TUN device.
func closeFD(fd int) { _ = unix.Close(fd) }
