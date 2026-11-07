//go:build !linux

package osnet

import "golang.zx2c4.com/wireguard/tun"

// Offloads exist only on Linux; elsewhere the normal interface is created.
func createTUNNoOffload(name string, mtu int) (tun.Device, error) {
	return createPlatformTUN(name, mtu)
}
