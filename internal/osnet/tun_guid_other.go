//go:build !windows

package osnet

import "golang.zx2c4.com/wireguard/tun"

func createPlatformTUN(name string, mtu int) (tun.Device, error) { return tun.CreateTUN(name, mtu) }
