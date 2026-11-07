//go:build windows

package osnet

import (
	"crypto/sha256"
	"encoding/binary"
	"strings"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
)

// Fixed adapter GUID (F-145, #305). Wintun gives a new adapter a random
// GUID unless one is requested, and Windows keys the network profile
// ("Özel" or "Ortak" ağ) on it: every new GUID opens a new profile and
// forgets the owner's choice. The GUID is derived from the interface
// name, so the service's "OpenScale" adapter keeps one identity across
// restarts and reinstalls, and a second tunnel with another name gets a
// different one.

// adapterGUID returns a stable, name-based (version 5 layout) GUID.
func adapterGUID(name string) *windows.GUID {
	sum := sha256.Sum256([]byte("openscale-tunnel-adapter:" + strings.ToLower(name)))
	sum[6] = sum[6]&0x0f | 0x50
	sum[8] = sum[8]&0x3f | 0x80
	g := windows.GUID{
		Data1: binary.BigEndian.Uint32(sum[0:4]),
		Data2: binary.BigEndian.Uint16(sum[4:6]),
		Data3: binary.BigEndian.Uint16(sum[6:8]),
	}
	copy(g.Data4[:], sum[8:16])
	return &g
}

func createPlatformTUN(name string, mtu int) (tun.Device, error) {
	return tun.CreateTUNWithRequestedGUID(name, adapterGUID(name), mtu)
}
