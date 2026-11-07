package osnet

import "golang.zx2c4.com/wireguard/tun"

// TUNOptions configures CreateTUN.
type TUNOptions struct {
	// DisableOffload creates a Linux TUN without the virtio header, so the
	// kernel hands over single packets instead of TSO/USO super-packets and
	// wireguard-go does no GSO/GRO on the interface (F-024). Use it when a
	// driver, a container runtime or a packet capture misbehaves with
	// offloads. Elsewhere it has no effect.
	DisableOffload bool
}

// CreateTUN creates the tunnel interface. With offloads enabled (the
// default) it is wireguard-go's tun.CreateTUN, which turns on TCP/UDP
// segmentation offload on Linux when the kernel supports it.
func CreateTUN(name string, mtu int, o TUNOptions) (tun.Device, error) {
	// OpenBSD cannot name the interface; the caller reads the real name
	// back with Device.Name (ADR-0090).
	name = platformTUNName(name)
	if o.DisableOffload {
		return createTUNNoOffload(name, mtu)
	}
	// On Windows with a fixed adapter GUID (F-145, tun_guid_windows.go).
	return createPlatformTUN(name, mtu)
}
