//go:build !linux

package osnet

import (
	"errors"

	"golang.zx2c4.com/wireguard/tun"
)

// SetTUNPersist is Linux only. On Windows the Wintun adapter goes with the
// process, but the next one is created with the same name-derived GUID
// (tun_guid_windows.go), so the network profile carries over; a persistent
// kill switch (exit node use, ADR-0023) stays installed in between and
// blocks everything but OpenScale itself until the new service permits the
// new adapter.
func SetTUNPersist(tun.Device, bool) error { return errors.ErrUnsupported }
