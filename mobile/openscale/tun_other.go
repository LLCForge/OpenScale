//go:build !linux

package openscale

import (
	"errors"

	"golang.zx2c4.com/wireguard/tun"
)

// tunFromFD exists only on Android (and Linux, which shares its TUN
// driver); elsewhere the package builds for tests.
func tunFromFD(int) (tun.Device, error) {
	return nil, errors.New("TUN dosya tanıtıcısı yalnızca Android'de kullanılabilir")
}

func closeFD(int) {}
