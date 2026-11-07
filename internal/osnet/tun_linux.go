//go:build linux

package osnet

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
)

// createTUNNoOffload opens a TUN like tun.CreateTUN but without
// IFF_VNET_HDR. wireguard-go then reads single packets (batch size 1) and
// never asks the kernel for segmentation offloads.
func createTUNNoOffload(name string, mtu int) (tun.Device, error) {
	nfd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("TUN oluşturulamadı: /dev/net/tun yok")
		}
		return nil, err
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		unix.Close(nfd)
		return nil, err
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(nfd, unix.TUNSETIFF, ifr); err != nil {
		unix.Close(nfd)
		return nil, err
	}
	if err := unix.SetNonblock(nfd, true); err != nil {
		unix.Close(nfd)
		return nil, err
	}
	f := os.NewFile(uintptr(nfd), "/dev/net/tun")
	dev, err := tun.CreateTUNFromFile(f, mtu)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return dev, nil
}
