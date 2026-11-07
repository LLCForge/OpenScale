//go:build linux

package osnet

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
)

// SetTUNPersist turns the persistent flag of a Linux TUN on or off (#203,
// ADR-0235). A persistent interface outlives the process that has it open:
// its addresses and the routes through it stay, and the next process that
// opens the same name takes it over. With nobody reading it the interface
// has no carrier and traffic routed into it is dropped (unless the system
// sets ignore_routes_with_linkdown; then the kill switch, which stays, is
// the protection, as without this flag). "openscale up" turns it on only
// when an update restarts
// it and off right after opening the interface again, so a normal stop
// still removes the interface.
func SetTUNPersist(dev tun.Device, on bool) error {
	f, ok := dev.(interface{ File() *os.File })
	if !ok || f.File() == nil {
		return errors.ErrUnsupported
	}
	rc, err := f.File().SyscallConn()
	if err != nil {
		return err
	}
	v := 0
	if on {
		v = 1
	}
	var ioErr error
	// Control, not Fd: Fd would put the descriptor into blocking mode
	// under wireguard-go's non-blocking reads.
	if err := rc.Control(func(fd uintptr) { ioErr = unix.IoctlSetInt(int(fd), unix.TUNSETPERSIST, v) }); err != nil {
		return err
	}
	return ioErr
}
