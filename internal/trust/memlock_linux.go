//go:build linux

package trust

import "golang.org/x/sys/unix"

const memlockSupported = true

func lockPage(addr, n uintptr) error {
	if _, _, errno := unix.Syscall(unix.SYS_MLOCK, addr, n, 0); errno != 0 {
		return errno
	}
	return nil
}

func unlockPage(addr, n uintptr) error {
	if _, _, errno := unix.Syscall(unix.SYS_MUNLOCK, addr, n, 0); errno != 0 {
		return errno
	}
	return nil
}
