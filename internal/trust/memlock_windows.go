//go:build windows

package trust

import "golang.org/x/sys/windows"

const memlockSupported = true

func lockPage(addr, n uintptr) error { return windows.VirtualLock(addr, n) }

func unlockPage(addr, n uintptr) error { return windows.VirtualUnlock(addr, n) }
