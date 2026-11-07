//go:build windows

package wintunembed

import "syscall"

func syscallN(p uintptr, args ...uintptr) (uintptr, uintptr, error) {
	r1, r2, e := syscall.SyscallN(p, args...)
	if e != 0 {
		return r1, r2, e
	}
	return r1, r2, nil
}
