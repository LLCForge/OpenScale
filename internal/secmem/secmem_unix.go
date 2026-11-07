//go:build linux || darwin || freebsd || netbsd || openbsd

package secmem

import "golang.org/x/sys/unix"

const platformSupported = true

// region is an anonymous private mapping, rounded up to whole pages.
type region struct{ b []byte }

func (r region) bytes() []byte { return r.b }

func allocate(n int) (region, error) {
	b, err := unix.Mmap(-1, 0, roundPage(n), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		return region{}, err
	}
	excludeFromDump(b)
	return region{b: b}, nil
}

func lock(r region) bool { return unix.Mlock(r.b) == nil }

func unlock(r region) { _ = unix.Munlock(r.b) }

func release(r region) {
	if len(r.b) > 0 {
		_ = unix.Munmap(r.b)
	}
}

func roundPage(n int) int {
	p := unix.Getpagesize()
	return (n + p - 1) / p * p
}
