package trust

import (
	"os"
	"sync"
	"unsafe"
)

// Memory locking (#8, ADR-0060). Private key buffers are pinned in RAM with
// mlock (Linux) or VirtualLock (Windows) so the operating system does not
// write them to swap or the page file, and WipeKey zeroes and unpins them.
//
// This is partial protection by design: the Go runtime may copy a slice
// before it is locked (JSON decoding, base64 buffers, stack growth), a
// hibernation file still holds locked pages, and a buffer is locked only
// after it was created. Locking is best effort: when the limit
// (RLIMIT_MEMLOCK, the Windows working set) is reached, keys stay usable
// but unlocked.

// maxLockedRanges bounds the registry. Device keys that the garbage
// collector frees without WipeKey stay registered; the bound keeps a
// long-running daemon from growing the table or the locked set forever.
const maxLockedRanges = 256

var memlock = struct {
	sync.Mutex
	ranges map[uintptr]int // start address -> length
	pages  map[uintptr]int // page address -> number of ranges on it
}{ranges: map[uintptr]int{}, pages: map[uintptr]int{}}

var pageSize = uintptr(os.Getpagesize())

// lockMemory pins the pages under b. It reports whether they are locked.
func lockMemory(b []byte) bool {
	if len(b) == 0 || !memlockSupported {
		return false
	}
	start := uintptr(unsafe.Pointer(unsafe.SliceData(b)))
	memlock.Lock()
	defer memlock.Unlock()
	if _, ok := memlock.ranges[start]; ok || len(memlock.ranges) >= maxLockedRanges {
		return ok
	}
	first, last := pageRange(start, len(b))
	var locked []uintptr
	for p := first; p <= last; p += pageSize {
		if memlock.pages[p] == 0 {
			if err := lockPage(p, pageSize); err != nil {
				for _, q := range locked {
					_ = unlockPage(q, pageSize)
					delete(memlock.pages, q)
				}
				return false
			}
			locked = append(locked, p)
		}
	}
	for p := first; p <= last; p += pageSize {
		memlock.pages[p]++
	}
	memlock.ranges[start] = len(b)
	return true
}

// unlockMemory releases b's pages that no other locked key shares.
func unlockMemory(b []byte) {
	if len(b) == 0 || !memlockSupported {
		return
	}
	start := uintptr(unsafe.Pointer(unsafe.SliceData(b)))
	memlock.Lock()
	defer memlock.Unlock()
	n, ok := memlock.ranges[start]
	if !ok {
		return
	}
	delete(memlock.ranges, start)
	first, last := pageRange(start, n)
	for p := first; p <= last; p += pageSize {
		memlock.pages[p]--
		if memlock.pages[p] <= 0 {
			delete(memlock.pages, p)
			_ = unlockPage(p, pageSize)
		}
	}
}

func pageRange(start uintptr, n int) (uintptr, uintptr) {
	first := start &^ (pageSize - 1)
	last := (start + uintptr(n) - 1) &^ (pageSize - 1)
	return first, last
}

// LockKey pins a private key buffer in RAM on a best-effort basis and
// reports whether it worked. Release it with WipeKey.
func LockKey(b []byte) bool { return lockMemory(b) }

// WipeKey zeroes b and releases its memory lock, if any. It is safe on
// buffers that were never locked.
func WipeKey(b []byte) {
	wipe(b)
	unlockMemory(b)
}

// MemoryLockSupported reports whether this platform can lock memory.
func MemoryLockSupported() bool { return memlockSupported }

// Wipe zeroes the device's private keys and releases their memory locks.
// The secrets are unusable afterwards.
func (s *DeviceSecrets) Wipe() {
	if s == nil {
		return
	}
	WipeKey(s.SigningSeed)
	WipeKey(s.WireGuardPrivate)
}

// lockSecrets pins a device's private keys; see the package notes above.
func (s *DeviceSecrets) lockSecrets() {
	lockMemory(s.SigningSeed)
	lockMemory(s.WireGuardPrivate)
}
