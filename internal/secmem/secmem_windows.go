//go:build windows

package secmem

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

const platformSupported = true

// region is a committed read-write VirtualAlloc block.
type region struct {
	addr uintptr
	size int
}

func (r region) bytes() []byte {
	if r.addr == 0 {
		return nil
	}
	// The block is not Go memory, so the garbage collector never moves
	// it; the conversion goes through a pointer to keep vet's
	// uintptr-to-pointer rule (the address is valid until VirtualFree).
	addr := r.addr
	p := *(*unsafe.Pointer)(unsafe.Pointer(&addr))
	return unsafe.Slice((*byte)(p), r.size)
}

func allocate(n int) (region, error) {
	size := roundPage(n)
	addr, err := windows.VirtualAlloc(0, uintptr(size), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return region{}, err
	}
	return region{addr: addr, size: size}, nil
}

func lock(r region) bool { return windows.VirtualLock(r.addr, uintptr(r.size)) == nil }

func unlock(r region) { _ = windows.VirtualUnlock(r.addr, uintptr(r.size)) }

func release(r region) {
	if r.addr != 0 {
		_ = windows.VirtualFree(r.addr, 0, windows.MEM_RELEASE)
	}
}

func roundPage(n int) int {
	const page = 4096
	return (n + page - 1) / page * page
}
