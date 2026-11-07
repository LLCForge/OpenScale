// Package secmem keeps secrets (root key passphrases, private keys,
// session keys) in memory that the Go garbage collector never moves or
// copies and that the operating system does not write to swap or the page
// file (#639, ADR-0192).
//
// A Buffer is allocated outside the Go heap (mmap on Unix, VirtualAlloc on
// Windows), pinned with mlock or VirtualLock, excluded from core dumps on
// Linux (MADV_DONTDUMP) and zeroed and released by Destroy. When the
// system refuses to lock (RLIMIT_MEMLOCK, the working set quota) the
// buffer still works and Locked reports false: locking is defence in
// depth, the caller must not fail because of it.
//
// What this package cannot do: a secret that was ever a Go string, or that
// passed through a heap []byte before it reached the Buffer, may still
// have copies the program cannot reach. Callers read secrets straight
// into Buffer.Bytes() where they can (terminal input, files) and use Wipe
// on every temporary slice.
package secmem

import (
	"crypto/subtle"
	"errors"
	"runtime"
	"sync"
)

// MaxSize bounds one buffer. Secrets are small; a larger request is a bug.
const MaxSize = 1 << 20

// Errors.
var (
	ErrSize      = errors.New("secmem: buffer size must be 1..1 MiB")
	ErrDestroyed = errors.New("secmem: buffer already destroyed")
)

// Buffer is a fixed-size secret in locked memory. The zero value is not
// usable; create one with New or Copy. A Buffer is safe for concurrent
// use; the slice returned by Bytes is not synchronized.
type Buffer struct {
	mu        sync.Mutex
	data      []byte
	mem       region
	locked    bool
	destroyed bool
}

// New returns a zeroed buffer of n bytes.
func New(n int) (*Buffer, error) {
	if n <= 0 || n > MaxSize {
		return nil, ErrSize
	}
	mem, err := allocate(n)
	if err != nil {
		return nil, err
	}
	b := &Buffer{data: mem.bytes()[:n:n], mem: mem}
	b.locked = lock(mem)
	// A buffer the program forgot to destroy is still zeroed and released
	// when it becomes unreachable.
	runtime.SetFinalizer(b, (*Buffer).Destroy)
	return b, nil
}

// Copy moves src into a new buffer and wipes src. On error src is wiped
// as well, so the secret never stays behind in the caller's slice.
func Copy(src []byte) (*Buffer, error) {
	defer Wipe(src)
	b, err := New(len(src))
	if err != nil {
		return nil, err
	}
	copy(b.data, src)
	return b, nil
}

// Bytes returns the secret. The slice is valid until Destroy; it must not
// be kept after Destroy. It is nil after Destroy.
func (b *Buffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.destroyed {
		return nil
	}
	return b.data
}

// Len is the buffer size, 0 after Destroy.
func (b *Buffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.destroyed {
		return 0
	}
	return len(b.data)
}

// Locked reports whether the memory is pinned (not swappable).
func (b *Buffer) Locked() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.locked && !b.destroyed
}

// Equal compares the secret with v in constant time (for v of the same
// length).
func (b *Buffer) Equal(v []byte) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.destroyed {
		return false
	}
	return subtle.ConstantTimeCompare(b.data, v) == 1
}

// Use calls fn with the secret while holding the buffer, so Destroy cannot
// release the memory under fn. It returns ErrDestroyed after Destroy.
func (b *Buffer) Use(fn func([]byte) error) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.destroyed {
		return ErrDestroyed
	}
	return fn(b.data)
}

// Destroy zeroes the secret, unlocks and releases the memory. It is safe
// to call more than once.
func (b *Buffer) Destroy() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.destroyed {
		return
	}
	b.destroyed = true
	Wipe(b.mem.bytes())
	if b.locked {
		unlock(b.mem)
	}
	release(b.mem)
	b.data = nil
	b.mem = region{}
	runtime.SetFinalizer(b, nil)
}

// Wipe zeroes b. The stores cannot be dropped by the compiler because the
// slice stays alive through runtime.KeepAlive.
func Wipe(b []byte) {
	if len(b) == 0 {
		return
	}
	clear(b)
	runtime.KeepAlive(b)
}

// Supported reports whether this platform allocates outside the Go heap
// and can lock memory.
func Supported() bool { return platformSupported }
