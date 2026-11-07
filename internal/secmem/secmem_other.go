//go:build !windows && !linux && !darwin && !freebsd && !netbsd && !openbsd

package secmem

const platformSupported = false

// region is a plain heap slice where no system allocator is bound.
type region struct{ b []byte }

func (r region) bytes() []byte { return r.b }

func allocate(n int) (region, error) { return region{b: make([]byte, n)}, nil }
func lock(region) bool               { return false }
func unlock(region)                  {}
func release(region)                 {}
