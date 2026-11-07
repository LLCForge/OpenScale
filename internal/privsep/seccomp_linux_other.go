//go:build linux && !amd64 && !arm64

package privsep

// No seccomp filter on this architecture: the summary says so (the
// account drop, no_new_privs and Landlock still apply).
const (
	seccompArch = 0
	seccompX32  = false
)

var deniedSyscalls []uintptr
