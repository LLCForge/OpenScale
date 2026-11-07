//go:build linux && arm64

package privsep

import "golang.org/x/sys/unix"

// seccompArch is the audit architecture the filter accepts.
const (
	seccompArch = unix.AUDIT_ARCH_AARCH64
	seccompX32  = false
)

// deniedSyscalls are refused with EPERM in the helper (sandbox_linux.go).
var deniedSyscalls = commonDenied()
