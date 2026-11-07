//go:build linux && amd64

package privsep

import "golang.org/x/sys/unix"

// seccompArch is the audit architecture the filter accepts; seccompX32
// rejects the x32 ABI, whose calls share this architecture value.
const (
	seccompArch = unix.AUDIT_ARCH_X86_64
	seccompX32  = true
)

// deniedSyscalls are refused with EPERM in the helper (sandbox_linux.go).
var deniedSyscalls = append(commonDenied(), []uintptr{
	unix.SYS_FORK, unix.SYS_VFORK, unix.SYS_IOPL, unix.SYS_IOPERM, unix.SYS_USELIB,
}...)
