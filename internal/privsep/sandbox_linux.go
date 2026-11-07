//go:build linux

package privsep

import (
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Linux helper sandbox (ADR-0233): after Enter (unprivileged account,
// no_new_privs, root cannot be regained) the helper
//   - denies itself every file system access with Landlock: a ruleset that
//     handles all rights the kernel knows and allows none (the coordinator's
//     ADR-0111 sandbox, without its state directory rule), and
//   - installs a seccomp filter that refuses with EPERM the system calls a
//     parser never needs: running programs, creating processes (threads
//     stay allowed), sockets, ptrace, mounts, namespaces, kernel modules,
//     BPF, keyrings, identity changes and clock changes.
//
// Both apply to every thread (Landlock through AllThreadsSyscall, seccomp
// with the TSYNC flag). The standard input and output pipes were opened
// before and keep working. A kernel without Landlock or an unsupported
// architecture for the filter is reported in the summary; the account
// drop and no_new_privs still hold.

// llHandledV1..V5 are the file system rights of the Landlock ABI versions.
const (
	llHandledV1 = unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE | unix.LANDLOCK_ACCESS_FS_READ_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
		unix.LANDLOCK_ACCESS_FS_MAKE_CHAR | unix.LANDLOCK_ACCESS_FS_MAKE_DIR | unix.LANDLOCK_ACCESS_FS_MAKE_REG |
		unix.LANDLOCK_ACCESS_FS_MAKE_SOCK | unix.LANDLOCK_ACCESS_FS_MAKE_FIFO | unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_SYM
	llHandledV2 = llHandledV1 | unix.LANDLOCK_ACCESS_FS_REFER
	llHandledV3 = llHandledV2 | unix.LANDLOCK_ACCESS_FS_TRUNCATE
	llHandledV5 = llHandledV3 | unix.LANDLOCK_ACCESS_FS_IOCTL_DEV
)

type llRuleset struct {
	handledAccessFS uint64
}

// helperAccount is the unprivileged account the helper runs as when the
// parent is root; an unprivileged parent passes its own (Command ignores
// the values then).
func helperAccount() (uint32, uint32, error) {
	if os.Geteuid() != 0 {
		return 0, 0, nil
	}
	return SandboxAccount()
}

// contain does nothing on Linux: the helper dies with its parent
// (Pdeathsig) and the sandbox is entered by the helper itself.
func contain(int) (func(), error) { return func() {}, nil }

// confine enters the sandbox and describes it.
func confine() string {
	parts := []string{"uid " + strconv.Itoa(os.Getuid()), "no_new_privs"}
	if abi, ok := denyAllFiles(); ok {
		parts = append(parts, "Landlock ABI "+strconv.Itoa(abi)+" (dosya erişimi yok)")
	} else {
		parts = append(parts, "Landlock yok")
	}
	if ok, why := installSeccomp(); ok {
		parts = append(parts, "seccomp")
	} else {
		parts = append(parts, "seccomp yok ("+why+")")
	}
	return strings.Join(parts, ", ")
}

// denyAllFiles restricts the process to no file system access at all.
func denyAllFiles() (int, bool) {
	abi, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 || abi == 0 {
		return 0, false
	}
	handled := uint64(llHandledV1)
	switch {
	case abi >= 5:
		handled = llHandledV5
	case abi >= 3:
		handled = llHandledV3
	case abi >= 2:
		handled = llHandledV2
	}
	attr := llRuleset{handledAccessFS: handled}
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if errno != 0 {
		return int(abi), false
	}
	defer unix.Close(int(fd))
	if _, _, errno := syscall.AllThreadsSyscall(unix.SYS_LANDLOCK_RESTRICT_SELF, fd, 0, 0); errno != 0 {
		return int(abi), false
	}
	return int(abi), true
}

// installSeccomp installs the deny list for this architecture.
func installSeccomp() (bool, string) {
	if seccompArch == 0 {
		return false, "mimari desteklenmiyor"
	}
	prog := seccompProgram(seccompArch, deniedSyscalls, seccompX32)
	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]} //nolint:gosec // a few dozen instructions
	_, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&fprog)))
	if errno != 0 {
		return false, errno.Error()
	}
	return true, ""
}

// seccompProgram builds the BPF filter: a foreign architecture kills the
// process (its system call numbers mean something else), x32 calls too
// where x32 exists; clone without CLONE_THREAD and every denied call
// return EPERM; clone3 returns ENOSYS so the runtime falls back to clone;
// everything else is allowed.
func seccompProgram(arch uint32, denied []uintptr, x32 bool) []unix.SockFilter {
	const (
		offNr   = 0
		offArch = 4
		offArg0 = 16 // low 32 bits of args[0] on little-endian systems
	)
	ld := func(off uint32) unix.SockFilter {
		return unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: off}
	}
	ret := func(v uint32) unix.SockFilter { return unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: v} }
	jeq := func(k uint32, jt, jf uint8) unix.SockFilter {
		return unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: k, Jt: jt, Jf: jf}
	}
	eperm := uint32(unix.SECCOMP_RET_ERRNO) | uint32(unix.EPERM)
	enosys := uint32(unix.SECCOMP_RET_ERRNO) | uint32(unix.ENOSYS)
	allow := uint32(unix.SECCOMP_RET_ALLOW)
	kill := uint32(unix.SECCOMP_RET_KILL_PROCESS)

	p := []unix.SockFilter{ld(offArch), jeq(arch, 1, 0), ret(kill), ld(offNr)}
	if x32 {
		p = append(p, unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K, K: 0x40000000, Jt: 0, Jf: 1}, ret(kill))
	}
	// clone: allowed only for threads.
	p = append(p, jeq(uint32(unix.SYS_CLONE), 0, 4), ld(offArg0),
		unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K, K: unix.CLONE_THREAD, Jt: 0, Jf: 1}, ret(allow), ret(eperm))
	p = append(p, jeq(uint32(unix.SYS_CLONE3), 0, 1), ret(enosys))
	for _, nr := range denied {
		p = append(p, jeq(uint32(nr), 0, 1), ret(eperm))
	}
	return append(p, ret(allow))
}
