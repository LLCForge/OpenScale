//go:build linux

package coordinator

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Landlock file system sandbox for the coordinator (#147, ADR-0111). Once
// WireGuard is up the coordinator only reads and writes its state
// directory and reads a few system paths (the system report of admin
// devices, time zones, the random device fallback). Sockets that are
// already open are not affected, and connecting to the systemd notify
// socket is not a file system access Landlock restricts here. Everything
// is best effort: a kernel without Landlock, a cgo build (where Go cannot
// apply it to every thread) or any error leaves the process as it was and
// is logged; systemd's own hardening still applies.

// Landlock ABI versions and the file system rights each one handles.
const (
	llAccessV1 = unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE | unix.LANDLOCK_ACCESS_FS_READ_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
		unix.LANDLOCK_ACCESS_FS_MAKE_CHAR | unix.LANDLOCK_ACCESS_FS_MAKE_DIR | unix.LANDLOCK_ACCESS_FS_MAKE_REG |
		unix.LANDLOCK_ACCESS_FS_MAKE_SOCK | unix.LANDLOCK_ACCESS_FS_MAKE_FIFO | unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_SYM
	llAccessV2 = llAccessV1 | unix.LANDLOCK_ACCESS_FS_REFER
	llAccessV3 = llAccessV2 | unix.LANDLOCK_ACCESS_FS_TRUNCATE
	llAccessV5 = llAccessV3 | unix.LANDLOCK_ACCESS_FS_IOCTL_DEV

	// llStateDir is what the state directory allows: files are created,
	// replaced (rename within the directory), read and removed.
	llStateDir = unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR |
		unix.LANDLOCK_ACCESS_FS_REMOVE_FILE | unix.LANDLOCK_ACCESS_FS_REMOVE_DIR | unix.LANDLOCK_ACCESS_FS_MAKE_REG |
		unix.LANDLOCK_ACCESS_FS_MAKE_DIR | unix.LANDLOCK_ACCESS_FS_REFER | unix.LANDLOCK_ACCESS_FS_TRUNCATE
	llReadOnly = unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR
	// llFileRights are the only rights a rule on a regular file may carry.
	llFileRights = unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
		unix.LANDLOCK_ACCESS_FS_TRUNCATE | unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_IOCTL_DEV
)

// sandboxReadOnly are read-only paths; missing ones are skipped.
// /usr/lib/os-release is the target of the /etc/os-release symlink on
// Debian and most systemd distributions; Landlock checks the resolved path,
// so without it the system report shows only "Linux".
var sandboxReadOnly = []string{"/etc", "/usr/lib/os-release", "/proc", "/sys", "/usr/share/zoneinfo", "/dev/urandom", "/dev/null"}

// SandboxResult says what applySandbox did; Applied is false when it was
// skipped, with Reason.
type SandboxResult struct {
	Applied bool
	ABI     int
	Reason  string
}

// llRulesetAttr is the ABI 1 ruleset attribute; newer kernels accept it
// and zero-fill the fields they added.
type llRulesetAttr struct {
	handledAccessFS uint64
}

// SandboxOptOut turns the sandbox off when set to 1 in the environment, for
// a deployment that needs the coordinator to reach other paths.
const SandboxOptOut = "OPENSCALE_NO_LANDLOCK"

func (s *Server) applySandbox() {
	if os.Getenv(SandboxOptOut) == "1" {
		s.logger.Info("Landlock sandbox skipped", "reason", SandboxOptOut+"=1")
		return
	}
	res := RestrictFiles(s.cfg.Store.Dir())
	if res.Applied {
		s.logger.Info("Landlock sandbox active: file access limited to the state directory", "abi", res.ABI)
		return
	}
	s.logger.Info("Landlock sandbox skipped", "reason", res.Reason)
}

// RestrictFiles limits the whole process to read-write access below dir
// and read-only access to sandboxReadOnly. It cannot be undone.
func RestrictFiles(dir string) SandboxResult {
	abi, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 || abi == 0 {
		return SandboxResult{Reason: "çekirdek Landlock desteklemiyor (" + errnoText(errno) + ")"}
	}
	handled := uint64(llAccessV1)
	switch {
	case abi >= 5:
		handled = llAccessV5
	case abi >= 3:
		handled = llAccessV3
	case abi >= 2:
		handled = llAccessV2
	}
	attr := llRulesetAttr{handledAccessFS: handled}
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if errno != 0 {
		return SandboxResult{ABI: int(abi), Reason: "kural kümesi oluşturulamadı (" + errnoText(errno) + ")"}
	}
	ruleset := int(fd)
	defer unix.Close(ruleset)
	if err := addPathRule(ruleset, dir, llStateDir&handled); err != nil {
		return SandboxResult{ABI: int(abi), Reason: "durum klasörü kuralı eklenemedi: " + err.Error()}
	}
	for _, p := range sandboxReadOnly {
		// Missing paths are fine; anything else only narrows access more.
		_ = addPathRule(ruleset, p, llReadOnly&handled)
	}
	// Landlock needs no_new_privs; both must reach every thread of the Go
	// runtime, which AllThreadsSyscall does (ENOTSUP in cgo builds).
	if _, _, errno := syscall.AllThreadsSyscall(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0); errno != 0 {
		return SandboxResult{ABI: int(abi), Reason: "no_new_privs ayarlanamadı (" + errnoText(errno) + ")"}
	}
	if _, _, errno := syscall.AllThreadsSyscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(ruleset), 0, 0); errno != 0 {
		return SandboxResult{ABI: int(abi), Reason: "kısıtlama uygulanamadı (" + errnoText(errno) + ")"}
	}
	return SandboxResult{Applied: true, ABI: int(abi)}
}

func addPathRule(ruleset int, path string, rights uint64) error {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		rights &= llFileRights
	}
	if rights == 0 {
		return errors.New("no rights")
	}
	attr := unix.LandlockPathBeneathAttr{Allowed_access: rights, Parent_fd: int32(fd)} //nolint:gosec // fd fits int32
	_, _, errno := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, uintptr(ruleset), unix.LANDLOCK_RULE_PATH_BENEATH, uintptr(unsafe.Pointer(&attr)), 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("landlock_add_rule %s: %w", path, errno)
	}
	return nil
}

func errnoText(e syscall.Errno) string {
	if e == 0 {
		return "sürüm 0"
	}
	return e.Error()
}
