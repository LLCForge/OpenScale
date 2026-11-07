//go:build linux

package privsep

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// CurrentStatus reports the current process's rights.
func CurrentStatus() Status {
	data, err := os.ReadFile("/proc/self/status")
	ps := parseProcStatus(string(data))
	if err != nil || !ps.ok {
		return Status{Summary: "bilinmiyor"}
	}
	st := Status{NoNewPrivs: ps.noNewPrivs, Privileged: ps.euid == 0 || ps.capEff != 0}
	switch {
	case st.Privileged:
		st.Summary = "ayrıcalıklı (root veya yetenek)"
	default:
		st.Summary = "ayrıcalıksız (uid " + strconv.Itoa(ps.euid) + ")"
	}
	if st.NoNewPrivs {
		st.Summary += ", no_new_privs açık"
	}
	return st
}

// SandboxAccount returns the uid and gid the helper runs as: the
// "nobody" account.
func SandboxAccount() (uint32, uint32, error) {
	u, err := user.Lookup("nobody")
	if err != nil {
		return 0, 0, fmt.Errorf("ayrıcalıksız hesap bulunamadı: %w", err)
	}
	uid, err1 := strconv.ParseUint(u.Uid, 10, 32)
	gid, err2 := strconv.ParseUint(u.Gid, 10, 32)
	if err1 != nil || err2 != nil || uid == 0 || gid == 0 {
		return 0, 0, errors.New("ayrıcalıksız hesabın kimliği geçersiz")
	}
	return uint32(uid), uint32(gid), nil
}

// Command prepares exe to run as uid:gid with no supplementary groups,
// in its own session, killed when the parent dies, with an empty
// environment. When the parent is not root the credentials are left
// alone (an unprivileged parent cannot change them and needs no drop).
// release is a no-op on Linux; it keeps the signature shared with Windows.
func Command(exe string, args []string, uid, gid uint32) (*exec.Cmd, func(), error) {
	if os.Geteuid() == 0 && (uid == 0 || gid == 0) {
		return nil, func() {}, errors.New("yardımcı süreç root olarak başlatılamaz")
	}
	cmd := exec.Command(exe, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"}
	cmd.Dir = "/"
	attr := &syscall.SysProcAttr{Setsid: true, Pdeathsig: syscall.SIGKILL}
	if os.Geteuid() == 0 {
		attr.Credential = &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}}
	}
	cmd.SysProcAttr = attr
	return cmd, func() {}, nil
}

// Enter is called first thing in the helper process. It sets
// PR_SET_NO_NEW_PRIVS on every thread when the runtime allows it (not
// with cgo, where only the calling thread can be changed, which Enter
// then locks to) and refuses to continue when the process can still
// become root.
func Enter() error {
	if _, _, errno := syscall.AllThreadsSyscall(syscall.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0); errno != 0 {
		if errno != syscall.ENOTSUP {
			return fmt.Errorf("no_new_privs ayarlanamadı: %w", errno)
		}
		runtime.LockOSThread()
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			return fmt.Errorf("no_new_privs ayarlanamadı: %w", err)
		}
	}
	if os.Geteuid() == 0 || os.Getuid() == 0 {
		return errors.New("yardımcı süreç root olarak çalışıyor; yetki düşürülmeden devam edilmez")
	}
	if err := syscall.Setresuid(0, 0, 0); err == nil {
		return errors.New("yardımcı süreç root yetkisini geri alabiliyor")
	}
	return nil
}

// DropTo switches the running process to uid:gid for good: no
// supplementary groups, real, effective and saved ids all changed, then
// verified by trying to regain root.
func DropTo(uid, gid uint32) error {
	if uid == 0 || gid == 0 {
		return errors.New("root hesabına düşürülemez")
	}
	if err := syscall.Setgroups([]int{}); err != nil {
		return fmt.Errorf("ek gruplar bırakılamadı: %w", err)
	}
	if err := syscall.Setresgid(int(gid), int(gid), int(gid)); err != nil {
		return fmt.Errorf("grup değiştirilemedi: %w", err)
	}
	if err := syscall.Setresuid(int(uid), int(uid), int(uid)); err != nil {
		return fmt.Errorf("kullanıcı değiştirilemedi: %w", err)
	}
	if err := syscall.Setresuid(0, 0, 0); err == nil {
		return errors.New("yetki düşürme doğrulanamadı: root geri alınabiliyor")
	}
	return nil
}
