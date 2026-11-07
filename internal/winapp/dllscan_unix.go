//go:build !windows

package winapp

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// checkFolderTrusted: the program and its folder belong to root and are
// not writable by group or others.
func checkFolderTrusted(exe string) error {
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return err
	}
	for _, p := range []string{resolved, filepath.Dir(resolved)} {
		fi, err := os.Stat(p)
		if err != nil {
			return err
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("%s: sahip okunamadı", p)
		}
		if st.Uid != 0 {
			return fmt.Errorf("%s root'a ait değil", p)
		}
		if fi.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s başka kullanıcılarca yazılabilir", p)
		}
	}
	return nil
}

// systemOwnedFile reports whether path (not followed if it is a link) and
// the file it points to are root's and writable only by root.
func systemOwnedFile(path string) bool {
	for _, stat := range []func(string) (os.FileInfo, error){os.Lstat, os.Stat} {
		fi, err := stat(path)
		if err != nil {
			return false
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		perm := fi.Mode().Perm()
		if fi.Mode()&os.ModeSymlink != 0 {
			perm = 0 // link permissions mean nothing; the target is checked next
		}
		if !ok || !ownerTrusted(st.Uid, perm) {
			return false
		}
	}
	return true
}

// InstalledProgramDirs are the folders of an installed program.
func InstalledProgramDirs() []string { return []string{"/usr/local/bin", "/usr/bin"} }
