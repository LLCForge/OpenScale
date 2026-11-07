//go:build !windows

package svcmgr

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// CheckTrustedPath reports an error unless the file and every folder above
// it belong to root and are not writable by group or others (F-124): a
// program run as root from a place another user can change would run that
// user's code with root rights.
func CheckTrustedPath(p string) error {
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		return err
	}
	for cur := resolved; ; cur = filepath.Dir(cur) {
		fi, err := os.Stat(cur)
		if err != nil {
			return err
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("%s: sahip okunamadı", cur)
		}
		if st.Uid != 0 {
			return fmt.Errorf("%s root'a ait değil", cur)
		}
		if fi.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s başka kullanıcılarca yazılabilir", cur)
		}
		if parent := filepath.Dir(cur); parent == cur {
			return nil
		}
	}
}
