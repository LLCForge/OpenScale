//go:build !windows

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// checkConfigFilePerm refuses a --config file that someone other than root
// could have changed when the command runs as root (F-125): the file
// chooses ports, folders and the exit node of a root process. The file
// itself and its folder must belong to root and not be group or world
// writable.
func checkConfigFilePerm(path string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	resolved, err := filepath.EvalSymlinks(path)
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
			continue
		}
		if st.Uid != 0 || fi.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("yapılandırma dosyası güvenli değil: %s root'a ait olmalı ve yalnızca root yazabilmeli", p)
		}
	}
	return nil
}
