//go:build linux

package autoupdate

import (
	"os"
	"syscall"
)

// matchOwner gives path the owner of ref: the coordinator unit runs as the
// openscale user and must read what root published into its state folder.
func matchOwner(path, ref string) error {
	info, err := os.Stat(ref)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (int(st.Uid) == os.Geteuid() && int(st.Gid) == os.Getegid()) {
		return nil
	}
	return os.Lchown(path, int(st.Uid), int(st.Gid))
}
