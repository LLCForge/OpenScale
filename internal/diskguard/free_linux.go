//go:build linux

package diskguard

import "golang.org/x/sys/unix"

func freeBytes(dir string) (uint64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return st.Bavail * uint64(st.Bsize), nil
}

func isDiskFullOS(err error) bool { return false }
