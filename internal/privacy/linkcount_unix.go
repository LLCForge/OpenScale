//go:build unix

package privacy

import (
	"io/fs"
	"syscall"
)

// linkCount returns the number of hard links of the file.
func linkCount(_ string, info fs.FileInfo) uint64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Nlink)
	}
	return 1
}
