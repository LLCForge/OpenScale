//go:build linux

package secmem

import "golang.org/x/sys/unix"

// excludeFromDump keeps the pages out of core dumps.
func excludeFromDump(b []byte) { _ = unix.Madvise(b, unix.MADV_DONTDUMP) }
