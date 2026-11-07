//go:build !unix && !windows

package privacy

import "io/fs"

// linkCount is 1 where hard links cannot be counted.
func linkCount(string, fs.FileInfo) uint64 { return 1 }
