//go:build linux

package osnet

import (
	"io"
	"os"
	"strings"
)

// CurrentOSBuild reads the distribution from os-release and the kernel
// release from /proc.
func CurrentOSBuild() OSBuild {
	b := OSBuild{Family: "linux"}
	data := readSmall("/etc/os-release")
	if len(data) == 0 {
		data = readSmall("/usr/lib/os-release")
	}
	id, ver := parseOSRelease(data)
	b.Version = strings.TrimSpace(id + " " + ver)
	b.Build = cleanBuildField(string(readSmall("/proc/sys/kernel/osrelease")))
	return b
}

// readSmall reads at most 64 KiB of a file; errors give nil.
func readSmall(path string) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	data, _ := io.ReadAll(io.LimitReader(f, 64<<10))
	return data
}
