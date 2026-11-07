//go:build darwin

package sysinfo

import (
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

func collect(in *Info) {
	ver, _ := unix.Sysctl("kern.osproductversion")
	build, _ := unix.Sysctl("kern.osversion")
	in.OSName = strings.TrimSpace("macOS " + ver)
	if build != "" {
		in.OSName += " (" + build + ")"
	}
	in.CPU, _ = unix.Sysctl("machdep.cpu.brand_string")
	in.MemTotal, _ = unix.SysctlUint64("hw.memsize")
	free, err1 := unix.SysctlUint32("vm.page_free_count")
	spec, err2 := unix.SysctlUint32("vm.page_speculative_count")
	if err1 == nil && err2 == nil {
		in.MemFree = uint64(free+spec) * uint64(os.Getpagesize())
	}
	// The sealed system volume is "/"; user data lives on the data volume.
	for _, p := range []string{"/System/Volumes/Data", "/"} {
		var st unix.Statfs_t
		if unix.Statfs(p, &st) == nil && st.Bsize > 0 {
			in.DiskTotal, in.DiskFree = st.Blocks*uint64(st.Bsize), st.Bavail*uint64(st.Bsize)
			break
		}
	}
	if tv, err := unix.SysctlTimeval("kern.boottime"); err == nil && tv.Sec > 0 {
		in.Uptime = int64(time.Since(time.Unix(tv.Sec, 0)).Seconds())
	}
}
