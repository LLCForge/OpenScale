//go:build linux

package svcmgr

import (
	"io"
	"os"
	"path/filepath"
)

// CurrentCgroupLimits reads the cgroup v2 limits of this process; ok is
// false without cgroup v2 or outside a limited cgroup.
func CurrentCgroupLimits() (CgroupLimits, bool) {
	p, ok := cgroupV2Path(readCgroupFile("/proc/self/cgroup"))
	if !ok {
		return CgroupLimits{}, false
	}
	dir := filepath.Join("/sys/fs/cgroup", filepath.FromSlash(p))
	l := CgroupLimits{
		Path:      p,
		MemoryMax: parseCgroupValue(readCgroupFile(filepath.Join(dir, "memory.max"))),
		MemoryHi:  parseCgroupValue(readCgroupFile(filepath.Join(dir, "memory.high"))),
		TasksMax:  parseCgroupValue(readCgroupFile(filepath.Join(dir, "pids.max"))),
	}
	return l, l.MemoryMax != 0 || l.MemoryHi != 0 || l.TasksMax != 0
}

func readCgroupFile(path string) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	data, _ := io.ReadAll(io.LimitReader(f, 4096))
	return data
}
