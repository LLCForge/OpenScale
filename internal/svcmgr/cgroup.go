package svcmgr

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"
)

// Cgroup v2 limits of this process (#494), read for the platform status.

// CgroupLimits are the memory and task ceilings of this process's cgroup.
type CgroupLimits struct {
	Path      string `json:"path,omitempty"`
	MemoryMax uint64 `json:"memory_max,omitempty"`
	MemoryHi  uint64 `json:"memory_high,omitempty"`
	TasksMax  uint64 `json:"tasks_max,omitempty"`
}

// cgroupV2Path returns the unified hierarchy path from /proc/self/cgroup
// ("0::/system.slice/openscale-device.service").
func cgroupV2Path(data []byte) (string, bool) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := sc.Text()
		if p, ok := strings.CutPrefix(line, "0::"); ok {
			p = strings.TrimSpace(p)
			if !strings.HasPrefix(p, "/") || strings.Contains(p, "..") || len(p) > 512 {
				return "", false
			}
			return p, true
		}
	}
	return "", false
}

// parseCgroupValue reads a memory.max style value; "max" is no limit (0).
func parseCgroupValue(data []byte) uint64 {
	s := strings.TrimSpace(string(data))
	if s == "" || s == "max" {
		return 0
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0
	}
	return n
}
