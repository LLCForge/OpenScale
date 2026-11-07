//go:build !windows && !darwin

package peercred

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ProcessImagePath returns the program file of a process (Linux /proc);
// elsewhere ErrUnsupported.
func ProcessImagePath(pid int) (string, error) {
	p, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe")
	if err != nil {
		if os.IsNotExist(err) {
			return "", ErrUnsupported
		}
		return "", fmt.Errorf("image of process %d: %w", pid, err)
	}
	return strings.TrimSuffix(p, " (deleted)"), nil
}

// parentProcess reads PPid from /proc/<pid>/status.
func parentProcess(pid int) (int, error) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return 0, ErrUnsupported
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, "PPid:"); ok {
			return strconv.Atoi(strings.TrimSpace(v))
		}
	}
	return 0, nil
}
