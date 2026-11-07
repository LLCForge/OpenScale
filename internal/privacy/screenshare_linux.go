//go:build linux

package privacy

import (
	"os"
	"strings"
)

// processNames reads /proc/<pid>/comm for every process.
func processNames() ([]string, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if len(out) >= maxProcesses {
			break
		}
		name := e.Name()
		if name == "" || name[0] < '0' || name[0] > '9' {
			continue
		}
		b, err := os.ReadFile("/proc/" + name + "/comm")
		if err != nil || len(b) > 64 {
			continue
		}
		out = append(out, strings.TrimSpace(string(b)))
	}
	return out, nil
}
