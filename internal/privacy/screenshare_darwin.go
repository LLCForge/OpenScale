//go:build darwin

package privacy

import (
	"bytes"
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// processNames asks ps for the executable paths of all processes.
func processNames() ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/bin/ps", "-axo", "comm=").Output()
	if err != nil {
		return nil, err
	}
	var names []string
	for _, line := range bytes.Split(out, []byte("\n")) {
		if len(names) >= maxProcesses {
			break
		}
		s := strings.TrimSpace(string(line))
		if s != "" {
			names = append(names, filepath.Base(s))
		}
	}
	return names, nil
}
