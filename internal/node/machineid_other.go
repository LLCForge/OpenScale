//go:build !windows

package node

import (
	"os"
	"strings"
)

// machineID reads the systemd/D-Bus machine id (Linux) or the host id
// (FreeBSD). Other systems have no stable id here and skip the binding.
func machineID() (string, bool) {
	for _, path := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id", "/etc/hostid"} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if v := strings.TrimSpace(string(data)); len(v) >= 8 && len(v) <= 128 && strings.Trim(v, "0") != "" {
			return v, true
		}
	}
	return "", false
}
