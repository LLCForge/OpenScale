//go:build windows

package node

import (
	"strings"

	"golang.org/x/sys/windows/registry"
)

// machineID reads the Windows installation's MachineGuid.
func machineID() (string, bool) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return "", false
	}
	defer k.Close()
	v, _, err := k.GetStringValue("MachineGuid")
	v = strings.TrimSpace(v)
	if err != nil || len(v) < 8 {
		return "", false
	}
	return v, true
}
