//go:build windows

package filesend

import "golang.org/x/sys/windows/registry"

// defenderCloud reads Defender's cloud protection setting (MAPS
// membership): the policy value wins over the local one. 0 is off.
func defenderCloud() (on, known bool) {
	for _, p := range []string{
		`SOFTWARE\Policies\Microsoft\Windows Defender\Spynet`,
		`SOFTWARE\Microsoft\Windows Defender\Spynet`,
	} {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, p, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		v, _, err := k.GetIntegerValue("SpynetReporting")
		_ = k.Close()
		if err == nil {
			return v != 0, true
		}
	}
	return false, false
}
