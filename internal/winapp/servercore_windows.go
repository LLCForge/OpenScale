//go:build windows

package winapp

import "golang.org/x/sys/windows/registry"

// IsServerCore reports whether this Windows has no desktop shell.
func IsServerCore() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	t, _, err := k.GetStringValue("InstallationType")
	return err == nil && isServerCoreType(t)
}
