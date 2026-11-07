//go:build windows

package leaktest

import "golang.org/x/sys/windows/registry"

// platformTimeZone reads the Windows time zone key name.
func platformTimeZone() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, err := k.GetStringValue("TimeZoneKeyName")
	if err != nil || len(v) > 128 {
		return ""
	}
	return v
}

// platformRegion is unknown on Windows: the language region is not
// compared there.
func platformRegion() string { return "" }
