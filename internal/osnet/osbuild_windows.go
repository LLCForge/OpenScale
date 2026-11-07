//go:build windows

package osnet

import (
	"strconv"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// CurrentOSBuild reads the version from RtlGetVersion (not subject to the
// compatibility shims of GetVersionEx) and the update revision and the
// installation type from the registry.
func CurrentOSBuild() OSBuild {
	v := windows.RtlGetVersion()
	b := OSBuild{
		Family:  "windows",
		Version: strconv.Itoa(int(v.MajorVersion)) + "." + strconv.Itoa(int(v.MinorVersion)),
		Build:   strconv.Itoa(int(v.BuildNumber)),
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return b
	}
	defer k.Close()
	if ubr, _, err := k.GetIntegerValue("UBR"); err == nil {
		b.Patch = strconv.FormatUint(ubr, 10)
	}
	if t, _, err := k.GetStringValue("InstallationType"); err == nil {
		b.Edition = cleanBuildField(t)
	}
	return b
}
