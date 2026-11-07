//go:build windows

package sysinfo

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func collectEnv(in *Info) {
	var vendor, product string
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\BIOS`, registry.QUERY_VALUE); err == nil {
		vendor, _, _ = k.GetStringValue("SystemManufacturer")
		product, _, _ = k.GetStringValue("SystemProductName")
		k.Close()
	}
	in.Model = joinModel(vendor, product)
	in.Virt = virtFromModel(vendor, product)
	in.Pkg = windowsPackage()
}

// windowsPackage tells the installed service (Program Files) from a copy
// run from elsewhere.
func windowsPackage() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	pf, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err == nil && pf != "" && strings.HasPrefix(strings.ToLower(filepath.Clean(exe)), strings.ToLower(filepath.Clean(pf))+`\`) {
		return "installed"
	}
	return "portable"
}
