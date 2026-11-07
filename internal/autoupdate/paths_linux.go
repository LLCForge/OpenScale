//go:build linux

package autoupdate

import (
	"os"
	"path/filepath"
)

const (
	linuxUpdateDir = "/var/lib/openscale/update"
	// linuxWorkDir is inside the device unit's only writable folder
	// (ReadWritePaths=/var/lib/openscale/device); the privileged installer
	// (openscale-autoupdate.service) reads the request from there.
	linuxWorkDir   = "/var/lib/openscale/device/autoupdate"
	linuxDeviceDir = "/var/lib/openscale/device"
	packageBinary  = "/usr/bin/openscale"
	localBinary    = "/usr/local/bin/openscale"
	dpkgList       = "/var/lib/dpkg/info/openscale.list"
)

// DefaultPaths describes the Linux installation: the .deb (/usr/bin) or
// the binary of "openscale service install" (/usr/local/bin). An RPM
// installation is left to its package manager.
func DefaultPaths() Paths {
	p := Paths{
		Supported:    true,
		Mode:         ModeBinary,
		Exe:          localBinary,
		UpdaterState: linuxUpdateDir,
		Settings:     filepath.Join(linuxUpdateDir, SettingsFile),
		Work:         linuxWorkDir,
	}
	if info, err := os.Stat(packageBinary); err == nil && info.Mode().IsRegular() {
		if _, err := os.Stat(dpkgList); err == nil {
			p.Mode, p.Exe = ModeDeb, packageBinary
		} else {
			p.Supported = false
			p.Reason = "OpenScale RPM paketiyle kurulmuş; otomatik güncelleme yalnızca .deb ve ikili kurulumda var. Güncellemeyi dnf ile yapın."
		}
	}
	return p
}

// DefaultCoordinatorStateDir is the coordinator unit's state directory.
func DefaultCoordinatorStateDir() string { return "/var/lib/openscale/coordinator" }

// IsDeviceServiceDir reports whether dir is the device unit's state
// directory, where "openscale up" runs as the installed service.
func IsDeviceServiceDir(dir string) bool { return filepath.Clean(dir) == linuxDeviceDir }
