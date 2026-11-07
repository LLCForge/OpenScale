//go:build linux

package updater

import (
	"errors"
	"os"

	"github.com/openscale/openscale/internal/svcmgr"
)

const (
	packageBinary = "/usr/bin/openscale"
	localBinary   = "/usr/local/bin/openscale"
)

// ErrPackageManaged: the program came with a .deb or .rpm package, whose
// manager must also do the update (its file list and checksums would be
// wrong otherwise).
var ErrPackageManaged = errors.New("OpenScale paketle kurulmuş (" + packageBinary + "); güncellemeyi paket yöneticisiyle yapın (apt/dnf), imzalı paket ADR-0091")

// DefaultPlatform describes a Linux installation made by "openscale
// service install" or deploy/linux: /usr/local/bin/openscale with the
// openscale-device and openscale-coordinator units.
func DefaultPlatform() (Platform, error) {
	if info, err := os.Stat(packageBinary); err == nil && info.Mode().IsRegular() {
		return Platform{}, ErrPackageManaged
	}
	return Platform{
		Exe:      localBinary,
		DataDir:  "/var/lib/openscale",
		StateDir: "/var/lib/openscale/update",
		Services: []Service{managedService{role: svcmgr.RoleDevice}, managedService{role: svcmgr.RoleCoordinator}},
	}, nil
}

// PackagePlatform describes the .deb installation (/usr/bin/openscale) for
// ApplyPackage (ADR-0225): the package manager replaces the program.
func PackagePlatform() Platform {
	return Platform{
		Exe:      packageBinary,
		DataDir:  "/var/lib/openscale",
		StateDir: "/var/lib/openscale/update",
		Services: []Service{managedService{role: svcmgr.RoleDevice}, managedService{role: svcmgr.RoleCoordinator}},
	}
}

// DefaultRootKeyFile is the conffile the packages and install scripts use.
func DefaultRootKeyFile() string { return "/etc/openscale/release-root.pub" }

// RequirePrivileges fails unless this process runs as root.
func RequirePrivileges() error {
	if os.Geteuid() != 0 {
		return svcmgr.ErrNeedsRoot
	}
	return nil
}
