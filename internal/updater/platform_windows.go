//go:build windows

package updater

import (
	"path/filepath"

	"github.com/openscale/openscale/internal/svcmgr"
	"github.com/openscale/openscale/internal/winapp"
)

// DefaultPlatform describes the Windows installation (ADR-0014): one
// service runs every role from %ProgramFiles%\OpenScale\openscale.exe.
func DefaultPlatform() (Platform, error) {
	data := winapp.DataDir()
	state := filepath.Join(data, "update")
	return Platform{
		Exe:        filepath.Join(winapp.InstallDir(), "openscale.exe"),
		DataDir:    data,
		StateDir:   state,
		Services:   []Service{managedService{role: svcmgr.RoleDevice}},
		ReadMarker: func() (Marker, error) { return ReadMarkerFile(filepath.Join(state, MarkerFile)) },
	}, nil
}

// DefaultRootKeyFile is where an installation keeps the release root key.
func DefaultRootKeyFile() string {
	return filepath.Join(winapp.InstallDir(), "release-root.pub")
}

// RequirePrivileges fails unless this process may replace the program
// and control the service.
func RequirePrivileges() error {
	if !winapp.IsElevated() {
		return svcmgr.ErrNeedsAdmin
	}
	return nil
}
