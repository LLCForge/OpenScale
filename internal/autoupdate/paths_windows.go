//go:build windows

package autoupdate

import (
	"path/filepath"

	"github.com/openscale/openscale/internal/winapp"
)

// DefaultPaths describes the Windows installation (ADR-0014): the service
// runs from %ProgramFiles%\OpenScale and keeps its data in %ProgramData%.
func DefaultPaths() Paths {
	upd := filepath.Join(winapp.DataDir(), "update")
	return Paths{
		Supported:    true,
		Mode:         ModeBinary,
		Exe:          filepath.Join(winapp.InstallDir(), "openscale.exe"),
		UpdaterState: upd,
		Settings:     filepath.Join(upd, SettingsFile),
		Work:         filepath.Join(upd, "auto"),
	}
}

// IsDeviceServiceDir is false: on Windows the service runs the updater
// itself (internal/service), never "openscale up".
func IsDeviceServiceDir(string) bool { return false }

// DefaultCoordinatorStateDir is the coordinator folder of the service.
func DefaultCoordinatorStateDir() string { return filepath.Join(winapp.DataDir(), "coordinator") }
