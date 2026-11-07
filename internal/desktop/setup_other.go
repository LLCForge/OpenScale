//go:build !darwin && !linux

package desktop

import (
	"context"
	"errors"
)

// errMacOnly: the app service commands exist only on macOS and Linux
// (ADR-0227, ADR-0234).
var errMacOnly = errors.New("uygulama servisi komutları yalnızca macOS ve Linux'ta")

// InstallService is macOS only; the Windows app installs its service
// itself.
func InstallService(context.Context) ([]string, error) { return nil, errMacOnly }

// RestartService is macOS only.
func RestartService(context.Context) error { return errMacOnly }
