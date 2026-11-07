//go:build !windows && !darwin && !linux

package desktop

import (
	"context"
	"errors"
)

var errWindowsOnly = errors.New("masaüstü uygulaması şimdilik yalnızca Windows'ta; bu sistemde komut satırını kullanın")

// LaunchedByDoubleClick is always false outside Windows.
func LaunchedByDoubleClick() bool { return false }

// RunApp is Windows-only.
func RunApp(context.Context) error { return errWindowsOnly }

// RunService is Windows-only.
func RunService() error { return errWindowsOnly }

// Uninstall is Windows-only.
func Uninstall() error { return errWindowsOnly }

// RunAppQuiet is Windows-only.
func RunAppQuiet(context.Context) error { return errWindowsOnly }
