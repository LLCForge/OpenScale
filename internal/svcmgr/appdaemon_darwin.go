//go:build darwin

package svcmgr

import "context"

// InstallDarwinApp installs or updates the macOS app service from this
// program (root; ADR-0227).
func InstallDarwinApp(ctx context.Context) (Result, error) { return installDarwinApp(ctx, realOps()) }

// RestartDarwinApp restarts the macOS app service (root).
func RestartDarwinApp(ctx context.Context) error { return restartDarwinApp(ctx, realOps()) }

// UninstallDarwinApp removes the macOS app service; state stays.
func UninstallDarwinApp(ctx context.Context) ([]string, error) {
	return uninstallDarwinApp(ctx, realOps())
}

// DarwinAppInstalled reports whether the app service is installed.
func DarwinAppInstalled() bool { return darwinAppInstalled(realOps()) }
