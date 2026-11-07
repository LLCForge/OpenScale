//go:build windows

package svcmgr

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/openscale/openscale/internal/winapp"
)

// On Windows one service runs every role (ADR-0014); the role only
// selects which parameters make sense, and both name the same service.

func windowsRole(r Role) error {
	if r != RoleDevice && r != RoleCoordinator && r != "" {
		return fmt.Errorf("rol %q geçersiz", r)
	}
	return nil
}

// Install copies this program to %ProgramFiles%\OpenScale, creates or
// updates the service and starts it.
func Install(_ context.Context, o Options) (Result, error) {
	if err := windowsRole(o.Role); err != nil {
		return Result{}, err
	}
	if o.StateDir != "" || o.ListenPort != 0 || o.Interface != "" || o.TCPListen != "" {
		return Result{}, errors.New("Windows servisinin ayarları panelden veya 'openscale set' ile yapılır; --state-dir, --listen-port, --interface ve --tcp-listen yalnızca Linux'ta")
	}
	if !winapp.IsElevated() {
		return Result{}, ErrNeedsAdmin
	}
	exe, err := os.Executable()
	if err != nil {
		return Result{}, err
	}
	dst, err := winapp.InstallService(exe)
	if err != nil {
		return Result{}, err
	}
	res := Result{Binary: dst}
	if err := winapp.CheckTrustedAncestors(dst); err != nil {
		res.Notes = append(res.Notes, "UYARI: program klasörünün üst klasörlerinde fazla geniş izin var: "+err.Error())
	}
	if o.NoStart {
		res.Notes = append(res.Notes, "Servis kuruldu ve açılışta başlayacak; şimdi başlatmak için: openscale service start")
		return res, nil
	}
	if err := winapp.StartService(); err != nil {
		return res, err
	}
	res.Started = true
	return res, nil
}

// Start starts the service.
func Start(_ context.Context, r Role) error {
	if err := windowsRole(r); err != nil {
		return err
	}
	if !winapp.IsElevated() {
		return ErrNeedsAdmin
	}
	return winapp.StartService()
}

// Stop stops the service; the kill switch filters stay (ADR-0023).
func Stop(_ context.Context, r Role) error {
	if err := windowsRole(r); err != nil {
		return err
	}
	if !winapp.IsElevated() {
		return ErrNeedsAdmin
	}
	return winapp.StopService()
}

// Restart stops and starts the service.
func Restart(ctx context.Context, r Role) error {
	if err := Stop(ctx, r); err != nil {
		return err
	}
	return winapp.StartService()
}

// Get returns the service state; it works without elevation.
func Get(_ context.Context, r Role) (Status, error) {
	if err := windowsRole(r); err != nil {
		return Status{}, err
	}
	info, err := winapp.QueryService()
	if err != nil {
		return Status{}, err
	}
	return Status{Installed: info.Installed, Running: info.Running, Enabled: info.Automatic, State: info.State,
		Binary: info.Binary, PID: int(info.PID)}, nil
}

// Uninstall is done by "openscale service uninstall" through the desktop
// package, which also removes the kill switch and firewall rules.
func Uninstall(context.Context, Role) ([]string, error) { return nil, ErrUnsupported }
