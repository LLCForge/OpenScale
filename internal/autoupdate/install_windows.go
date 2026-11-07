//go:build windows

package autoupdate

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/openscale/openscale/internal/updater"
)

const (
	createNewProcessGroup = 0x00000200
	detachedProcess       = 0x00000008
)

func packageOptions() (updater.PackageOptions, error) {
	return updater.PackageOptions{}, errors.New("Windows'ta paket kurulumu yok")
}

// Trigger starts "<exe> update auto install" as a detached process of the
// service: the installer stops the service, replaces the program and
// starts it again, so it must not be part of the service process. It runs
// with the service's (LocalSystem) rights; a non-elevated caller cannot
// start it.
func Trigger(exe string) func(context.Context) error {
	return func(context.Context) error {
		if exe == "" {
			self, err := os.Executable()
			if err != nil {
				return err
			}
			exe = self
		}
		cmd := exec.Command(exe, "update", "auto", "install")
		cmd.Dir = filepath.Dir(exe)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNewProcessGroup | detachedProcess}
		if err := cmd.Start(); err != nil {
			return err
		}
		return cmd.Process.Release()
	}
}
