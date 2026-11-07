//go:build linux

package svcmgr

import (
	"context"
	"os"
	"os/user"
	"slices"
	"strconv"
)

// InstallLinuxApp installs or updates the Linux app service from this
// program (root; ADR-0234).
func InstallLinuxApp(ctx context.Context) (Result, error) {
	s, err := realOps()
	if err != nil {
		return Result{}, err
	}
	return installLinuxApp(ctx, s)
}

// RestartLinuxApp restarts the Linux app service (root).
func RestartLinuxApp(ctx context.Context) error {
	s, err := realOps()
	if err != nil {
		return err
	}
	return restartLinuxApp(ctx, s)
}

// UninstallLinuxApp removes the Linux app service; state stays.
func UninstallLinuxApp(ctx context.Context) ([]string, error) {
	s, err := realOps()
	if err != nil {
		return nil, err
	}
	return uninstallLinuxApp(ctx, s)
}

// LinuxAppInstalled reports whether the app unit file is there (no
// systemd needed to answer).
func LinuxAppInstalled() bool {
	_, err := os.Stat(linuxAppUnitPath())
	return err == nil
}

// LinuxDeviceUnitInstalled reports whether the command line device unit
// is installed.
func LinuxDeviceUnitInstalled() bool { return linuxDeviceInstalled(sysOps{}) }

// LinuxAppProgram returns the program the installed app unit runs.
func LinuxAppProgram() (string, error) { return linuxAppProgram(sysOps{}) }

// AddLinuxAppUser puts the user with uid into the openscale group so
// their tray may use the tray socket (root).
func AddLinuxAppUser(ctx context.Context, uid int) ([]string, error) {
	s, err := realOps()
	if err != nil {
		return nil, err
	}
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return nil, err
	}
	g, gerr := user.LookupGroup(LinuxAppGroup)
	exists := gerr == nil
	member := false
	if exists {
		if ids, err := u.GroupIds(); err == nil {
			member = slices.Contains(ids, g.Gid)
		}
	}
	return addToLinuxAppGroup(ctx, s, u.Username, exists, member)
}
