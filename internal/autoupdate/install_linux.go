//go:build linux

package autoupdate

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/updater"
)

const dpkgTimeout = 10 * time.Minute

func packageOptions() (updater.PackageOptions, error) {
	if err := updater.RequirePrivileges(); err != nil {
		return updater.PackageOptions{}, err
	}
	p := updater.PackagePlatform()
	return updater.PackageOptions{
		Options: updater.Options{Exe: p.Exe, StateDir: p.StateDir, Services: p.Services},
		Install: dpkgInstall,
	}, nil
}

// dpkgInstall installs a verified package file. The administrator's
// changes to conffiles (/etc/openscale/release-root.pub) are kept; the
// package's postinst restarts the units that were running.
func dpkgInstall(ctx context.Context, path string) error {
	ctx, cancel := context.WithTimeout(ctx, dpkgTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/dpkg", "--force-confold", "--install", "--", path)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "DEBIAN_FRONTEND=noninteractive"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if len(msg) > 400 {
			msg = msg[len(msg)-400:]
		}
		return fmt.Errorf("dpkg başarısız: %w: %s", err, msg)
	}
	return nil
}

// Trigger is nil on Linux: openscale-autoupdate.path starts the installer
// as root when the device writes the request (the device unit itself has
// no right to replace the program).
func Trigger(string) func(context.Context) error { return nil }
