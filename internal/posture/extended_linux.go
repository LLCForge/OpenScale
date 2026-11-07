//go:build linux

package posture

import (
	"context"
	"os"
	"os/exec"
	"time"

	"github.com/openscale/openscale/internal/tpm"
)

const efiSecureBoot = "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-e39b6b4b2b8c"

func collectExtended() Extended {
	var x Extended
	if b, err := os.ReadFile(efiSecureBoot); err == nil {
		x.SecureBoot = ParseEFISecureBoot(b)
	} else if _, err := os.Stat("/sys/firmware/efi"); err != nil {
		// Legacy BIOS boot has no Secure Boot.
		x.SecureBoot = Off
	}
	if p, err := tpm.Detect(); err == nil {
		if p.Present && p.Version == "2.0" {
			x.TPM = On
		} else {
			x.TPM = Off
		}
	}
	x.ScreenLock, x.LockMinutes = gnomeLock()
	return x
}

// gnomeLock asks gsettings; it works only inside a desktop session (the
// service running as root gets Unknown).
func gnomeLock() (State, int) {
	path, err := exec.LookPath("gsettings")
	if err != nil {
		return Unknown, 0
	}
	run := func(args ...string) string {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, path, args...).Output()
		if err != nil || len(out) > 256 {
			return ""
		}
		return string(out)
	}
	return GnomeScreenLock(run("get", "org.gnome.desktop.screensaver", "lock-enabled"),
		run("get", "org.gnome.desktop.session", "idle-delay"))
}
