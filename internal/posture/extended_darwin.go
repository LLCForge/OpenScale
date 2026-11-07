//go:build darwin

package posture

import (
	"context"
	"os/exec"
	"time"
)

func collectExtended() Extended {
	var x Extended
	run := func(name string, args ...string) string {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		out, _ := exec.CommandContext(ctx, name, args...).CombinedOutput()
		if len(out) > 1024 {
			return ""
		}
		return string(out)
	}
	x.Disk = MacFileVault(run("/usr/bin/fdesetup", "status"))
	x.ScreenLock, x.LockMinutes = MacScreenLock(run("/usr/sbin/sysadminctl", "-screenLock", "status"))
	// Secure Boot on Apple silicon is always enforced at full security
	// unless lowered in recovery; without a reliable unprivileged query
	// it stays Unknown, like the Secure Enclave as TPM.
	return x
}
