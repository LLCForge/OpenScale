//go:build darwin

package osnet

import (
	"net/netip"
	"time"
)

// The macOS kill switch is the pf anchor "com.openscale" (#73, ADR-0100);
// darwin_pf.go holds the logic.

// KillSwitchSupported reports whether this system has a persistent kill
// switch: on macOS, whether pfctl is present.
func KillSwitchSupported() bool { return hostKillSwitch.supported() }

// InstallKillSwitch replaces the anchor's rules for cfg, hooks the anchor
// into pf, enables pf and saves cfg for the boot daemon.
func InstallKillSwitch(cfg KillSwitchConfig) error { return hostKillSwitch.install(cfg) }

// RemoveKillSwitch flushes the anchor, restores the system's pf.conf,
// releases OpenScale's pf reference and deletes the saved configuration.
func RemoveKillSwitch() error { return hostKillSwitch.removeAll() }

// KillSwitchInstalled reports whether the kill switch blocks traffic now.
func KillSwitchInstalled() (bool, error) { return hostKillSwitch.installed() }

// RestoreKillSwitch installs the saved kill switch again, if one is saved.
func RestoreKillSwitch() (bool, error) { return hostKillSwitch.restore() }

// KillSwitchBootSupported reports whether the kill switch can be restored
// at boot: launchd is always there on macOS.
func KillSwitchBootSupported() bool { return hostKillSwitch.bootSupported() }

// EnableKillSwitchBoot writes the launch daemon com.openscale.killswitch,
// which runs "openscale killswitch restore" at boot (#74).
func EnableKillSwitchBoot(exe string) error { return hostKillSwitch.enableBoot(exe) }

// DisableKillSwitchBoot removes the launch daemon.
func DisableKillSwitchBoot() error { return hostKillSwitch.disableBoot() }

// KillSwitchBootEnabled reports whether the launch daemon is installed.
func KillSwitchBootEnabled() (bool, error) { return hostKillSwitch.bootEnabled() }

// AllowCaptivePortal is not available on macOS (ErrCaptiveUnsupportedDarwin).
func AllowCaptivePortal(addrs []netip.Addr, d time.Duration) error {
	if _, err := validCaptive(addrs, d); err != nil {
		return err
	}
	return ErrCaptiveUnsupportedDarwin
}

// RevokeCaptivePortal has nothing to revoke on macOS.
func RevokeCaptivePortal() error { return nil }
