//go:build !windows

package winapp

import (
	"context"
	"net/netip"
	"os"
)

// IsElevated reports whether the process runs as root on non-Windows systems.
func IsElevated() bool { return os.Geteuid() == 0 }

// RelaunchElevated is Windows-only.
func RelaunchElevated(args []string) error { return ErrUnsupported }

// OpenURL is Windows-only. The URL is still validated so callers get the same
// error for a bad address on every platform.
func OpenURL(rawURL string) error {
	if _, err := validateLoopbackURL(rawURL); err != nil {
		return err
	}
	return ErrUnsupported
}

// InstallDir has no meaning outside Windows; it returns "".
func InstallDir() string { return "" }

// DataDir has no meaning outside Windows; it returns "".
func DataDir() string { return "" }

// InstallService is Windows-only.
func InstallService(srcExe string) (string, error) { return "", ErrUnsupported }

// StartService is Windows-only.
func StartService() error { return ErrUnsupported }

// StopService is Windows-only.
func StopService() error { return ErrUnsupported }

// ServiceRunning is Windows-only.
func ServiceRunning() (bool, error) { return false, ErrUnsupported }

// UninstallService is Windows-only.
func UninstallService() error { return ErrUnsupported }

// RunService runs run directly with a context cancelled on Ctrl+C/SIGTERM.
func RunService(run func(ctx context.Context) error) error { return runConsole(run) }

// EnsureFirewallRules is Windows-only; inputs are still validated.
func EnsureFirewallRules(exePath string, overlayIPv4 string) error {
	if _, err := validateProgramPath(exePath); err != nil {
		return err
	}
	if _, err := validateIPv4CIDR(overlayIPv4); err != nil {
		return err
	}
	return ErrUnsupported
}

// RemoveFirewallRules is Windows-only.
func RemoveFirewallRules() error { return ErrUnsupported }

// Tray is a no-op outside Windows; Run returns ErrUnsupported.
type Tray struct{}

// NewTray returns a Tray whose Run reports ErrUnsupported.
func NewTray(tooltip string) *Tray { return &Tray{} }

// SetItems does nothing outside Windows.
func (t *Tray) SetItems(items []MenuItem) {}

// SetTooltip does nothing outside Windows.
func (t *Tray) SetTooltip(s string) {}

// OnClick does nothing outside Windows.
func (t *Tray) OnClick(fn func(id int)) {}

// OnLeftClick does nothing outside Windows.
func (t *Tray) OnLeftClick(fn func()) {}

// Notify does nothing outside Windows.
func (t *Tray) Notify(title, msg string) {}

// SetIconPNG validates the PNG; the icon itself is Windows-only.
func (t *Tray) SetIconPNG(png []byte) error {
	_, err := decodePNG(png)
	return err
}

// Run returns ErrUnsupported.
func (t *Tray) Run(ctx context.Context) error { return ErrUnsupported }

// SetClipboardText is Windows-only.
func SetClipboardText(string) error { return ErrUnsupported }

// RemoteAccessStatus describes remote desktop and SSH (Windows only).
type RemoteAccessStatus struct {
	RDPEnabled   bool
	RDPPort      int
	RDPScoped    bool
	SSHInstalled bool
	SSHPort      int
	SSHScoped    bool
}

// Listener is a listening socket (Windows only).
type Listener struct {
	Proto   string
	Address string
	Port    int
	Process string
}

// GetRemoteAccess is Windows-only.
func GetRemoteAccess() (RemoteAccessStatus, error) { return RemoteAccessStatus{}, ErrUnsupported }

// SetRemoteAccessScope is Windows-only.
func SetRemoteAccessScope(string, bool, []netip.Prefix) error { return ErrUnsupported }

// ListeningPorts is Windows-only.
func ListeningPorts() ([]Listener, error) { return nil, ErrUnsupported }
