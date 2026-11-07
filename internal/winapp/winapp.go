// Package winapp contains the Windows desktop integration of OpenScale:
// UAC elevation, the Windows service, Windows Defender Firewall rules and
// the notification-area (tray) icon.
//
// Every exported function has a stub on other platforms so the module keeps
// building on Linux and macOS; those stubs return ErrUnsupported or do nothing
// where doing nothing is the sensible behavior.
package winapp

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"
)

// Service identity as registered with the Service Control Manager.
const (
	ServiceName        = "OpenScale"
	ServiceDisplayName = "OpenScale"
	ServiceDescription = "OpenScale kişisel mesh VPN servisi"
)

// Firewall rule names; they are also the keys used to delete the rules.
const (
	firewallRuleUDP  = "OpenScale (UDP)"
	firewallRulePing = "OpenScale (ping)"
)

// ErrUnsupported is returned by the non-Windows stubs.
var ErrUnsupported = errors.New("bu özellik yalnızca Windows'ta")

// ErrSystemShutdown is the cancellation cause of the service context when
// Windows shuts down, as opposed to a requested stop. The persistent kill
// switch stays installed across a shutdown (ADR-0023).
var ErrSystemShutdown = errors.New("system shutdown")

// MenuItem is one entry of the tray popup menu. ID must be in 1..65535 for
// the item to be clickable; Separator items ignore every other field.
type MenuItem struct {
	ID        int
	Label     string
	Disabled  bool
	Separator bool
	// Detail is shown right-aligned after the label (e.g. an IP address).
	Detail string
	// Checked shows a check mark; Default renders the item in bold.
	Checked bool
	Default bool
	// Children turns the item into a submenu; ID is then ignored.
	Children []MenuItem
}

// runConsole runs fn with a context that is cancelled on Ctrl+C or on a
// termination request (console close, logoff, shutdown on Windows).
func runConsole(run func(ctx context.Context) error) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return run(ctx)
}
