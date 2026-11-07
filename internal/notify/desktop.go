package notify

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Desktop delivers a notification to the owner's own devices through the
// tunnel. The transport belongs to the caller (the service's local event
// stream or the tray connection), so this package never opens a listener;
// Deliver is called once per device and must only reach a device that the
// signed document lists as the owner's.
type Desktop struct {
	Label   string
	Devices []string
	Deliver func(ctx context.Context, device string, m Message) error
}

// Name implements Channel.
func (d *Desktop) Name() string { return d.Label }

// Send implements Channel. It succeeds when at least one device accepted
// the message.
func (d *Desktop) Send(ctx context.Context, m Message) error {
	if d.Deliver == nil || len(d.Devices) == 0 {
		return errors.New("masaüstü bildirimi için cihaz yok")
	}
	m = m.normalized()
	var errs []error
	for _, dev := range d.Devices {
		if err := d.Deliver(ctx, dev, m); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", dev, err))
			continue
		}
		return nil
	}
	return errors.Join(errs...)
}

// ErrNoLocalNotifier is returned where no local notifier is available.
var ErrNoLocalNotifier = errors.New("bu sistemde yerel masaüstü bildirimi gösterilemiyor")

const localTimeout = 10 * time.Second

// ShowLocal shows m on this computer's desktop with the system's own
// notifier (notify-send on Linux, osascript on macOS). It runs no shell;
// the text is passed as arguments (escaped for AppleScript on macOS). On
// Windows the tray shows notifications itself, so this returns
// ErrNoLocalNotifier.
func ShowLocal(ctx context.Context, m Message) error {
	m = m.normalized()
	name, args, ok := localCommand(m)
	if !ok {
		return ErrNoLocalNotifier
	}
	path, err := exec.LookPath(name)
	if err != nil {
		return ErrNoLocalNotifier
	}
	ctx, cancel := context.WithTimeout(ctx, localTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = desktopEnv()
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("yerel bildirim gösterilemedi: %w (%s)", err, strings.TrimSpace(truncate(string(out), 200)))
	}
	return nil
}

// desktopEnv passes only what a notifier needs to find the session bus
// and the display.
func desktopEnv() []string {
	var env []string
	for _, k := range []string{"PATH", "HOME", "DISPLAY", "WAYLAND_DISPLAY", "DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR"} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}

// appleScriptString quotes s as an AppleScript string literal.
func appleScriptString(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

// notifySendArgs builds notify-send arguments; "--" ends the options so a
// title starting with '-' is never read as a flag.
func notifySendArgs(m Message) []string {
	urgency := "normal"
	switch m.Priority {
	case PriorityLow:
		urgency = "low"
	case PriorityUrgent:
		urgency = "critical"
	}
	return []string{"--app-name=OpenScale", "--urgency=" + urgency, "--", m.Title, m.Body}
}

func osascriptArgs(m Message) []string {
	script := "display notification " + appleScriptString(m.Body) + " with title " + appleScriptString(m.Title)
	return []string{"-e", script}
}
