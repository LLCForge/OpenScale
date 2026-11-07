//go:build linux

package desktop

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/dbuswire"
)

// Desktop notifications (org.freedesktop.Notifications) for the Linux
// tray: messages, and yes/no questions where the server shows buttons
// ("actions" capability). Message text is escaped when the server reads
// markup, so a network or device name can never become markup.

const (
	notifyName = "org.freedesktop.Notifications"
	notifyPath = dbuswire.ObjectPath("/org/freedesktop/Notifications")
	// confirmWait is how long a question waits for an answer.
	confirmWait = 2 * time.Minute
	// maxNotifyText bounds what goes into one notification.
	maxNotifyText = 1000
)

type desktopNotifier struct {
	bus *dbuswire.Conn

	mu        sync.Mutex
	caps      map[string]bool
	capsKnown bool
}

func newDesktopNotifier(bus *dbuswire.Conn) *desktopNotifier { return &desktopNotifier{bus: bus} }

func (n *desktopNotifier) capabilities(ctx context.Context) map[string]bool {
	n.mu.Lock()
	if n.capsKnown {
		defer n.mu.Unlock()
		return n.caps
	}
	n.mu.Unlock()
	caps := map[string]bool{}
	m, err := n.bus.Call(ctx, notifyName, notifyPath, notifyName, "GetCapabilities", "")
	if err == nil && len(m.Body) == 1 {
		for _, c := range stringsOf(m.Body[0]) {
			caps[c] = true
		}
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if err == nil {
		n.caps, n.capsKnown = caps, true
	}
	return caps
}

func notifyText(s string, markup bool) string {
	if r := []rune(s); len(r) > maxNotifyText {
		s = string(r[:maxNotifyText-3]) + "..."
	}
	if markup {
		s = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
	}
	return s
}

func (n *desktopNotifier) notify(ctx context.Context, summary, body string, actions []string, expire int32) (uint32, error) {
	markup := n.capabilities(ctx)["body-markup"]
	hints := map[string]dbuswire.Variant{"urgency": dbuswire.MakeVariant(byte(1))}
	if actions == nil {
		actions = []string{}
	}
	m, err := n.bus.Call(ctx, notifyName, notifyPath, notifyName, "Notify", "susssasa{sv}i",
		"OpenScale", uint32(0), "network-vpn", notifyText(summary, false), notifyText(body, markup), actions, hints, expire)
	if err != nil {
		return 0, err
	}
	if len(m.Body) != 1 {
		return 0, &dbuswire.Error{Name: dbuswire.ErrNameFailed}
	}
	id, _ := m.Body[0].(uint32)
	return id, nil
}

// show sends a message; failures are dropped (there is nowhere else to
// show them).
func (n *desktopNotifier) show(summary, body string) {
	if n == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), busCallTimeout)
	defer cancel()
	_, _ = n.notify(ctx, summary, body, nil, -1)
}

// confirm asks a yes/no question. asked is false when the server shows no
// buttons; the caller then decides without an answer.
func (n *desktopNotifier) confirm(ctx context.Context, summary, body, yes, no string) (answer, asked bool) {
	if n == nil {
		return false, false
	}
	cctx, cancel := context.WithTimeout(ctx, busCallTimeout)
	caps := n.capabilities(cctx)
	cancel()
	if !caps["actions"] {
		return false, false
	}
	sctx, scancel := context.WithTimeout(ctx, busCallTimeout)
	sub, err := n.bus.Subscribe(sctx, dbuswire.Match{Path: notifyPath, Interface: notifyName}, 8)
	scancel()
	if err != nil {
		return false, false
	}
	defer sub.Close()
	nctx, ncancel := context.WithTimeout(ctx, busCallTimeout)
	id, err := n.notify(nctx, summary, body, []string{"yes", yes, "no", no}, 0)
	ncancel()
	if err != nil {
		return false, false
	}
	octx, ocancel := context.WithTimeout(ctx, busCallTimeout)
	owner, err := n.bus.NameOwner(octx, notifyName)
	ocancel()
	if err != nil {
		return false, true
	}
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), busCallTimeout)
		defer cancel()
		_, _ = n.bus.Call(c, notifyName, notifyPath, notifyName, "CloseNotification", "u", id)
	}()
	timer := time.NewTimer(confirmWait)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return false, true
		case <-timer.C:
			return false, true
		case m, ok := <-sub.C:
			if !ok {
				return false, true
			}
			// Only the notification server's own signals count.
			if m.Sender != owner || len(m.Body) < 2 {
				continue
			}
			if got, _ := m.Body[0].(uint32); got != id {
				continue
			}
			switch m.Member {
			case "ActionInvoked":
				key, _ := m.Body[1].(string)
				return key == "yes", true
			case "NotificationClosed":
				return false, true
			}
		}
	}
}
