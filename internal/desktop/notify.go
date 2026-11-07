package desktop

import "github.com/openscale/openscale/internal/panel"

// notifyCodes are the health alerts announced with a tray notification
// when they appear (F-017, F-018); the others are shown in the menu only.
var notifyCodes = map[string]string{
	panel.HealthCaptivePortal: "Bu ağ bir giriş sayfası (captive portal) bekliyor. Ayrıntı için OpenScale panelini açın.",
}

// alertNotifier remembers which alerts were already announced, so each is
// shown once per appearance.
type alertNotifier struct {
	shown map[string]bool
}

// update returns the notification texts for alerts that appeared since the
// last status. An unreachable service changes nothing.
func (n *alertNotifier) update(st panel.AppStatus, reachable bool) []string {
	if !reachable {
		return nil
	}
	if n.shown == nil {
		n.shown = map[string]bool{}
	}
	present := map[string]bool{}
	var out []string
	for _, a := range st.Health {
		msg, ok := notifyCodes[a.Code]
		if !ok || present[a.Code] {
			continue
		}
		present[a.Code] = true
		if !n.shown[a.Code] {
			out = append(out, msg)
		}
	}
	n.shown = present
	return out
}
