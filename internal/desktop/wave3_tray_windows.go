package desktop

import (
	"context"
	"net/http"
	"strings"

	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/winapp"
)

// Connection wave 3 in the tray: the automatic exit node choice in effect
// (ADR-0133) and the network profile switch (ADR-0135).

// profileIDBase numbers the profile items; profile choices travel in the
// exit choice map with profileChoicePrefix, which no device name has.
const (
	profileIDBase       = 5000
	profileChoicePrefix = "\x00profile:"
)

// exitAutoItem describes the automatic exit node choice, if it runs.
func exitAutoItem(dev *panel.DeviceStatus) (winapp.MenuItem, bool) {
	if dev == nil || dev.Wave3 == nil || dev.Wave3.ExitAuto == nil {
		return winapp.MenuItem{}, false
	}
	a := dev.Wave3.ExitAuto
	mode := "yedekli"
	if a.Settings.Mode == panel.ExitAutoFastest {
		mode = "en hızlı"
	}
	if a.Settings.Untrusted {
		mode += ", güvenilmeyen ağda"
	}
	exit := a.Exit
	if exit == "" {
		exit = "kapalı"
	}
	return winapp.MenuItem{Label: "Otomatik seçim (" + mode + "): " + exit, Detail: a.Reason, Disabled: true}, true
}

// profileItems lists the network profiles; a click on another joined
// profile switches to it (the tunnel restarts).
func profileItems(dev *panel.DeviceStatus, choices map[int]string) []winapp.MenuItem {
	if dev == nil || dev.Wave3 == nil || len(dev.Wave3.Profiles) < 2 {
		return nil
	}
	var out []winapp.MenuItem
	for i, p := range dev.Wave3.Profiles {
		label := p.Name
		if p.DisplayName != "" {
			label += " (" + p.DisplayName + ")"
		}
		item := winapp.MenuItem{Label: label, Checked: p.Active, Disabled: !p.Joined || p.Active}
		if p.Joined && !p.Active {
			item.ID = profileIDBase + i
			choices[item.ID] = profileChoicePrefix + p.Name
		}
		out = append(out, item)
	}
	return out
}

// profileChoice returns the profile name of a tray choice.
func profileChoice(choice string) (string, bool) {
	return strings.CutPrefix(choice, profileChoicePrefix)
}

// setProfile switches the network profile through the service.
func (c *trayClient) setProfile(ctx context.Context, name string) error {
	var st panel.AppStatus
	return c.do(ctx, http.MethodPost, "/api/app/tray/profile", map[string]string{"name": name}, &st)
}
