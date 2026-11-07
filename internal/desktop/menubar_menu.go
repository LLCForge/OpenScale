package desktop

import (
	"fmt"

	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/winapp"
)

// The macOS menu bar menu (ADR-0227) and the Linux tray menu (ADR-0234).
// It is built here, without AppKit or D-Bus, so the layout is tested on
// every system; menubar_darwin.go turns it into an NSMenu and sni.go into
// a dbusmenu layout. The order follows the Windows tray: state and the
// connection switch, problems, this device, exit nodes, then the app.

// Menu bar item ids. Exit node entries use mbExitBase + index.
const (
	mbToggle = iota + 1
	mbThisDevice
	mbOpen
	mbAutostart
	mbAbout
	mbPanic
	mbQuit
	mbInstall
	mbRestart
	mbReleaseKillSwitch
	mbKillSwitch
	mbExitNone
	mbExitLast
	mbDisconnect5Min
	mbDisconnect1Hour
	mbDisconnectMorning
	mbExitBase = 3000
)

// mbDisconnectChoices maps the timed disconnect items to the service's
// choices (F-121).
var mbDisconnectChoices = map[int]string{
	mbDisconnect5Min:    panel.Disconnect5Min,
	mbDisconnect1Hour:   panel.Disconnect1Hour,
	mbDisconnectMorning: panel.DisconnectMorning,
}

// menuBarService is what the app knows about the background service when
// the tray socket does not answer.
type menuBarService int

const (
	// serviceUnknown: the socket answered or nothing is known.
	serviceUnknown menuBarService = iota
	// serviceMissing: the launch daemon is not installed.
	serviceMissing
	// serviceInstalled: installed but not answering (starting, stopped
	// or crashed).
	serviceInstalled
	// serviceOutdated: answering, but it runs another program than this
	// app, so the socket refuses the app until the service is updated.
	serviceOutdated
	// serviceCommandLine: no app service, but the command line device
	// service (Linux openscale-device.service) runs the tunnel; the two
	// never run side by side (ADR-0234).
	serviceCommandLine
)

// menuBarState is everything the menu is built from.
type menuBarState struct {
	status    panel.AppStatus
	reachable bool
	service   menuBarService
	autostart bool
}

// menuBarItems lays out the menu. exits is refilled with the ids that
// choose an exit node ("" for none).
func menuBarItems(s menuBarState, exits map[int]string) []winapp.MenuItem {
	clear(exits)
	if !s.reachable {
		items := []winapp.MenuItem{{Label: "OpenScale", Detail: unreachableLabel(s.service), Disabled: true}, {Separator: true}}
		switch s.service {
		case serviceMissing:
			items = append(items, winapp.MenuItem{ID: mbInstall, Label: "Arka plan servisini kur...", Default: true})
		case serviceOutdated:
			items = append(items, winapp.MenuItem{ID: mbInstall, Label: "Servisi bu sürüme güncelle...", Default: true})
		case serviceCommandLine:
			items = append(items, winapp.MenuItem{Label: "Önce: sudo openscale service uninstall --role device", Disabled: true})
		default:
			items = append(items, winapp.MenuItem{ID: mbRestart, Label: "Servisi yeniden başlat..."})
		}
		// The way back to the internet when the service is gone but its
		// pf or nftables rules stayed (ADR-0023, ADR-0100); asks for the
		// password. Not while the command line service owns the rules.
		if s.service != serviceCommandLine {
			items = append(items, winapp.MenuItem{ID: mbReleaseKillSwitch, Label: "Kill switch'i kaldır (interneti aç)..."})
		}
		items = append(items,
			winapp.MenuItem{Separator: true},
			winapp.MenuItem{ID: mbAutostart, Label: "Oturum açılınca başlat", Checked: s.autostart},
			winapp.MenuItem{ID: mbAbout, Label: "OpenScale hakkında"},
			winapp.MenuItem{Separator: true},
			winapp.MenuItem{ID: mbQuit, Label: "Çık"},
		)
		return items
	}
	st := s.status
	dev := st.Device
	items := []winapp.MenuItem{{Label: trayTitle(st), Detail: connectionLabel(st), Disabled: true}}
	if dev != nil && dev.Name != "" {
		toggle := "Bağlan"
		if dev.Connected {
			toggle = "Bağlantıyı kes"
		}
		items = append(items, winapp.MenuItem{ID: mbToggle, Label: toggle})
		if dev.Connected {
			items = append(items, winapp.MenuItem{Label: "Bağlantıyı süreli kes", Children: []winapp.MenuItem{
				{ID: mbDisconnect5Min, Label: "5 dakika"},
				{ID: mbDisconnect1Hour, Label: "1 saat"},
				{ID: mbDisconnectMorning, Label: "Yarın sabaha kadar"},
			}})
		}
	}
	if alerts := menuBarProblems(st.Health); len(alerts) > 0 {
		items = append(items, winapp.MenuItem{Label: fmt.Sprintf("Sorunlar (%d)", len(alerts)), Children: alerts})
	}
	if dev != nil && dev.Name != "" {
		items = append(items,
			winapp.MenuItem{Separator: true},
			winapp.MenuItem{ID: mbThisDevice, Label: "Bu cihaz: " + dev.Name, Detail: dev.IPv4},
			winapp.MenuItem{Label: "Çıkış düğümü", Detail: exitSummary(dev), Children: menuBarExits(dev, exits)},
		)
	}
	items = append(items,
		winapp.MenuItem{Separator: true},
		winapp.MenuItem{ID: mbOpen, Label: "Paneli aç", Default: st.Mode == panel.ModeSetup || st.Mode == panel.ModeJoining},
		winapp.MenuItem{ID: mbAutostart, Label: "Oturum açılınca başlat", Checked: s.autostart},
		winapp.MenuItem{ID: mbAbout, Label: "OpenScale hakkında"},
		winapp.MenuItem{Separator: true},
	)
	if dev != nil && dev.Name != "" {
		items = append(items, winapp.MenuItem{ID: mbPanic, Label: "Panik: ağı kilitle..."})
	}
	return append(items, winapp.MenuItem{ID: mbQuit, Label: "Çık"})
}

func unreachableLabel(s menuBarService) string {
	switch s {
	case serviceMissing:
		return "Arka plan servisi kurulu değil"
	case serviceOutdated:
		return "Servis başka bir sürüm çalıştırıyor"
	case serviceCommandLine:
		return "Komut satırı cihaz servisi kurulu; tepsi uygulama servisini kullanır"
	}
	return "Servise ulaşılamıyor"
}

func exitSummary(dev *panel.DeviceStatus) string {
	switch {
	case dev.ExitNodeWanted == "":
		return "yok"
	case dev.ExitNode == dev.ExitNodeWanted:
		return dev.ExitNode
	default:
		return dev.ExitNodeWanted + " (bağlanıyor)"
	}
}

// menuBarExits lists "none", the last used exit node, every exit node
// with its country and the kill switch.
func menuBarExits(dev *panel.DeviceStatus, exits map[int]string) []winapp.MenuItem {
	var out []winapp.MenuItem
	if dev.ExitNodeWanted == "" && dev.LastExitNode != "" {
		out = append(out,
			winapp.MenuItem{ID: mbExitLast, Label: "Son kullanılan: " + dev.LastExitNode},
			winapp.MenuItem{Separator: true},
		)
		exits[mbExitLast] = dev.LastExitNode
	}
	out = append(out, winapp.MenuItem{ID: mbExitNone, Label: "Yok (doğrudan internet)", Checked: dev.ExitNodeWanted == ""})
	exits[mbExitNone] = ""
	for i, p := range dev.ExitNodes {
		id := mbExitBase + i
		label := p.Name
		if p.Name == dev.ExitNodeWanted && dev.ExitNode != p.Name {
			label += " (bağlanıyor)"
		}
		detail := p.IPv4
		if p.Country != "" {
			detail = p.Country + "  " + p.IPv4
		}
		out = append(out, winapp.MenuItem{ID: id, Label: label, Detail: detail, Checked: p.Name == dev.ExitNodeWanted, Disabled: !p.Online && p.Name != dev.ExitNodeWanted})
		exits[id] = p.Name
	}
	if len(dev.ExitNodes) == 0 {
		out = append(out, winapp.MenuItem{Label: "Ağda çıkış düğümü yok", Disabled: true})
	}
	if dev.KillSwitchSupported {
		out = append(out, winapp.MenuItem{Separator: true}, winapp.MenuItem{ID: mbKillSwitch, Label: "Kill switch", Checked: dev.KillSwitch})
	}
	return out
}

// maxMenuBarAlert is how much of an alert message fits in a menu item.
const maxMenuBarAlert = 90

// menuBarProblems lists the warning and danger alerts (F-193).
func menuBarProblems(alerts []panel.HealthAlert) []winapp.MenuItem {
	var out []winapp.MenuItem
	for _, a := range alerts {
		if a.Level == panel.LevelInfo {
			continue
		}
		msg := a.Message
		if r := []rune(msg); len(r) > maxMenuBarAlert {
			msg = string(r[:maxMenuBarAlert-3]) + "..."
		}
		out = append(out, winapp.MenuItem{Label: msg, Disabled: true})
	}
	return out
}

// menuBarTooltip is the status item's help text.
func menuBarTooltip(s menuBarState) string {
	if !s.reachable {
		return "OpenScale: " + unreachableLabel(s.service)
	}
	tip := trayTitle(s.status) + ": " + connectionLabel(s.status)
	if dev := s.status.Device; dev != nil && dev.Connected && dev.ExitNode != "" {
		tip += " (çıkış: " + dev.ExitNode + ")"
	}
	return tip
}
