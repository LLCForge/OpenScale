//go:build windows

package desktop

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/openscale/openscale/internal/osnet"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/service"
	"github.com/openscale/openscale/internal/winapp"
)

const (
	trayMutexName   = `Local\OpenScaleTray`
	statusEvery     = 5 * time.Second
	serviceWaitTime = 30 * time.Second
	// trayTakeoverWait is how long a new launch waits for the old icon.
	trayTakeoverWait = 5 * time.Second
)

var (
	kernel32                  = windows.NewLazySystemDLL("kernel32.dll")
	procGetConsoleProcessList = kernel32.NewProc("GetConsoleProcessList")
	procFreeConsole           = kernel32.NewProc("FreeConsole")
)

// LaunchedByDoubleClick reports whether this process owns its console
// alone, which is the case when Explorer started it rather than a terminal.
func LaunchedByDoubleClick() bool {
	var ids [2]uint32
	n, _, _ := procGetConsoleProcessList.Call(uintptr(unsafe.Pointer(&ids[0])), 2)
	return n == 1
}

func hideOwnConsole() {
	if LaunchedByDoubleClick() {
		_, _, _ = procFreeConsole.Call()
	}
}

// RunApp is the double-click entry: it elevates, installs and starts the
// service, then shows the tray icon and opens the panel.
func RunApp(ctx context.Context) error { return runAppMode(ctx, false) }

// runAppMode is RunApp; quiet (sign-in start, "autostart run") shows only
// the tray icon and does not open the panel window.
func runAppMode(ctx context.Context, quiet bool) error {
	if !winapp.IsElevated() {
		// A running tray can open the panel without asking for consent.
		if !quiet && askRunningTrayToOpen() {
			return nil
		}
		// At sign-in the scheduled task starts the tray elevated; this Run
		// entry start would only ask for consent a second time.
		if quiet && winapp.TrayTaskInstalled() {
			return nil
		}
		// The elevated copy does the work; this one only asks for consent.
		relaunch := []string{"app"}
		if quiet {
			relaunch = []string{"autostart", "run"}
		}
		if err := winapp.RelaunchElevated(relaunch); err != nil {
			showError(err.Error())
			return err
		}
		return nil
	}
	hideOwnConsole()
	err := runApp(ctx, quiet)
	if err != nil {
		showError(err.Error())
	}
	return err
}

func runApp(ctx context.Context, quiet bool) error {
	client := newTrayClient(winapp.DataDir())

	// Every launch installs (or updates) and starts the service first, so
	// opening a newer openscale.exe always upgrades the running service.
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if _, err := winapp.InstallService(exe); err != nil {
		return fmt.Errorf("OpenScale servisi kurulamadı: %w", err)
	}
	if err := winapp.StartService(); err != nil {
		return fmt.Errorf("OpenScale servisi başlatılamadı: %w", err)
	}
	if err := client.waitReady(ctx, serviceWaitTime); err != nil {
		return err
	}

	// One tray icon at a time: a newer launch asks the running icon to quit
	// and takes its place. An older icon that does not listen keeps running;
	// then this launch only opens the panel.
	mutex, err := takeTraySlot()
	if err != nil {
		if quiet {
			return nil
		}
		return openPanel(ctx, client)
	}
	defer windows.CloseHandle(mutex)
	quit, err := trayQuitEvent()
	if err != nil {
		return err
	}
	defer windows.CloseHandle(quit)

	if !quiet {
		if err := openPanel(ctx, client); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if openEv, err := createTrayOpenEvent(); err == nil {
		defer windows.CloseHandle(openEv)
		go watchTrayOpen(ctx, client, openEv)
	}
	go func() {
		// Wakes when a newer launch signals the event or the tray exits.
		if ev, _ := windows.WaitForSingleObject(quit, windows.INFINITE); ev == windows.WAIT_OBJECT_0 {
			cancel()
		}
	}()
	err = runTray(ctx, client)
	// Unblock the waiter when the tray ends on its own.
	_ = windows.SetEvent(quit)
	return err
}

const trayQuitEventName = `Local\OpenScaleTrayQuit`

func trayQuitEvent() (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(trayQuitEventName)
	if err != nil {
		return 0, err
	}
	// Auto-reset: one signal ends exactly one tray.
	return windows.CreateEvent(nil, 0, 0, name)
}

// takeTraySlot returns the tray mutex, asking a running tray to quit first.
func takeTraySlot() (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(trayMutexName)
	if err != nil {
		return 0, err
	}
	deadline := time.Now().Add(trayTakeoverWait)
	for {
		mutex, err := windows.CreateMutex(nil, false, name)
		if err == nil {
			return mutex, nil
		}
		if mutex != 0 {
			_ = windows.CloseHandle(mutex)
		}
		if !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return 0, err
		}
		if time.Now().After(deadline) {
			return 0, errors.New("başka bir OpenScale simgesi açık")
		}
		if ev, err := trayQuitEvent(); err == nil {
			_ = windows.SetEvent(ev)
			_ = windows.CloseHandle(ev)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func openPanel(ctx context.Context, client *trayClient) error {
	link, err := client.panelURL(ctx)
	if err != nil {
		return fmt.Errorf("panel açılamadı: %w", err)
	}
	return openPanelURL(link) // #520, p11_edge_windows.go
}

// Menu item ids. Device entries use peerIDBase + index.
const (
	idToggle = iota + 1
	idThisDevice
	idOpen
	idRestart
	idLogs
	idAbout
	idHide
	idQuit
	idExitNone
	idKillSwitch
	idDisconnect5Min
	idDisconnect1Hour
	idDisconnectMorning
	idExitLast
	idReleaseKillSwitch
	idHelp
	idPanic    // W2: publish the prepared lockdown document
	peerIDBase = 1000
	exitIDBase = 3000
)

// disconnectChoices maps the timed disconnect items to the service's
// choices (F-121).
var disconnectChoices = map[int]string{
	idDisconnect5Min:    panel.Disconnect5Min,
	idDisconnect1Hour:   panel.Disconnect1Hour,
	idDisconnectMorning: panel.DisconnectMorning,
}

// maxTrayAlert is how much of an alert message fits in a menu item.
const maxTrayAlert = 90

// trayState is what the menu was last built from.
type trayState struct {
	mu     sync.Mutex
	status panel.AppStatus
	ok     bool
	copies map[int]string
	exits  map[int]string
}

func runTray(ctx context.Context, client *trayClient) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	tray := winapp.NewTray("OpenScale")
	var icons map[trayIconState][]byte
	if len(trayIconPNG) > 0 {
		icons = makeTrayIcons(trayIconPNG)
		_ = tray.SetIconPNG(trayIconPNG)
	}
	state := &trayState{copies: map[int]string{}, exits: map[int]string{}}
	shownIcon := trayIconState(-1)
	notifier := &alertNotifier{}
	refresh := func() {
		st, err := client.status(ctx)
		state.mu.Lock()
		state.status, state.ok = st, err == nil
		items, tip := buildTrayMenu(st, err == nil, state.copies, state.exits)
		items = withTokenModeItems(items) // ADR-0223, ym_tokenmode_windows.go
		items = withF3Items(items)        // #802: sol tık tercihi (f3_tray_windows.go)
		icon := iconStateFor(st, err == nil)
		changed := icon != shownIcon
		shownIcon = icon
		notes := notifier.update(st, err == nil)
		state.mu.Unlock()
		for _, msg := range notes {
			tray.Notify("OpenScale", msg)
		}
		tray.SetItems(items)
		tray.SetTooltip(tip)
		if changed && icons != nil {
			_ = tray.SetIconPNG(icons[icon])
		}
	}
	open := func() {
		if err := openPanel(ctx, client); err != nil {
			tray.Notify("OpenScale", err.Error())
		}
	}
	tray.OnLeftClick(f3LeftClick(ctx, client, open))                                 // #802: durum penceresi veya panel (f3_tray_windows.go)
	tray.OnSessionLock(func(locked bool) { reportSessionLock(ctx, client, locked) }) // #501
	tray.OnClick(func(id int) {
		if f3MenuClick(id) { // #802
			refresh()
			return
		}
		if tokenModeClick(ctx, tray, id) { // ADR-0223
			refresh()
			return
		}
		state.mu.Lock()
		st, ok := state.status, state.ok
		ip, isCopy := state.copies[id]
		exitName, isExit := state.exits[id]
		state.mu.Unlock()
		switch {
		case isExit && strings.HasPrefix(exitName, profileChoicePrefix):
			name, _ := profileChoice(exitName)
			if !confirm("Ağ profili " + name + " olarak değiştirilsin mi?\n\nTünel yeniden başlar; bağlantılar kısa süre kesilir.") {
				return
			}
			if err := client.setProfile(ctx, name); err != nil {
				tray.Notify("OpenScale", err.Error())
			}
			refresh()
		case isExit:
			if err := client.setExit(ctx, exitName); err != nil {
				tray.Notify("OpenScale", err.Error())
			}
			refresh()
		case isCopy:
			if err := winapp.SetClipboardText(ip); err != nil {
				tray.Notify("OpenScale", "Panoya kopyalanamadı.")
			}
		case id == idKillSwitch && ok && st.Device != nil:
			on := !st.Device.KillSwitch
			if !on && st.Device.ExitNodeWanted != "" &&
				!confirm("Kill switch kapatılsın mı?\n\nÇıkış düğümüne ulaşılamazsa veya servis durursa internet trafiği doğrudan bu bilgisayarın bağlantısından çıkabilir.") {
				return
			}
			if err := client.setExitOptions(ctx, on, st.Device.ExitAllowLAN); err != nil {
				tray.Notify("OpenScale", err.Error())
			}
			refresh()
		case id == idToggle && ok && st.Device != nil:
			if _, err := client.setConnected(ctx, !st.Device.Connected); err != nil {
				tray.Notify("OpenScale", err.Error())
			}
			refresh()
		case disconnectChoices[id] != "" && ok && st.Device != nil:
			if err := client.disconnectFor(ctx, disconnectChoices[id]); err != nil {
				tray.Notify("OpenScale", err.Error())
			}
			refresh()
		case id == idReleaseKillSwitch:
			if confirm("Kill switch filtreleri kaldırılsın mı?\n\nServise ulaşılamıyor. Filtreler kalkınca internet trafiği doğrudan bu bilgisayarın bağlantısından çıkar; servis yeniden çalışıp bir çıkış düğümü etkinleşince filtreler tekrar kurulur.") {
				if err := osnet.RemoveKillSwitch(); err != nil {
					tray.Notify("OpenScale", "Kill switch kaldırılamadı: "+err.Error())
				} else {
					tray.Notify("OpenScale", "Kill switch kaldırıldı; internet erişimi açık.")
				}
			}
		case id == idHelp && ok && st.Device != nil:
			if confirm(helpPrompt) {
				go requestHelp(ctx, tray)
			}
		case id == idPanic:
			trayPanic(ctx, client, tray) // w2_desktop_windows.go
		case id == idOpen:
			open()
		case id == idRestart:
			if err := restartService(); err != nil {
				tray.Notify("OpenScale", err.Error())
			}
		case id == idLogs:
			openFolder(filepath.Join(winapp.DataDir(), logDirName))
		case id == idAbout:
			showInfo("OpenScale " + Version + "\n\nKişisel, bağımsız ve gizlilik öncelikli mesh VPN.\nHiçbir şirkete veya hesaba bağlı değildir.")
		case id == idHide:
			cancel()
		case id == idQuit:
			if confirm(quitPrompt(st, ok)) {
				if err := fullExit(ctx, client); err != nil {
					tray.Notify("OpenScale", err.Error())
					return
				}
				cancel()
			}
		}
	})
	refresh()
	startTokenMode(ctx, tray, client.dataDir, refresh) // ADR-0223: YubiKey administrator mode
	startNetPlaces(ctx, client, tray)                  // ADR-0226: ağ konumları (netplaces_windows.go)
	startF3(ctx, client, tray)                         // #803, #813: Gönder menüsü, dosya teklifleri (f3_tray_windows.go)
	// Event stream (F-182) and its notifications (F-158); the status poll
	// below thins out while the stream works (events.go).
	gate := &refreshGate{}
	go followEvents(ctx, client, gate, func(notes []string) {
		for _, msg := range notes {
			tray.Notify("OpenScale", msg)
		}
		refresh()
	})
	go func() {
		ticker := time.NewTicker(statusEvery)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if gate.skip() {
					continue
				}
				refresh()
			}
		}
	}()
	return tray.Run(ctx)
}

// buildTrayMenu lays the menu out like other mesh VPN clients: connection
// switch, problems, this device, the other devices, exit nodes, then the
// app items. copies is refilled with the ids whose click copies an IP
// address, exitChoice with the ids that choose an exit node.
func buildTrayMenu(st panel.AppStatus, reachable bool, copies, exitChoice map[int]string) ([]winapp.MenuItem, string) {
	clear(copies)
	clear(exitChoice)
	if !reachable {
		items := []winapp.MenuItem{
			{Label: "OpenScale", Detail: "Servise ulaşılamıyor", Disabled: true},
			{Separator: true},
			{ID: idRestart, Label: "Servisi yeniden başlat"},
		}
		if osnet.KillSwitchSupported() {
			// The way back to the internet when the service is gone but
			// its filters stayed (ADR-0023); the tray runs elevated.
			items = append(items, winapp.MenuItem{ID: idReleaseKillSwitch, Label: "Kill switch'i kaldır (interneti aç)"})
		}
		items = append(items, winapp.MenuItem{ID: idHide, Label: "Simgeyi gizle"})
		return items, "OpenScale: servise ulaşılamıyor"
	}
	label := connectionLabel(st)
	title := trayTitle(st)
	items := []winapp.MenuItem{}
	dev := st.Device
	if dev != nil && dev.Name != "" {
		items = append(items, winapp.MenuItem{ID: idToggle, Label: title, Detail: label, Checked: dev.Connected, Default: true})
		if dev.Connected {
			items = append(items, winapp.MenuItem{Label: "Bağlantıyı süreli kes", Children: []winapp.MenuItem{
				{ID: idDisconnect5Min, Label: "5 dakika"},
				{ID: idDisconnect1Hour, Label: "1 saat"},
				{ID: idDisconnectMorning, Label: "Yarın sabaha kadar"},
			}})
		}
	} else {
		items = append(items, winapp.MenuItem{Label: title, Detail: label, Disabled: true})
	}
	if alerts := problemItems(st.Health); len(alerts) > 0 {
		items = append(items, winapp.MenuItem{Label: fmt.Sprintf("Sorunlar (%d)", countProblems(st.Health)), Children: alerts})
	}
	if dev != nil && dev.Name != "" {
		items = append(items,
			winapp.MenuItem{Separator: true},
			winapp.MenuItem{ID: idThisDevice, Label: "Bu cihaz: " + dev.Name, Detail: dev.IPv4},
			// Remote support without unattended access (#424, ADR-0146).
			winapp.MenuItem{ID: idHelp, Label: "Yardım iste...", Disabled: !dev.Connected},
		)
		copies[idThisDevice] = dev.IPv4
		items = append(items, winapp.MenuItem{Label: "Ağdaki cihazlar", Children: peerItems(dev.Peers, copies)})
		exits := exitItems(dev, exitChoice)
		if a, ok := exitAutoItem(dev); ok {
			exits = append([]winapp.MenuItem{a, {Separator: true}}, exits...)
		}
		items = append(items, winapp.MenuItem{Label: "Çıkış düğümleri", Children: exits})
		if profiles := profileItems(dev, exitChoice); len(profiles) > 0 {
			items = append(items, winapp.MenuItem{Label: "Ağ profili", Children: profiles})
		}
	}
	items = append(items,
		winapp.MenuItem{Separator: true},
		winapp.MenuItem{ID: idOpen, Label: "Paneli aç"},
		winapp.MenuItem{Label: "Tercihler", Children: []winapp.MenuItem{
			{ID: idRestart, Label: "Servisi yeniden başlat"},
			{ID: idLogs, Label: "Günlük klasörünü aç"},
		}},
		winapp.MenuItem{ID: idAbout, Label: "Hakkında..."},
		winapp.MenuItem{Separator: true},
		winapp.MenuItem{ID: idPanic, Label: "Panik: ağı kilitle..."},
		winapp.MenuItem{ID: idHide, Label: "Simgeyi gizle"},
		winapp.MenuItem{ID: idQuit, Label: "OpenScale'i tamamen kapat"},
	)
	tip := title + ": " + label
	if dev != nil && dev.Name != "" && dev.Connected {
		tip += " - " + dev.Name + " (" + dev.IPv4 + ")"
		if dev.ExitNode != "" {
			tip += ", çıkış: " + dev.ExitNode
		}
	}
	if n := countProblems(st.Health); n > 0 {
		tip += fmt.Sprintf(" - %d sorun", n)
	}
	return items, tip
}

// peerItems lists the reachable devices; a click copies the IP address.
// Pinned devices come first (the service sorts them), set apart by a line.
func peerItems(peers []panel.PeerInfo, copies map[int]string) []winapp.MenuItem {
	out := []winapp.MenuItem{}
	for i, p := range peers {
		if i > 0 && peers[i-1].Pinned && !p.Pinned {
			out = append(out, winapp.MenuItem{Separator: true})
		}
		id := peerIDBase + i
		name := p.Name
		switch {
		case !p.Online:
			name += " (çevrimdışı)"
		case p.Relayed:
			name += " (sunucu üzerinden)"
		}
		out = append(out, winapp.MenuItem{ID: id, Label: name, Detail: peerDetail(p), Checked: p.Online})
		copies[id] = p.IPv4
	}
	if len(out) == 0 {
		out = append(out, winapp.MenuItem{Label: "Ulaşabildiğin cihaz yok", Disabled: true})
	}
	return out
}

// exitItems lists the exit nodes with their country code, the last used
// one for a one-click return, and the kill switch (F-038).
func exitItems(dev *panel.DeviceStatus, exitChoice map[int]string) []winapp.MenuItem {
	exits := []winapp.MenuItem{}
	if dev.ExitNodeWanted == "" && dev.LastExitNode != "" {
		exits = append(exits,
			winapp.MenuItem{ID: idExitLast, Label: "Son kullanılan: " + dev.LastExitNode, Detail: countryOf(dev.ExitNodes, dev.LastExitNode)},
			winapp.MenuItem{Separator: true},
		)
		exitChoice[idExitLast] = dev.LastExitNode
	}
	exits = append(exits, winapp.MenuItem{ID: idExitNone, Label: "Yok (doğrudan internet)", Checked: dev.ExitNodeWanted == ""})
	exitChoice[idExitNone] = ""
	for i, p := range dev.ExitNodes {
		id := exitIDBase + i
		label := p.Name
		if p.Name == dev.ExitNodeWanted && dev.ExitNode != p.Name {
			label += " (bağlanıyor)"
		}
		detail := p.IPv4
		if p.Country != "" {
			detail = p.Country + "  " + p.IPv4
		}
		exits = append(exits, winapp.MenuItem{ID: id, Label: label, Detail: detail, Checked: p.Name == dev.ExitNodeWanted})
		exitChoice[id] = p.Name
	}
	if dev.KillSwitchSupported {
		exits = append(exits,
			winapp.MenuItem{Separator: true},
			winapp.MenuItem{ID: idKillSwitch, Label: "Kill switch", Checked: dev.KillSwitch},
		)
	}
	return exits
}

func countryOf(peers []panel.PeerInfo, name string) string {
	for _, p := range peers {
		if p.Name == name {
			return p.Country
		}
	}
	return ""
}

// problemItems summarizes the warning and danger alerts (F-193); the
// panel shows them in full.
func problemItems(alerts []panel.HealthAlert) []winapp.MenuItem {
	var out []winapp.MenuItem
	for _, a := range alerts {
		if a.Level == panel.LevelInfo {
			continue
		}
		msg := a.Message
		if r := []rune(msg); len(r) > maxTrayAlert {
			msg = string(r[:maxTrayAlert-3]) + "..."
		}
		out = append(out, winapp.MenuItem{Label: msg, Disabled: true})
	}
	if len(out) > 0 {
		out = append(out, winapp.MenuItem{Separator: true}, winapp.MenuItem{ID: idOpen, Label: "Ayrıntılar için paneli aç"})
	}
	return out
}

func countProblems(alerts []panel.HealthAlert) int {
	n := 0
	for _, a := range alerts {
		if a.Level != panel.LevelInfo {
			n++
		}
	}
	return n
}

// quitPrompt says what a full exit does, including the kill switch.
func quitPrompt(st panel.AppStatus, reachable bool) string {
	msg := "OpenScale tamamen kapatılsın mı?\n\nVPN bağlantısı kesilir ve servis durur. Programı yeniden açtığında veya bilgisayar yeniden başladığında tekrar başlar."
	if !reachable || st.Device == nil || st.Device.KillSwitchActive || st.Device.ExitNodeWanted != "" {
		msg += "\n\nKill switch filtreleri de kaldırılır: internet trafiği doğrudan bu bilgisayarın bağlantısından çıkar. (\"Servisi yeniden başlat\" ise filtreleri yerinde bırakır.)"
	}
	return msg
}

// fullExit stops the service for good and removes the kill switch: the
// service is told first, so its own stop path releases the filters, and
// the tray (elevated) removes whatever is left afterwards (ADR-0023).
func fullExit(ctx context.Context, client *trayClient) error {
	// A service that does not answer is stopped anyway; the removal below
	// still takes the filters away.
	_ = client.releaseOnStop(ctx)
	if err := winapp.StopService(); err != nil {
		return err
	}
	if !osnet.KillSwitchSupported() {
		return nil
	}
	if err := osnet.RemoveKillSwitch(); err != nil {
		return fmt.Errorf("servis durdu ama kill switch kaldırılamadı; yönetici olarak \"openscale killswitch off\" çalıştırın: %w", err)
	}
	return nil
}

func openFolder(dir string) {
	verb, _ := windows.UTF16PtrFromString("open")
	path, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return
	}
	_ = windows.ShellExecute(0, verb, path, nil, nil, windows.SW_SHOWNORMAL)
}

func showInfo(msg string) {
	text, err := windows.UTF16PtrFromString(msg)
	if err != nil {
		return
	}
	caption, _ := windows.UTF16PtrFromString("OpenScale")
	_, _ = windows.MessageBox(0, text, caption, windows.MB_OK|windows.MB_ICONINFORMATION)
}

func confirm(msg string) bool {
	text, err := windows.UTF16PtrFromString(msg)
	if err != nil {
		return false
	}
	caption, _ := windows.UTF16PtrFromString("OpenScale")
	r, _ := windows.MessageBox(0, text, caption, windows.MB_YESNO|windows.MB_ICONQUESTION|windows.MB_DEFBUTTON2)
	return r == idYes
}

// idYes is IDYES from MessageBox.
const idYes = 6

func restartService() error {
	if err := winapp.StopService(); err != nil {
		return err
	}
	return winapp.StartService()
}

// RunService is the entry point the Service Control Manager starts.
func RunService() error {
	dataDir := winapp.DataDir()
	logger, closeLog, err := serviceLogger(dataDir)
	if err != nil {
		return err
	}
	defer closeLog()
	// Temporary files left by a crash or power loss go first (#46).
	if n, err := securefile.RemoveStaleTemps(dataDir, time.Now()); err != nil {
		logger.Warn("stale temporary files", "error", err.Error())
	} else if n > 0 {
		logger.Info("stale temporary files removed", "count", n)
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	var (
		fwMu   sync.Mutex
		fwDone netip.Prefix
	)
	r, err := service.New(service.Config{
		DataDir: dataDir,
		Logger:  logger,
		// The tray and the CLI run elevated; the token alone is not
		// enough (ADR-0050). They must also run this OpenScale program
		// (#645, w2_desktop_windows.go).
		PeerCheck: localAPICheck(logger),
		Hooks: service.Hooks{
			ReapplyRemoteAccess: true,
			ConfigureDNS:        osnet.ConfigureDNS,
			RemoveDNS:           osnet.RemoveDNS,
			ConfigureNetworkDNS: osnet.ConfigureNetworkDNS,
			VerifyNetworkDNS:    osnet.VerifyNetworkDNS,
			DNSStatus:           osnet.SystemDNSStatus,
			ExitRouter:          osnet.NewExitRouter(),
			InstallKillSwitch: func(c osnet.KillSwitchConfig) error {
				// Only the installed program may talk past the filters.
				c.AppPath = exe
				return osnet.InstallKillSwitch(c)
			},
			RemoveKillSwitch: osnet.RemoveKillSwitch,
			DNSEnforce:       osnet.NewDNSEnforcer(), // #717: yalnızca sahip açınca ve çıkış düğümü varken uygulanır
			// DNS and routes a crash left behind (ADR-0051).
			Recover: service.SystemUndo,
			// Automatic updates from the coordinator's mirror (ADR-0225).
			AutoUpdate: true,
			AllowTraffic: func(overlay netip.Prefix) error {
				fwMu.Lock()
				defer fwMu.Unlock()
				if fwDone == overlay {
					return nil
				}
				if err := winapp.EnsureFirewallRules(exe, overlay.String()); err != nil {
					return err
				}
				fwDone = overlay
				return nil
			},
		},
	})
	if err != nil {
		return err
	}
	err = winapp.RunService(r.Run)
	if err != nil {
		logger.Error("service stopped", "error", err.Error())
	}
	return err
}

// Uninstall stops and removes the service, the persistent kill switch and
// the firewall rules. The data directory (keys and network) is kept.
func Uninstall() error {
	if !winapp.IsElevated() {
		return errors.New("kaldırmak için yönetici olarak çalıştırın")
	}
	if err := winapp.UninstallService(); err != nil {
		return err
	}
	// The kill switch outlives the service by design; without the service
	// nothing would ever remove it (ADR-0023).
	if err := osnet.RemoveKillSwitch(); err != nil {
		return err
	}
	return winapp.RemoveFirewallRules()
}

func showError(msg string) {
	text, err := windows.UTF16PtrFromString(msg)
	if err != nil {
		return
	}
	caption, _ := windows.UTF16PtrFromString("OpenScale")
	_, _ = windows.MessageBox(0, text, caption, windows.MB_OK|windows.MB_ICONERROR)
}
