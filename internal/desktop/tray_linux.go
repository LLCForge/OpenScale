//go:build linux

package desktop

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/openscale/openscale/internal/dbuswire"
	"github.com/openscale/openscale/internal/webview"
	"github.com/openscale/openscale/internal/winapp"
)

// The Linux tray (ADR-0039, ADR-0234, #311): a StatusNotifierItem with a
// com.canonical.dbusmenu menu on the session bus, spoken with
// internal/dbuswire. KDE Plasma, XFCE, Cinnamon, MATE, LXQt and Budgie
// show it natively, GNOME with the AppIndicator extension. The menu is the
// shared one of the macOS menu bar (menubar_menu.go); dialogs are desktop
// notifications, with buttons where the notification server has them.

const (
	sniPath     = dbuswire.ObjectPath("/StatusNotifierItem")
	menuPath    = dbuswire.ObjectPath("/MenuBar")
	sniIface    = "org.kde.StatusNotifierItem"
	menuIface   = "com.canonical.dbusmenu"
	watcherName = "org.kde.StatusNotifierWatcher"
	watcherPath = dbuswire.ObjectPath("/StatusNotifierWatcher")
	// linuxStatusEvery is the status poll; the event stream thins it out.
	linuxStatusEvery = 5 * time.Second
	// busCallTimeout bounds one call the tray makes on the bus.
	busCallTimeout = 10 * time.Second
	// trayEmergencyHint tells where the panic lockdown is confirmed.
	trayEmergencyHint = "Panik kilitlemesi panelde onaylanır: Ayarlar > Acil durum. Panel açılıyor."
	// trayNoWatcher explains a missing tray area once.
	trayNoWatcher = "Tepsi simgesi gösterilemiyor: bu masaüstünde StatusNotifierItem alanı yok. GNOME'da \"AppIndicator and KStatusNotifierItem Support\" uzantısını açın. OpenScale bildirimleri göstermeye devam eder; panel için: openscale app"
)

type linuxTray struct {
	app    *linuxApp
	ctx    context.Context
	cancel context.CancelFunc
	bus    *dbuswire.Conn
	menu   *dbusMenu
	notes  *desktopNotifier
	icons  map[trayIconState][]dbuswire.Struct
	name   string

	mu            sync.Mutex
	state         menuBarState
	exits         map[int]string
	shownIcon     trayIconState
	tooltip       string
	title         string
	toldNoWatcher bool

	alerts     alertNotifier
	windowBusy atomic.Bool
	setupBusy  atomic.Bool
}

func runLinuxTray(parent context.Context, quiet bool) error {
	app, err := newLinuxApp()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	t := &linuxTray{app: app, ctx: ctx, cancel: cancel, menu: newDBusMenu(), exits: map[int]string{}, shownIcon: -1}
	release, err := claimInstance(ctx, app.settingDir, quiet, func() { go t.openPanel() })
	if errors.Is(err, errOtherInstance) {
		return nil
	}
	if err != nil {
		return err
	}
	defer release()
	_ = app.syncAutostart()
	bus, err := dbuswire.DialSession(ctx, dbuswire.Options{})
	if err != nil {
		return t.withoutBus(quiet, err)
	}
	defer bus.Close()
	t.bus = bus
	t.notes = newDesktopNotifier(bus)
	t.icons = map[trayIconState][]dbuswire.Struct{}
	for state, png := range makeTrayIcons(trayIconPNG) {
		if pm, err := sniPixmaps(png, sniIconSizes); err == nil {
			t.icons[state] = pm
		}
	}
	if err := t.export(); err != nil {
		return err
	}
	t.refresh()
	t.register()
	go t.watchWatcher()
	if !quiet {
		go t.firstStart()
	}
	gate := &refreshGate{}
	go followEvents(ctx, app.client, gate, func(notes []string) {
		for _, msg := range notes {
			t.notes.show("OpenScale", msg)
		}
		t.refresh()
	})
	ticker := time.NewTicker(linuxStatusEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-bus.Done():
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("oturum D-Bus bağlantısı kapandı: %v", bus.Err())
		case <-ticker.C:
			if gate.skip() {
				continue
			}
			t.refresh()
		}
	}
}

// withoutBus runs without a session bus (no desktop session, or a
// terminal over SSH): a manual start still sets up the service and opens
// the panel in the browser.
func (t *linuxTray) withoutBus(quiet bool, busErr error) error {
	fmt.Fprintln(os.Stderr, "OpenScale tepsisi açılamadı: oturum D-Bus'ı yok ("+busErr.Error()+").")
	if quiet {
		return nil
	}
	switch t.app.serviceState() {
	case serviceMissing, serviceOutdated:
		if err := t.app.installService(t.ctx); err != nil {
			if errors.Is(err, errCancelled) {
				return nil
			}
			return fmt.Errorf("OpenScale servisi kurulamadı: %w", err)
		}
	case serviceCommandLine:
		return errors.New(unreachableLabel(serviceCommandLine) + "; önce: sudo openscale service uninstall --role device")
	default:
		if err := t.app.client.waitReady(t.ctx, linuxServiceWait); err != nil {
			return err
		}
	}
	return t.app.openPanelBrowser(t.ctx)
}

func (t *linuxTray) callCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(t.ctx, busCallTimeout)
}

// export publishes the item and its menu and takes the item's bus name.
func (t *linuxTray) export() error {
	if err := t.bus.Export(sniPath, t.sniInterface()); err != nil {
		return err
	}
	if err := t.bus.Export(menuPath, t.menuInterface()); err != nil {
		return err
	}
	t.name = fmt.Sprintf("org.kde.StatusNotifierItem-%d-1", os.Getpid())
	ctx, cancel := t.callCtx()
	defer cancel()
	if _, err := t.bus.RequestName(ctx, t.name, dbuswire.NameFlagDoNotQueue); err != nil {
		// The unique name works too; hosts accept either.
		t.name = t.bus.UniqueName()
	}
	return nil
}

// register announces the item to the watcher; without one the tray only
// sends notifications and says why once.
func (t *linuxTray) register() {
	ctx, cancel := t.callCtx()
	defer cancel()
	_, err := t.bus.Call(ctx, watcherName, watcherPath, watcherName, "RegisterStatusNotifierItem", "s", t.name)
	if err == nil {
		return
	}
	t.mu.Lock()
	told := t.toldNoWatcher
	t.toldNoWatcher = true
	t.mu.Unlock()
	if !told {
		fmt.Fprintln(os.Stderr, trayNoWatcher)
		t.notes.show("OpenScale", trayNoWatcher)
	}
}

// watchWatcher registers again whenever a watcher appears (the panel
// restarted, the GNOME extension was turned on).
func (t *linuxTray) watchWatcher() {
	ctx, cancel := t.callCtx()
	sub, err := t.bus.Subscribe(ctx, dbuswire.Match{Sender: dbuswire.BusName, Path: dbuswire.BusPath, Interface: dbuswire.BusInterface, Member: "NameOwnerChanged", Arg0: watcherName}, 4)
	cancel()
	if err != nil {
		return
	}
	defer sub.Close()
	for {
		select {
		case <-t.ctx.Done():
			return
		case m, ok := <-sub.C:
			if !ok {
				return
			}
			if len(m.Body) == 3 {
				if owner, _ := m.Body[2].(string); owner != "" {
					t.register()
				}
			}
		}
	}
}

func noArgs(*dbuswire.MethodCall) ([]any, error) { return nil, nil }

func (t *linuxTray) sniInterface() *dbuswire.Interface {
	str := func(s string) func() any { return func() any { return s } }
	return &dbuswire.Interface{
		Name: sniIface,
		Methods: []dbuswire.Method{
			{Name: "ContextMenu", In: "ii", InNames: []string{"x", "y"}, Handler: noArgs},
			{Name: "Activate", In: "ii", InNames: []string{"x", "y"}, Handler: func(*dbuswire.MethodCall) ([]any, error) {
				go t.openPanel()
				return nil, nil
			}},
			{Name: "SecondaryActivate", In: "ii", InNames: []string{"x", "y"}, Handler: noArgs},
			{Name: "Scroll", In: "is", InNames: []string{"delta", "orientation"}, Handler: noArgs},
		},
		Properties: []dbuswire.Property{
			{Name: "Category", Sig: "s", Get: str("Communications")},
			{Name: "Id", Sig: "s", Get: str("openscale")},
			{Name: "Title", Sig: "s", Get: func() any { t.mu.Lock(); defer t.mu.Unlock(); return t.title }},
			{Name: "Status", Sig: "s", Get: func() any { t.mu.Lock(); defer t.mu.Unlock(); return sniStatus(t.shownIcon) }},
			{Name: "WindowId", Sig: "i", Get: func() any { return int32(0) }},
			{Name: "IconName", Sig: "s", Get: str("")},
			{Name: "IconPixmap", Sig: "a(iiay)", Get: func() any { return t.pixmaps() }},
			{Name: "OverlayIconName", Sig: "s", Get: str("")},
			{Name: "OverlayIconPixmap", Sig: "a(iiay)", Get: func() any { return []any{} }},
			{Name: "AttentionIconName", Sig: "s", Get: str("")},
			{Name: "AttentionIconPixmap", Sig: "a(iiay)", Get: func() any { return t.pixmaps() }},
			{Name: "AttentionMovieName", Sig: "s", Get: str("")},
			{Name: "ToolTip", Sig: "(sa(iiay)ss)", Get: func() any {
				t.mu.Lock()
				defer t.mu.Unlock()
				title, text := trayLabelText(t.tooltip)
				return sniToolTip(title, text)
			}},
			{Name: "ItemIsMenu", Sig: "b", Get: func() any { return false }},
			{Name: "Menu", Sig: "o", Get: func() any { return menuPath }},
			{Name: "IconThemePath", Sig: "s", Get: str("")},
		},
		Signals: []dbuswire.SignalDef{
			{Name: "NewTitle"}, {Name: "NewIcon"}, {Name: "NewAttentionIcon"}, {Name: "NewOverlayIcon"},
			{Name: "NewToolTip"}, {Name: "NewStatus", Sig: "s", Names: []string{"status"}},
		},
	}
}

func (t *linuxTray) pixmaps() []dbuswire.Struct {
	t.mu.Lock()
	defer t.mu.Unlock()
	if pm, ok := t.icons[t.shownIcon]; ok {
		return pm
	}
	if pm, ok := t.icons[iconOff]; ok {
		return pm
	}
	return []dbuswire.Struct{}
}

// int32s and strings read arrays of a call's arguments.
func int32s(v any) []int32 {
	in, _ := v.([]any)
	out := make([]int32, 0, len(in))
	for _, x := range in {
		if i, ok := x.(int32); ok {
			out = append(out, i)
		}
	}
	return out
}

func stringsOf(v any) []string {
	in, _ := v.([]any)
	out := make([]string, 0, len(in))
	for _, x := range in {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

var errDBusMenuItem = &dbuswire.Error{Name: dbuswire.ErrNameInvalidArgs, Message: "unknown item"}

func (t *linuxTray) menuInterface() *dbuswire.Interface {
	return &dbuswire.Interface{
		Name: menuIface,
		Methods: []dbuswire.Method{
			{Name: "GetLayout", In: "iias", Out: "u" + layoutSig, InNames: []string{"parentId", "recursionDepth", "propertyNames"}, OutNames: []string{"revision", "layout"},
				Handler: func(c *dbuswire.MethodCall) ([]any, error) {
					rev, layout, err := t.menu.layout(c.Body[0].(int32), c.Body[1].(int32), stringsOf(c.Body[2]))
					if err != nil {
						return nil, errDBusMenuItem
					}
					return []any{rev, layout}, nil
				}},
			{Name: "GetGroupProperties", In: "aias", Out: "a(ia{sv})", InNames: []string{"ids", "propertyNames"}, OutNames: []string{"properties"},
				Handler: func(c *dbuswire.MethodCall) ([]any, error) {
					return []any{t.menu.groupProperties(int32s(c.Body[0]), stringsOf(c.Body[1]))}, nil
				}},
			{Name: "GetProperty", In: "is", Out: "v", InNames: []string{"id", "name"}, OutNames: []string{"value"},
				Handler: func(c *dbuswire.MethodCall) ([]any, error) {
					v, err := t.menu.property(c.Body[0].(int32), c.Body[1].(string))
					if err != nil {
						return nil, errDBusMenuItem
					}
					return []any{v}, nil
				}},
			{Name: "Event", In: "isvu", InNames: []string{"id", "eventId", "data", "timestamp"},
				Handler: func(c *dbuswire.MethodCall) ([]any, error) {
					id := c.Body[0].(int32)
					if !t.menu.knows(id) {
						return nil, errDBusMenuItem
					}
					t.menuEvent(id, c.Body[1].(string))
					return nil, nil
				}},
			{Name: "EventGroup", In: "a(isvu)", Out: "ai", InNames: []string{"events"}, OutNames: []string{"idErrors"},
				Handler: func(c *dbuswire.MethodCall) ([]any, error) {
					events, _ := c.Body[0].([]any)
					bad := []int32{}
					for i, e := range events {
						if i >= maxMenuIDs {
							break
						}
						st, _ := e.(dbuswire.Struct)
						if len(st) != 4 {
							continue
						}
						id, _ := st[0].(int32)
						ev, _ := st[1].(string)
						if !t.menu.knows(id) {
							bad = append(bad, id)
							continue
						}
						t.menuEvent(id, ev)
					}
					return []any{bad}, nil
				}},
			{Name: "AboutToShow", In: "i", Out: "b", InNames: []string{"id"}, OutNames: []string{"needUpdate"},
				Handler: func(*dbuswire.MethodCall) ([]any, error) {
					// The menu is current: every state change already sent
					// LayoutUpdated. Refreshing here would block the host.
					go t.refresh()
					return []any{false}, nil
				}},
			{Name: "AboutToShowGroup", In: "ai", Out: "aiai", InNames: []string{"ids"}, OutNames: []string{"updatesNeeded", "idErrors"},
				Handler: func(*dbuswire.MethodCall) ([]any, error) {
					go t.refresh()
					return []any{[]int32{}, []int32{}}, nil
				}},
		},
		Properties: []dbuswire.Property{
			{Name: "Version", Sig: "u", Get: func() any { return dbusMenuVersion }},
			{Name: "TextDirection", Sig: "s", Get: func() any { return "ltr" }},
			{Name: "Status", Sig: "s", Get: func() any { return "normal" }},
			{Name: "IconThemePath", Sig: "as", Get: func() any { return []string{} }},
		},
		Signals: []dbuswire.SignalDef{
			{Name: "ItemsPropertiesUpdated", Sig: "a(ia{sv})a(ias)", Names: []string{"updatedProps", "removedProps"}},
			{Name: "LayoutUpdated", Sig: "ui", Names: []string{"revision", "parent"}},
			{Name: "ItemActivationRequested", Sig: "iu", Names: []string{"id", "timestamp"}},
		},
	}
}

// menuEvent runs a click. Handlers return at once: the action runs on its
// own goroutine so the host never waits for the service or a dialog.
func (t *linuxTray) menuEvent(id int32, event string) {
	if event != "clicked" {
		return
	}
	if action, ok := t.menu.action(id); ok {
		go t.click(action)
	}
}

// refresh reads the status and updates the menu, tooltip and icon.
func (t *linuxTray) refresh() {
	st, err := t.app.client.status(t.ctx)
	ok := err == nil
	svc := serviceUnknown
	if !ok {
		svc = t.app.serviceState()
	}
	t.mu.Lock()
	t.state = menuBarState{status: st, reachable: ok, service: svc, autostart: t.app.autostartOn()}
	items := menuBarItems(t.state, t.exits)
	tip := menuBarTooltip(t.state)
	title := "OpenScale"
	if ok {
		title = trayTitle(st)
	}
	icon := iconStateFor(st, ok)
	iconChanged := icon != t.shownIcon
	tipChanged := tip != t.tooltip
	titleChanged := title != t.title
	t.shownIcon, t.tooltip, t.title = icon, tip, title
	alerts := t.alerts.update(st, ok)
	t.mu.Unlock()
	if rev, changed := t.menu.set(items); changed {
		_ = t.bus.Emit(menuPath, menuIface, "LayoutUpdated", "ui", rev, int32(0))
	}
	if titleChanged {
		_ = t.bus.Emit(sniPath, sniIface, "NewTitle", "")
	}
	if tipChanged {
		_ = t.bus.Emit(sniPath, sniIface, "NewToolTip", "")
	}
	if iconChanged {
		_ = t.bus.Emit(sniPath, sniIface, "NewIcon", "")
		_ = t.bus.Emit(sniPath, sniIface, "NewStatus", "s", sniStatus(icon))
	}
	for _, msg := range alerts {
		t.notes.show("OpenScale", msg)
	}
}

// fail shows an error from a menu action.
func (t *linuxTray) fail(err error) {
	if err == nil || errors.Is(err, errCancelled) || errors.Is(err, context.Canceled) {
		return
	}
	t.notes.show("OpenScale", err.Error())
}

// click runs on its own goroutine for every menu click.
func (t *linuxTray) click(id int) {
	t.mu.Lock()
	st, ok := t.state.status, t.state.reachable
	exitName, isExit := t.exits[id]
	t.mu.Unlock()
	dev := st.Device
	switch {
	case isExit && ok && dev != nil:
		t.fail(t.app.client.setExit(t.ctx, exitName))
	case id == mbToggle && ok && dev != nil:
		_, err := t.app.client.setConnected(t.ctx, !dev.Connected)
		t.fail(err)
	case mbDisconnectChoices[id] != "" && ok && dev != nil:
		t.fail(t.app.client.disconnectFor(t.ctx, mbDisconnectChoices[id]))
	case id == mbKillSwitch && ok && dev != nil:
		on := !dev.KillSwitch
		if !on && dev.ExitNodeWanted != "" {
			yes, asked := t.notes.confirm(t.ctx, "Kill switch kapatılsın mı?", "Çıkış düğümüne ulaşılamazsa veya servis durursa internet trafiği doğrudan bu bilgisayarın bağlantısından çıkabilir.", "Kapat", "Vazgeç")
			if !asked {
				t.notes.show("OpenScale", "Bu masaüstünün bildirimleri düğme göstermiyor; kill switch'i panelden kapatın.")
				return
			}
			if !yes {
				return
			}
		}
		t.fail(t.app.client.setExitOptions(t.ctx, on, dev.ExitAllowLAN))
	case id == mbThisDevice && dev != nil && dev.IPv4 != "":
		t.notes.show("OpenScale", "Bu cihaz: "+dev.Name+"\nTünel adresi: "+dev.IPv4)
	case id == mbOpen:
		t.openPanel()
	case id == mbInstall:
		t.setupService(false)
	case id == mbRestart:
		t.fail(t.app.restartService(t.ctx))
	case id == mbReleaseKillSwitch:
		yes, asked := t.notes.confirm(t.ctx, "Kill switch kuralları kaldırılsın mı?", "Servise ulaşılamıyor. Kurallar kalkınca internet trafiği doğrudan bu bilgisayarın bağlantısından çıkar; servis yeniden çalışıp bir çıkış düğümü etkinleşince kurallar tekrar kurulur.", "Kaldır", "Vazgeç")
		// Without buttons the polkit dialog is the confirmation.
		if asked && !yes {
			return
		}
		if err := t.app.releaseKillSwitch(t.ctx); err != nil {
			t.fail(err)
		} else {
			t.notes.show("OpenScale", "Kill switch kaldırıldı; internet erişimi açık.")
		}
	case id == mbAutostart:
		t.fail(t.app.setAutostart(!t.app.autostartOn()))
	case id == mbAbout:
		t.notes.show("OpenScale "+Version, "Kişisel, bağımsız ve gizlilik öncelikli mesh VPN. Hiçbir şirkete veya hesaba bağlı değildir.")
	case id == mbPanic && ok:
		t.notes.show("OpenScale", trayEmergencyHint)
		t.openPanel()
	case id == mbQuit:
		t.cancel()
		return
	}
	t.refresh()
}

// firstStart is a manual start: set the service up, or open the panel.
func (t *linuxTray) firstStart() {
	t.mu.Lock()
	reachable := t.state.reachable
	t.mu.Unlock()
	switch {
	case t.app.needsSetup():
		t.setupService(true)
	case t.app.serviceState() == serviceCommandLine && !reachable:
		t.notes.show("OpenScale", unreachableLabel(serviceCommandLine)+". Önce: sudo openscale service uninstall --role device")
	case reachable:
		t.openPanel()
	default:
		if t.app.client.waitReady(t.ctx, linuxServiceWait) == nil {
			t.refresh()
			t.openPanel()
		}
	}
}

// setupService installs or updates the service after the user agrees
// (ask) and opens the panel when it answers.
func (t *linuxTray) setupService(ask bool) {
	if !t.setupBusy.CompareAndSwap(false, true) {
		return
	}
	defer t.setupBusy.Store(false)
	if ask {
		msg := "Servis bilgisayar açılınca başlar ve VPN tünelini yönetir. Devam edince yönetici parolanız sorulur."
		title := "OpenScale'in arka plan servisi kurulacak"
		if t.app.serviceState() == serviceOutdated {
			title = "OpenScale servisi bu programın sürümüne güncellenecek"
			msg = "Servis kısa bir süre yeniden başlar; bağlantılar birkaç saniye kesilebilir. Devam edince yönetici parolanız sorulur."
		}
		// Without buttons the polkit dialog itself asks.
		if yes, asked := t.notes.confirm(t.ctx, title, msg, "Devam", "Şimdi değil"); asked && !yes {
			return
		}
	}
	if err := t.app.installService(t.ctx); err != nil {
		t.fail(err)
		t.refresh()
		return
	}
	t.refresh()
	t.openPanel()
}

// openPanel shows the panel in the WebKitGTK window with a fresh one-time
// sign-in link; an open window loads the link and comes to the front.
// Without a window (no cgo build, no WebKitGTK) the browser opens it.
func (t *linuxTray) openPanel() {
	link, err := t.app.client.panelURL(t.ctx)
	if err != nil {
		if t.app.needsSetup() {
			go t.setupService(true)
			return
		}
		t.fail(err)
		return
	}
	if webview.ForwardToOpenWindow(link, nil) == nil {
		return
	}
	if !t.windowBusy.CompareAndSwap(false, true) {
		return // a window is being created; this click is not needed
	}
	go func() {
		defer t.windowBusy.Store(false)
		err := winapp.OpenPanelWindow(t.ctx, link, "")
		switch {
		case err == nil, errors.Is(err, context.Canceled):
		case errors.Is(err, winapp.ErrWindowUnavailable):
			if err := winapp.OpenSystemBrowser(link); err != nil {
				t.fail(err)
			}
		default:
			t.fail(err)
		}
	}()
}
