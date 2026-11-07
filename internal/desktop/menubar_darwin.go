//go:build darwin && cgo

package desktop

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/openscale/openscale/internal/macapp"
	"github.com/openscale/openscale/internal/webview"
	"github.com/openscale/openscale/internal/winapp"
)

// The menu bar app (ADR-0227, #883). runMacApp runs on the main goroutine
// (cli.Run is called from main) because macapp.Run owns the AppKit loop
// there; everything else runs on other goroutines and changes the menu
// through macapp, which queues the work on the main thread.

// macStatusEvery is the status poll; the event stream thins it out.
const macStatusEvery = 5 * time.Second

type menuBar struct {
	app   *macApp
	ctx   context.Context
	icons map[trayIconState][]byte

	mu        sync.Mutex
	state     menuBarState
	exits     map[int]string
	shownIcon trayIconState

	notifier   alertNotifier
	windowBusy atomic.Bool
	setupBusy  atomic.Bool
}

func runMacApp(ctx context.Context, quiet bool) error {
	app, err := newMacApp()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	mb := &menuBar{app: app, ctx: ctx, exits: map[int]string{}, shownIcon: -1, icons: menuBarIcons(menuBarTemplatePNG)}
	release, err := claimInstance(ctx, app.settingDir, quiet, func() { mb.openPanel() })
	if errors.Is(err, errOtherInstance) {
		return nil
	}
	if err != nil {
		return err
	}
	defer release()
	// The panel window opens inside this run loop and closing it leaves
	// the app in the menu bar.
	webview.UseAppRunLoop()
	_ = app.syncAutostart()
	return macapp.Run(ctx, macapp.Config{
		Title:    "OpenScale",
		OnClick:  mb.click,
		OnReopen: mb.openPanel,
		OnReady:  func() { mb.start(quiet) },
	})
}

// start runs once the run loop has started: first refresh, the
// service set-up on a manual start, the status and event loops.
func (m *menuBar) start(quiet bool) {
	m.refresh()
	if !quiet {
		m.mu.Lock()
		reachable := m.state.reachable
		m.mu.Unlock()
		switch {
		case m.app.needsSetup():
			m.setupService(true)
		case reachable:
			m.openPanel()
		default:
			// Just installed or restarting: wait a little, then open.
			if m.app.client.waitReady(m.ctx, macServiceWait) == nil {
				m.refresh()
				m.openPanel()
			}
		}
	}
	gate := &refreshGate{}
	go followEvents(m.ctx, m.app.client, gate, func(notes []string) {
		for _, msg := range notes {
			macapp.Notify("OpenScale", msg)
		}
		m.refresh()
	})
	ticker := time.NewTicker(macStatusEvery)
	defer ticker.Stop()
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			if gate.skip() {
				continue
			}
			m.refresh()
		}
	}
}

// refresh reads the status and rebuilds the menu, tooltip and icon.
func (m *menuBar) refresh() {
	st, err := m.app.client.status(m.ctx)
	ok := err == nil
	svc := serviceUnknown
	if !ok {
		svc = m.app.serviceState()
	}
	m.mu.Lock()
	m.state = menuBarState{status: st, reachable: ok, service: svc, autostart: m.app.autostartOn()}
	items := toMacItems(menuBarItems(m.state, m.exits))
	tip := menuBarTooltip(m.state)
	icon := iconStateFor(st, ok)
	changed := icon != m.shownIcon
	m.shownIcon = icon
	notes := m.notifier.update(st, ok)
	m.mu.Unlock()
	_ = macapp.SetMenu(items)
	macapp.SetTooltip(tip)
	if changed {
		macapp.SetIcon(m.icons[icon], "OpenScale")
	}
	for _, msg := range notes {
		macapp.Notify("OpenScale", msg)
	}
}

func toMacItems(in []winapp.MenuItem) []macapp.Item {
	out := make([]macapp.Item, 0, len(in))
	for _, it := range in {
		out = append(out, macapp.Item{
			ID: it.ID, Label: it.Label, Detail: it.Detail, Disabled: it.Disabled,
			Separator: it.Separator, Checked: it.Checked, Bold: it.Default,
			Children: toMacItems(it.Children),
		})
	}
	return out
}

// fail shows an error from a menu action.
func (m *menuBar) fail(err error) {
	if err == nil || errors.Is(err, errCancelled) || errors.Is(err, context.Canceled) {
		return
	}
	macapp.Message("OpenScale\n\n" + err.Error())
}

// click runs on its own goroutine for every menu click.
func (m *menuBar) click(id int) {
	m.mu.Lock()
	st, ok := m.state.status, m.state.reachable
	exitName, isExit := m.exits[id]
	m.mu.Unlock()
	dev := st.Device
	switch {
	case isExit && ok && dev != nil:
		m.fail(m.app.client.setExit(m.ctx, exitName))
	case id == mbToggle && ok && dev != nil:
		_, err := m.app.client.setConnected(m.ctx, !dev.Connected)
		m.fail(err)
	case mbDisconnectChoices[id] != "" && ok && dev != nil:
		m.fail(m.app.client.disconnectFor(m.ctx, mbDisconnectChoices[id]))
	case id == mbKillSwitch && ok && dev != nil:
		on := !dev.KillSwitch
		if !on && dev.ExitNodeWanted != "" &&
			!macapp.Confirm("Kill switch kapatılsın mı?\n\nÇıkış düğümüne ulaşılamazsa veya servis durursa internet trafiği doğrudan bu bilgisayarın bağlantısından çıkabilir.", "Kapat", "Vazgeç", true) {
			return
		}
		m.fail(m.app.client.setExitOptions(m.ctx, on, dev.ExitAllowLAN))
	case id == mbThisDevice && dev != nil && dev.IPv4 != "":
		macapp.CopyText(dev.IPv4)
		macapp.Notify("OpenScale", dev.IPv4+" panoya kopyalandı.")
	case id == mbOpen:
		m.openPanel()
	case id == mbInstall:
		m.setupService(false)
	case id == mbRestart:
		m.fail(m.app.restartService(m.ctx))
	case id == mbReleaseKillSwitch:
		if macapp.Confirm("Kill switch kuralları kaldırılsın mı?\n\nServise ulaşılamıyor. Kurallar kalkınca internet trafiği doğrudan bu bilgisayarın bağlantısından çıkar; servis yeniden çalışıp bir çıkış düğümü etkinleşince kurallar tekrar kurulur.", "Kaldır", "Vazgeç", true) {
			if err := m.app.releaseKillSwitch(m.ctx); err != nil {
				m.fail(err)
			} else {
				macapp.Notify("OpenScale", "Kill switch kaldırıldı; internet erişimi açık.")
			}
		}
	case id == mbAutostart:
		m.fail(m.app.setAutostart(!m.app.autostartOn()))
	case id == mbAbout:
		macapp.Message("OpenScale " + Version + "\n\nKişisel, bağımsız ve gizlilik öncelikli mesh VPN. Hiçbir şirkete veya hesaba bağlı değildir.")
	case id == mbPanic && ok:
		m.panic()
	case id == mbQuit:
		macapp.Quit()
		return
	}
	m.refresh()
}

// setupService installs or updates the service after the user agrees
// (ask) and opens the panel when it answers.
func (m *menuBar) setupService(ask bool) {
	if !m.setupBusy.CompareAndSwap(false, true) {
		return
	}
	defer m.setupBusy.Store(false)
	missing := m.app.serviceState() == serviceMissing
	if ask {
		msg := "OpenScale'in arka plan servisi kurulacak.\n\nServis bilgisayar açılınca başlar ve VPN tünelini yönetir. Devam edince macOS yönetici parolanızı soracak."
		if !missing {
			msg = "OpenScale servisi bu uygulamanın sürümüne güncellenecek.\n\nServis kısa bir süre yeniden başlar; bağlantılar birkaç saniye kesilebilir. Devam edince macOS yönetici parolanızı soracak."
		}
		if !macapp.Confirm(msg, "Devam", "Şimdi değil", false) {
			return
		}
	}
	if err := m.app.installService(m.ctx); err != nil {
		m.fail(err)
		m.refresh()
		return
	}
	m.refresh()
	m.openPanel()
}

// openPanel shows the panel in the native window with a fresh one-time
// sign-in link; a window that is already open loads the link and comes to
// the front. Without a window the browser opens the link.
func (m *menuBar) openPanel() {
	link, err := m.app.client.panelURL(m.ctx)
	if err != nil {
		if m.app.needsSetup() {
			go m.setupService(true)
			return
		}
		m.fail(err)
		return
	}
	if webview.ForwardToOpenWindow(link, nil) == nil {
		return
	}
	if !m.windowBusy.CompareAndSwap(false, true) {
		return // a window is being created; this click is not needed
	}
	go func() {
		defer m.windowBusy.Store(false)
		err := winapp.OpenPanelWindow(m.ctx, link, "")
		switch {
		case err == nil, errors.Is(err, context.Canceled):
		case errors.Is(err, winapp.ErrWindowUnavailable):
			if err := winapp.OpenSystemBrowser(link); err != nil {
				m.fail(err)
			}
		default:
			m.fail(err)
		}
	}()
}

// panic asks twice (alert, then the root key passphrase in a secure text
// field) and publishes the prepared lockdown document.
func (m *menuBar) panic() {
	if !macapp.Confirm(macPanicConfirm, "Kilitle", "Vazgeç", true) {
		return
	}
	pass, ok := macapp.AskSecret("Kök anahtar parolası\n\nPanik kilitlemesi için ağın kök anahtar parolasını girin.", "Kilitle")
	if !ok {
		return
	}
	// The passphrase leaves this buffer only for the request body.
	err := m.app.client.publishPanic(m.ctx, string(pass))
	clear(pass)
	if err != nil {
		m.fail(fmt.Errorf("panik uygulanamadı: %w", err))
		return
	}
	macapp.Notify("OpenScale", "Kilitleme belgesi yayımlandı.")
}
