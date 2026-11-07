//go:build darwin

package desktop

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/openscale/openscale/internal/osnet"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/peercred"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/service"
	"github.com/openscale/openscale/internal/svcmgr"
	"github.com/openscale/openscale/internal/winapp"
)

// The macOS app (ADR-0227): OpenScale.app is a menu bar app that runs as
// the logged-in user; the tunnel, the panel and the tray API run in the
// launch daemon com.openscale.service ("openscale service run" as root).
// The app installs the daemon once through the administrator password
// dialog and talks to it only through the tray socket below.

const (
	// traySocketDir holds the tray socket; root-owned, 0755.
	traySocketDir = "/var/run/openscale"
	// TraySocket is where the service accepts the menu bar app.
	TraySocket = traySocketDir + "/tray.sock"
	// gateBase is the HTTP base of requests over the tray socket; the host
	// name is never resolved.
	gateBase = "http://tray.invalid"
	// macServiceWait is how long the app waits for a freshly started
	// service.
	macServiceWait = 30 * time.Second
	// maxGateConns bounds simultaneous tray socket connections.
	maxGateConns = 16
	// osascriptPath runs the administrator password dialog (sealed
	// system volume, never looked up in PATH).
	osascriptPath = "/usr/bin/osascript"
	// privilegedTimeout covers the dialog and the installation.
	privilegedTimeout = 5 * time.Minute
)

// LaunchedByDoubleClick reports whether Finder (LaunchServices) started
// the program from the app bundle: no terminal and the program inside
// OpenScale.app/Contents/MacOS. main then runs "app".
func LaunchedByDoubleClick() bool {
	exe, err := ownExecutable()
	if err != nil {
		return false
	}
	return strings.Contains(exe, ".app/Contents/MacOS/") && !term.IsTerminal(int(os.Stdin.Fd()))
}

// RunApp is the app entry: the menu bar icon, the service set-up when it
// is missing or older than the app, and the panel window.
func RunApp(ctx context.Context) error { return runMacApp(ctx, false) }

// RunAppQuiet is the sign-in start ("openscale autostart run"): only the
// menu bar icon, no window and no password dialog.
func RunAppQuiet(ctx context.Context) error { return runMacApp(ctx, true) }

// macApp is what the menu bar (cgo) and the browser fallback share.
type macApp struct {
	client *trayClient
	exe    string
	hashes programHashes
	// settingDir is the user's OpenScale folder (autostart setting, lock).
	settingDir string
}

func newMacApp() (*macApp, error) {
	exe, err := ownExecutable()
	if err != nil {
		return nil, err
	}
	base, err := os.UserConfigDir()
	if err != nil || base == "" {
		return nil, errors.New("kullanıcı ayar klasörü bulunamadı")
	}
	return &macApp{client: newGatewayClient(), exe: exe, settingDir: filepath.Join(base, "OpenScale")}, nil
}

// serviceState says why the socket may not answer.
func (a *macApp) serviceState() menuBarService {
	if !svcmgr.DarwinAppInstalled() {
		return serviceMissing
	}
	if !a.sameProgram() {
		return serviceOutdated
	}
	return serviceInstalled
}

// sameProgram reports whether the service runs this app's program; the
// tray socket refuses the app otherwise.
func (a *macApp) sameProgram() bool {
	own, err := a.hashes.sum(a.exe)
	if err != nil {
		return false
	}
	installed, err := a.hashes.sum(svcmgr.DarwinAppBinary)
	return err == nil && own == installed
}

// needsSetup reports whether the service must be installed or updated
// before the app can use it.
func (a *macApp) needsSetup() bool {
	s := a.serviceState()
	return s == serviceMissing || s == serviceOutdated
}

// installService installs or updates the service with the password
// dialog and waits until it answers.
func (a *macApp) installService(ctx context.Context) error {
	if err := runPrivileged(ctx, a.exe, "OpenScale arka plan servisini kurmak veya güncellemek istiyor.", "app", "install-service"); err != nil {
		return err
	}
	return a.client.waitReady(ctx, macServiceWait)
}

// restartService restarts the service with the password dialog.
func (a *macApp) restartService(ctx context.Context) error {
	if err := runPrivileged(ctx, a.exe, "OpenScale arka plan servisini yeniden başlatmak istiyor.", "app", "restart-service"); err != nil {
		return err
	}
	return a.client.waitReady(ctx, macServiceWait)
}

// releaseKillSwitch removes the pf rules when the service is gone.
func (a *macApp) releaseKillSwitch(ctx context.Context) error {
	return runPrivileged(ctx, a.exe, "OpenScale kill switch kurallarını kaldırmak istiyor.", "killswitch", "off")
}

// autostartOn reports the user's sign-in setting.
func (a *macApp) autostartOn() bool {
	on, _ := svcmgr.LoadAutostartSetting(a.settingDir)
	return on
}

// syncAutostart writes or removes the user's launch agent so it starts
// this app's program (the app may have moved since the last start).
func (a *macApp) syncAutostart() error {
	if !a.autostartOn() {
		_, err := svcmgr.DisableAutostart(svcmgr.ScopeUser)
		return err
	}
	if st, err := svcmgr.AutostartState(svcmgr.ScopeUser); err == nil && st.Installed && !st.Ours {
		return nil // someone else's file: leave it
	}
	_, err := svcmgr.EnableAutostart(svcmgr.ScopeUser, a.exe)
	return err
}

// setAutostart changes the sign-in setting and the launch agent.
func (a *macApp) setAutostart(on bool) error {
	if err := svcmgr.SaveAutostartSetting(a.settingDir, on); err != nil {
		return err
	}
	return a.syncAutostart()
}

// errCancelled: the user closed the password dialog.
var errCancelled = errors.New("işlem iptal edildi")

// privilegedScript runs "argv[2] argv[3...]" as root after the system's
// administrator password dialog with argv[1] as its explanation. Every
// value is passed as an argument and quoted by AppleScript ("quoted form
// of"), never pasted into the script text, so no path or label can change
// the command (ADR-0227).
var privilegedScript = []string{
	"on run argv",
	"set cmd to quoted form of (item 2 of argv)",
	"repeat with i from 3 to count of argv",
	"set cmd to cmd & \" \" & quoted form of (item i of argv)",
	"end repeat",
	"do shell script cmd with prompt (item 1 of argv) with administrator privileges",
	"end run",
}

// privilegedCommands are the only commands the app runs as root.
var privilegedCommands = map[string]bool{
	"app install-service": true,
	"app restart-service": true,
	"killswitch off":      true,
}

// privilegedArgs builds the osascript command line.
func privilegedArgs(exe, prompt string, args ...string) ([]string, error) {
	if !privilegedCommands[strings.Join(args, " ")] {
		return nil, fmt.Errorf("yetkili komut izinli değil: %q", strings.Join(args, " "))
	}
	if !filepath.IsAbs(exe) || strings.ContainsAny(exe, "\x00\r\n") || strings.ContainsAny(prompt, "\x00") {
		return nil, errors.New("yetkili komut için program yolu geçersiz")
	}
	out := make([]string, 0, 2*len(privilegedScript)+2+len(args))
	for _, line := range privilegedScript {
		out = append(out, "-e", line)
	}
	out = append(out, prompt, exe)
	return append(out, args...), nil
}

// runPrivileged runs this program's command as root after the password
// dialog. The program checks its own arguments again as root.
func runPrivileged(ctx context.Context, exe, prompt string, args ...string) error {
	argv, err := privilegedArgs(exe, prompt, args...)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, privilegedTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, osascriptPath, argv...)
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=tr_TR.UTF-8"}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(out.String())
		// -128 is AppleScript's "User canceled."
		if strings.Contains(msg, "(-128)") {
			return errCancelled
		}
		if len(msg) > 400 {
			msg = msg[:400]
		}
		return fmt.Errorf("yönetici işlemi başarısız: %v: %s", err, msg)
	}
	return nil
}

// InstallService installs or updates the app service from this program
// ("openscale app install-service", root, run by the app).
func InstallService(ctx context.Context) ([]string, error) {
	if os.Geteuid() != 0 {
		return nil, svcmgr.ErrNeedsRoot
	}
	res, err := svcmgr.InstallDarwinApp(ctx)
	return res.Notes, err
}

// RestartService restarts the app service (root).
func RestartService(ctx context.Context) error { return svcmgr.RestartDarwinApp(ctx) }

// Uninstall removes the app service and the persistent kill switch; keys
// and the network stay in the state folder.
func Uninstall() error {
	if os.Geteuid() != 0 {
		return errors.New("kaldırmak için yönetici olarak çalıştırın: sudo openscale app uninstall-service")
	}
	if _, err := svcmgr.UninstallDarwinApp(context.Background()); err != nil {
		return err
	}
	return osnet.RemoveKillSwitch()
}

// RunService is what launchd starts: the service with the panel, the
// tray API and the tunnel, plus the tray socket.
func RunService() error {
	if os.Geteuid() != 0 {
		return errors.New("servis root olarak çalışır; launchd başlatır (openscale app install-service)")
	}
	dataDir := svcmgr.DarwinAppStateDir
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return err
	}
	logger, closeLog, err := serviceLogger(dataDir)
	if err != nil {
		return err
	}
	defer closeLog()
	if n, err := securefile.RemoveStaleTemps(dataDir, time.Now()); err != nil {
		logger.Warn("stale temporary files", "error", err.Error())
	} else if n > 0 {
		logger.Info("stale temporary files removed", "count", n)
	}
	r, err := service.New(service.Config{
		DataDir: dataDir,
		Logger:  logger,
		// The app token is read only by root (0600 in a 0700 folder);
		// the menu bar app reaches the API through the tray socket.
		Hooks: service.Hooks{
			ConfigureDNS:        osnet.ConfigureDNS,
			RemoveDNS:           osnet.RemoveDNS,
			ConfigureNetworkDNS: osnet.ConfigureNetworkDNS,
			VerifyNetworkDNS:    osnet.VerifyNetworkDNS,
			DNSStatus:           osnet.SystemDNSStatus,
			ExitRouter:          osnet.NewExitRouter(),
			InstallKillSwitch:   osnet.InstallKillSwitch,
			RemoveKillSwitch:    osnet.RemoveKillSwitch,
			DNSEnforce:          osnet.NewDNSEnforcer(),
			Recover:             service.SystemUndo,
		},
	})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := serveTrayGate(ctx, logger, dataDir); err != nil && ctx.Err() == nil {
			logger.Error("tray socket stopped", "error", err.Error())
		}
	}()
	err = r.Run(ctx)
	stop()
	wg.Wait()
	if err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("service stopped", "error", err.Error())
		return err
	}
	return nil
}

// macPanicConfirm is the first question of the panic item.
const macPanicConfirm = "Panik: ağ kilitlensin mi?\n\nÖnceden hazırlanmış kilitleme belgesi yayımlanır. Cihazlar bir sonraki eşitlemede kilitli belgeyi alır ve bağlantılar kısıtlanır. Geri almak için kök anahtarla yeni bir belge imzalamanız gerekir."

// publishPanic publishes the prepared lockdown document.
func (c *trayClient) publishPanic(ctx context.Context, passphrase string) error {
	var out map[string]any
	return c.do(ctx, http.MethodPost, "/api/app/tray/panic", panel.TrayPanicRequest{Passphrase: passphrase}, &out)
}

// openPanelBrowser opens a fresh sign-in link in the system browser.
func (a *macApp) openPanelBrowser(ctx context.Context) error {
	link, err := a.client.panelURL(ctx)
	if err != nil {
		return fmt.Errorf("panel açılamadı: %w", err)
	}
	return winapp.OpenSystemBrowser(link)
}

// trayGatePolicy: root and the admin group (ADR-0227); the kernel's group
// list is complete up to 16 groups.
func trayGatePolicy() gatePeerPolicy {
	return gatePeerPolicy{group: adminGroupID, image: peercred.ProcessImagePath, inGroup: userInGroup}
}
