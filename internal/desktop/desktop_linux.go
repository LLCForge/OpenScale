//go:build linux

package desktop

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/openscale/openscale/internal/osnet"
	"github.com/openscale/openscale/internal/peercred"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/service"
	"github.com/openscale/openscale/internal/svcmgr"
	"github.com/openscale/openscale/internal/winapp"
)

// The Linux desktop app (ADR-0234): "openscale tray" (and "openscale
// app") is a StatusNotifierItem tray icon that runs as the signed-in
// user; the tunnel, the panel and the tray API run in the systemd unit
// openscale-app.service ("openscale service run" as root). The tray
// installs the unit once through polkit (pkexec) and talks to it only
// through the tray socket below, like the macOS menu bar app.

const (
	// traySocketDir holds the tray socket; systemd creates it (root,
	// 0755, RuntimeDirectory=openscale).
	traySocketDir = svcmgr.LinuxAppRuntimeDir
	// TraySocket is where the service accepts the tray.
	TraySocket = traySocketDir + "/tray.sock"
	// gateBase is the HTTP base of requests over the tray socket; the host
	// name is never resolved.
	gateBase = "http://tray.invalid"
	// linuxServiceWait is how long the tray waits for a freshly started
	// service.
	linuxServiceWait = 30 * time.Second
	// maxGateConns bounds simultaneous tray socket connections.
	maxGateConns = 16
	// pkexecPath runs the administrator dialog of polkit (never looked up
	// in PATH).
	pkexecPath = "/usr/bin/pkexec"
	// privilegedTimeout covers the dialog and the installation.
	privilegedTimeout = 5 * time.Minute
)

// LaunchedByDoubleClick is false on Linux: the tray starts from the
// application menu entry or XDG autostart with an explicit command.
func LaunchedByDoubleClick() bool { return false }

// RunApp is "openscale app": the tray icon, the service set-up when it is
// missing or older than this program, and the panel window.
func RunApp(ctx context.Context) error { return runLinuxTray(ctx, false) }

// RunAppQuiet is the sign-in start ("openscale autostart run") and
// "openscale tray": only the tray icon, no window and no password dialog.
func RunAppQuiet(ctx context.Context) error { return runLinuxTray(ctx, true) }

// linuxApp is what the tray needs to know about the service.
type linuxApp struct {
	client *trayClient
	exe    string
	hashes programHashes
	// settingDir is the user's OpenScale folder (autostart setting, lock).
	settingDir string
}

func newLinuxApp() (*linuxApp, error) {
	exe, err := ownExecutable()
	if err != nil {
		return nil, err
	}
	base, err := os.UserConfigDir()
	if err != nil || base == "" {
		return nil, errors.New("kullanıcı ayar klasörü bulunamadı")
	}
	return &linuxApp{client: newGatewayClient(), exe: exe, settingDir: filepath.Join(base, "OpenScale")}, nil
}

// serviceState says why the socket may not answer.
func (a *linuxApp) serviceState() menuBarService {
	if !svcmgr.LinuxAppInstalled() {
		if svcmgr.LinuxDeviceUnitInstalled() {
			return serviceCommandLine
		}
		return serviceMissing
	}
	if !a.sameProgram() {
		return serviceOutdated
	}
	return serviceInstalled
}

// sameProgram reports whether the service runs this program; the tray
// socket refuses the tray otherwise.
func (a *linuxApp) sameProgram() bool {
	installed, err := svcmgr.LinuxAppProgram()
	if err != nil {
		return false
	}
	own, err := a.hashes.sum(a.exe)
	if err != nil {
		return false
	}
	theirs, err := a.hashes.sum(installed)
	return err == nil && own == theirs
}

func (a *linuxApp) needsSetup() bool {
	s := a.serviceState()
	return s == serviceMissing || s == serviceOutdated
}

// installService installs or updates the service through polkit and
// waits until it answers.
func (a *linuxApp) installService(ctx context.Context) error {
	if err := runPrivileged(ctx, a.exe, "app", "install-service"); err != nil {
		return err
	}
	return a.client.waitReady(ctx, linuxServiceWait)
}

// restartService restarts the service through polkit.
func (a *linuxApp) restartService(ctx context.Context) error {
	if err := runPrivileged(ctx, a.exe, "app", "restart-service"); err != nil {
		return err
	}
	return a.client.waitReady(ctx, linuxServiceWait)
}

// releaseKillSwitch removes the nftables rules when the service is gone.
func (a *linuxApp) releaseKillSwitch(ctx context.Context) error {
	return runPrivileged(ctx, a.exe, "killswitch", "off")
}

func (a *linuxApp) autostartOn() bool {
	on, _ := svcmgr.LoadAutostartSetting(a.settingDir)
	return on
}

// syncAutostart writes or removes the user's XDG autostart entry
// (~/.config/autostart/openscale-tray.desktop) so it starts this program.
func (a *linuxApp) syncAutostart() error {
	if !a.autostartOn() {
		_, err := svcmgr.DisableAutostart(svcmgr.ScopeUser)
		return err
	}
	if st, err := svcmgr.AutostartState(svcmgr.ScopeUser); err == nil && st.Installed && !st.Ours {
		return nil // someone else's file: leave it
	}
	_, err := svcmgr.EnableAutostart(svcmgr.ScopeUser, autostartExe(a.exe))
	return err
}

// autostartExe prefers the installed program, which survives the
// downloaded copy being moved or deleted.
func autostartExe(own string) string {
	if p, err := svcmgr.LinuxAppProgram(); err == nil {
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			return p
		}
	}
	return own
}

func (a *linuxApp) setAutostart(on bool) error {
	if err := svcmgr.SaveAutostartSetting(a.settingDir, on); err != nil {
		return err
	}
	return a.syncAutostart()
}

// errCancelled: the user closed the administrator dialog.
var errCancelled = errors.New("işlem iptal edildi")

// errNoPolkit: pkexec is not installed.
var errNoPolkit = errors.New("yönetici penceresi (pkexec) yok")

// privilegedCommands are the only commands the tray runs as root.
var privilegedCommands = map[string]bool{
	"app install-service": true,
	"app restart-service": true,
	"killswitch off":      true,
}

// privilegedArgs builds the pkexec command line. pkexec checks the
// polkit rule for running a program as root (auth_admin), clears the
// environment and runs exe with args; no shell is involved.
func privilegedArgs(exe string, args ...string) ([]string, error) {
	if !privilegedCommands[strings.Join(args, " ")] {
		return nil, fmt.Errorf("yetkili komut izinli değil: %q", strings.Join(args, " "))
	}
	if !filepath.IsAbs(exe) || strings.ContainsAny(exe, "\x00\r\n") {
		return nil, errors.New("yetkili komut için program yolu geçersiz")
	}
	return append([]string{"--disable-internal-agent", exe}, args...), nil
}

// runPrivileged runs this program's command as root after the polkit
// dialog. The program checks its own arguments again as root.
func runPrivileged(ctx context.Context, exe string, args ...string) error {
	argv, err := privilegedArgs(exe, args...)
	if err != nil {
		return err
	}
	if fi, err := os.Stat(pkexecPath); err != nil || !fi.Mode().IsRegular() {
		return fmt.Errorf("%w; terminalde çalıştırın: sudo %s %s", errNoPolkit, exe, strings.Join(args, " "))
	}
	ctx, cancel := context.WithTimeout(ctx, privilegedTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, pkexecPath, argv...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=tr_TR.UTF-8"}
	for _, k := range []string{"DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"} {
		if v := os.Getenv(k); v != "" {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		// 126: the dialog was dismissed or authorization refused.
		if errors.As(err, &ee) && ee.ExitCode() == 126 {
			return errCancelled
		}
		msg := strings.TrimSpace(out.String())
		if len(msg) > 400 {
			msg = msg[:400]
		}
		return fmt.Errorf("yönetici işlemi başarısız: %v: %s", err, msg)
	}
	return nil
}

// invokingUID is the user who asked for the root command: pkexec sets
// PKEXEC_UID, sudo SUDO_UID.
func invokingUID() (int, bool) {
	for _, k := range []string{"PKEXEC_UID", "SUDO_UID"} {
		if v := os.Getenv(k); v != "" {
			if uid, err := strconv.Atoi(v); err == nil && uid > 0 {
				return uid, true
			}
		}
	}
	return 0, false
}

// InstallService installs or updates the app service from this program
// ("openscale app install-service", root, run by the tray through
// pkexec) and lets the user who authorized it use the tray socket.
func InstallService(ctx context.Context) ([]string, error) {
	if os.Geteuid() != 0 {
		return nil, svcmgr.ErrNeedsRoot
	}
	res, err := svcmgr.InstallLinuxApp(ctx)
	notes := res.Notes
	if err != nil {
		return notes, err
	}
	if uid, ok := invokingUID(); ok {
		more, err := svcmgr.AddLinuxAppUser(ctx, uid)
		notes = append(notes, more...)
		if err != nil {
			notes = append(notes, "Kullanıcı "+svcmgr.LinuxAppGroup+" grubuna eklenemedi: "+err.Error())
		}
	} else {
		notes = append(notes, "Tepsiyi kullanacak hesabı "+svcmgr.LinuxAppGroup+" grubuna ekleyin: sudo gpasswd -a <kullanıcı> "+svcmgr.LinuxAppGroup)
	}
	return notes, nil
}

// RestartService restarts the app service (root).
func RestartService(ctx context.Context) error { return svcmgr.RestartLinuxApp(ctx) }

// Uninstall removes the app service and the persistent kill switch; keys
// and the network stay in the state folder.
func Uninstall() error {
	if os.Geteuid() != 0 {
		return errors.New("kaldırmak için yönetici olarak çalıştırın: sudo openscale app uninstall-service")
	}
	if _, err := svcmgr.UninstallLinuxApp(context.Background()); err != nil {
		return err
	}
	return osnet.RemoveKillSwitch()
}

// RunService is what systemd starts: the service with the panel, the
// tray API and the tunnel, plus the tray socket.
func RunService() error {
	if os.Geteuid() != 0 {
		return errors.New("servis root olarak çalışır; systemd başlatır (openscale app install-service)")
	}
	dataDir := svcmgr.LinuxAppStateDir
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
		// the tray reaches the API through the tray socket.
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

// trayGatePolicy: root and members of the openscale group (ADR-0234).
// SO_PEERCRED carries no supplementary groups, so the group database is
// asked every time; without the group only root gets in.
func trayGatePolicy() gatePeerPolicy {
	p := gatePeerPolicy{group: noGroup, partialGroups: true, image: linuxPeerProgram, inGroup: userInGroup}
	if g, err := user.LookupGroup(svcmgr.LinuxAppGroup); err == nil {
		if gid, err := strconv.Atoi(g.Gid); err == nil && gid > 0 {
			p.group = gid
		}
	}
	return p
}

// linuxPeerProgram is the program file a process runs. The path from
// /proc/<pid>/exe must still be the very file the process was started
// from (same device and inode), so a program that was replaced or deleted
// since is refused instead of hashing whatever is at the path now.
func linuxPeerProgram(pid int) (string, error) {
	p, err := peercred.ProcessImagePath(pid)
	if err != nil {
		return "", err
	}
	running, err := os.Stat("/proc/" + strconv.Itoa(pid) + "/exe")
	if err != nil {
		return "", err
	}
	onDisk, err := os.Stat(p)
	if err != nil {
		return "", err
	}
	if !os.SameFile(running, onDisk) {
		return "", errors.New("program dosyası süreç başladıktan sonra değişmiş")
	}
	return p, nil
}

// openPanelBrowser opens a fresh sign-in link in the system browser.
func (a *linuxApp) openPanelBrowser(ctx context.Context) error {
	link, err := a.client.panelURL(ctx)
	if err != nil {
		return fmt.Errorf("panel açılamadı: %w", err)
	}
	return winapp.OpenSystemBrowser(link)
}
