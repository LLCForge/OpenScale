package svcmgr

// The macOS app's background service (ADR-0227): the same service the
// Windows app runs (internal/service: panel, tray API, setup in the panel,
// tunnel), here as the launch daemon com.openscale.service. The menu bar
// app installs it through the administrator password dialog ("openscale
// app install-service" run as root) and talks to it through the tray
// socket. Like launchd.go the work is plain file and command work behind
// sysOps, so it is tested on every system.

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/openscale/openscale/internal/launchd"
)

// Paths of the macOS app service. The program is copied out of the app
// bundle into a folder only root can change, so launchd never runs a
// file the user (or anything running as the user) can replace.
const (
	DarwinAppLabel    = "com.openscale.service"
	DarwinAppDir      = "/Library/Application Support/OpenScale"
	DarwinAppBinary   = DarwinAppDir + "/bin/openscale"
	DarwinAppStateDir = "/var/db/openscale/service"
	darwinAppLog      = "/var/log/openscale-service.log"
	darwinAppSyslog   = "/etc/newsyslog.d/openscale-service.conf"
	// darwinAppMarker marks the daemon file as written by the app.
	darwinAppMarker = "Installed by the OpenScale app; openscale app uninstall-service removes it."
)

// ErrDarwinDeviceDaemon: the command line device daemon (ADR-0100) is
// installed; two tunnels on one Mac would fight over routes and DNS.
var ErrDarwinDeviceDaemon = errors.New("komut satırı cihaz servisi (com.openscale.device) kurulu; uygulama servisi yanına kurulmaz. Önce: sudo openscale service uninstall")

// DarwinAppJob is the launch daemon of the app service: root (utun,
// routes, pf), started at boot, restarted after a crash but not after a
// requested stop, root-only log rotated by newsyslog.
func DarwinAppJob(bin string) launchd.Job {
	return launchd.Job{
		Label:              DarwinAppLabel,
		Program:            []string{bin, "service", "run"},
		Marker:             darwinAppMarker,
		RunAtLoad:          true,
		KeepAliveOnFailure: true,
		ThrottleInterval:   10,
		ExitTimeOut:        30,
		Umask:              0o077,
		WorkingDirectory:   DarwinAppStateDir,
		StdoutPath:         darwinAppLog,
		StderrPath:         darwinAppLog,
		Env:                map[string]string{"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
	}
}

func darwinAppNewsyslog() string {
	return installMarker + "\n# logfilename\t\t\t[owner:group]\tmode\tcount\tsize(KB)\twhen\tflags\n" +
		darwinAppLog + "\troot:wheel\t600\t5\t10240\t*\tJ\n"
}

// installDarwinApp copies this program to DarwinAppBinary and installs,
// updates and (re)starts the app daemon.
func installDarwinApp(ctx context.Context, s sysOps) (Result, error) {
	var res Result
	if s.euid() != 0 {
		return res, fmt.Errorf("%w: uygulama servisi yönetici parolasıyla kurulur", ErrNeedsRoot)
	}
	if s.exists(launchd.Path(darwinDeviceLabel)) {
		return res, ErrDarwinDeviceDaemon
	}
	plistPath := launchd.Path(DarwinAppLabel)
	if err := checkMarkedPlist(s, plistPath, darwinAppMarker); err != nil {
		return res, err
	}
	src, err := s.executable()
	if err != nil {
		return res, fmt.Errorf("program yolu bulunamadı: %w", err)
	}
	dst := s.path(DarwinAppBinary)
	same, err := sameFile(src, dst)
	if err != nil {
		return res, err
	}
	if !same {
		if err := copyProgram(src, dst); err != nil {
			return res, err
		}
		res.Notes = append(res.Notes, "Program "+DarwinAppBinary+" konumuna kopyalandı.")
	}
	res.Binary = DarwinAppBinary
	if err := s.trusted(dst); err != nil {
		return res, fmt.Errorf("servis programı güvenli bir yerde değil (F-124): %w", err)
	}
	if err := prepareStateDir(ctx, s, Options{Role: RoleDevice, StateDir: DarwinAppStateDir}); err != nil {
		return res, err
	}
	plist, err := launchd.Plist(DarwinAppJob(DarwinAppBinary))
	if err != nil {
		return res, err
	}
	if err := writeFile(s, plistPath, plist, 0o644); err != nil {
		return res, err
	}
	if err := writeFile(s, darwinAppSyslog, []byte(darwinAppNewsyslog()), 0o644); err != nil {
		return res, err
	}
	target := launchd.Target(DarwinAppLabel)
	// enable clears an earlier "launchctl disable", so the daemon loads at
	// boot again.
	if _, err := s.launchctl(ctx, "enable", target); err != nil {
		return res, fmt.Errorf("launchctl enable: %w", err)
	}
	// A loaded daemon keeps running the old program and property list
	// until it is unloaded.
	if _, err := s.launchctl(ctx, "print", target); err == nil {
		_, _ = s.launchctl(ctx, "bootout", target)
	}
	if _, err := s.launchctl(ctx, "bootstrap", "system", plistPath); err != nil {
		return res, fmt.Errorf("launchctl bootstrap: %w", err)
	}
	res.Started = true
	return res, nil
}

// checkMarkedPlist refuses to overwrite a daemon file that lacks marker.
func checkMarkedPlist(s sysOps, p, marker string) error {
	data, err := os.ReadFile(s.path(p))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !launchd.HasMarker(data, marker) {
		return fmt.Errorf("%s elle yazılmış görünüyor; üzerine yazılmadı (silip yeniden deneyin)", p)
	}
	return nil
}

// restartDarwinApp restarts the app daemon (root).
func restartDarwinApp(ctx context.Context, s sysOps) error {
	if s.euid() != 0 {
		return fmt.Errorf("%w: sudo openscale app restart-service", ErrNeedsRoot)
	}
	plistPath := launchd.Path(DarwinAppLabel)
	if !s.exists(plistPath) {
		return errors.New("uygulama servisi kurulu değil")
	}
	target := launchd.Target(DarwinAppLabel)
	if _, err := s.launchctl(ctx, "print", target); err == nil {
		_, err := s.launchctl(ctx, "kickstart", "-k", target)
		return err
	}
	_, err := s.launchctl(ctx, "bootstrap", "system", plistPath)
	return err
}

// uninstallDarwinApp stops the app daemon and removes its files; the
// state folder (keys and network) stays.
func uninstallDarwinApp(ctx context.Context, s sysOps) ([]string, error) {
	if s.euid() != 0 {
		return nil, fmt.Errorf("%w: sudo openscale app uninstall-service", ErrNeedsRoot)
	}
	plistPath := launchd.Path(DarwinAppLabel)
	if err := checkMarkedPlist(s, plistPath, darwinAppMarker); err != nil {
		return nil, err
	}
	var notes []string
	target := launchd.Target(DarwinAppLabel)
	if _, err := s.launchctl(ctx, "print", target); err == nil {
		_, _ = s.launchctl(ctx, "bootout", target)
	}
	for _, p := range []string{plistPath, DarwinAppBinary} {
		if err := os.Remove(s.path(p)); err == nil {
			notes = append(notes, p+" kaldırıldı.")
		} else if !errors.Is(err, fs.ErrNotExist) {
			return notes, err
		}
	}
	if removed, err := removeOwned(s, darwinAppSyslog); err != nil {
		return notes, err
	} else if removed {
		notes = append(notes, darwinAppSyslog+" kaldırıldı.")
	}
	notes = append(notes, "Durum klasörü (anahtarlar ve ağ) "+DarwinAppStateDir+" ve "+darwinAppLog+" yerinde bırakıldı.")
	return notes, nil
}

// darwinAppInstalled reports whether the app daemon file is there.
func darwinAppInstalled(s sysOps) bool { return s.exists(launchd.Path(DarwinAppLabel)) }
