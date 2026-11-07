package svcmgr

// The macOS side of the package (#159, ADR-0100): the device role as the
// launch daemon com.openscale.device. Like systemd.go it is plain file and
// command work behind sysOps, so the tests run on every system against a
// temporary root and a recorded command list; svcmgr_darwin.go wires the
// real system. A Mac runs the tunnel only; the coordinator belongs on a
// Linux server or the Windows service (ADR-0005).

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/openscale/openscale/internal/launchd"
)

// Paths of a macOS installation. /var/db is where macOS keeps daemon
// state; /usr/local/bin is outside the sealed system volume and root-owned
// on a fresh system (CheckTrustedPath refuses it when a package manager
// gave it to a user).
const (
	DarwinDeviceStateDir = "/var/db/openscale/device"
	darwinDeviceLabel    = "com.openscale.device"
	darwinDeviceLog      = "/var/log/openscale-device.log"
	darwinNewsyslogConf  = "/etc/newsyslog.d/openscale.conf"
	// darwinInterface lets wireguard-go pick the first free utun unit.
	darwinInterface = "utun"
	// darwinPlistMarker is the comment that marks the daemon file as
	// written by "service install".
	darwinPlistMarker = "Installed by openscale service install; openscale service uninstall removes it."
)

// ErrDarwinCoordinator is returned for the coordinator role on macOS.
var ErrDarwinCoordinator = errors.New("macOS'ta yalnızca cihaz servisi kurulur; koordinatörü bir Linux sunucuda veya Windows servisinde çalıştırın")

// darwinDeviceJob is the launch daemon of the device role. It runs as
// root (utun, routes and pf need it), restarts after a crash but not after
// a clean stop, and logs to a root-only file rotated by newsyslog.
func darwinDeviceJob(bin, params, stateDir string) launchd.Job {
	return launchd.Job{
		Label:              darwinDeviceLabel,
		Program:            []string{bin, "up", "--config", params},
		Marker:             darwinPlistMarker,
		RunAtLoad:          true,
		KeepAliveOnFailure: true,
		ThrottleInterval:   10,
		ExitTimeOut:        30,
		Umask:              0o077,
		WorkingDirectory:   stateDir,
		StdoutPath:         darwinDeviceLog,
		StderrPath:         darwinDeviceLog,
		Env:                map[string]string{"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
	}
}

// darwinNewsyslog rotates the daemon log: 5 files of up to 10 MB,
// compressed, readable by root only.
func darwinNewsyslog() string {
	return installMarker + "\n# logfilename\t\t\t[owner:group]\tmode\tcount\tsize(KB)\twhen\tflags\n" +
		darwinDeviceLog + "\troot:wheel\t600\t5\t10240\t*\tJ\n"
}

func (s sysOps) launchctl(ctx context.Context, args ...string) ([]byte, error) {
	return s.run(ctx, "launchctl", args...)
}

// loadedDarwin reports whether launchd has the daemon loaded.
func loadedDarwin(ctx context.Context, s sysOps) bool {
	_, err := s.launchctl(ctx, "print", launchd.Target(darwinDeviceLabel))
	return err == nil
}

func normalizeDarwin(o Options) (Options, error) {
	if o.Role == "" {
		o.Role = RoleDevice
	}
	if o.Role != RoleDevice {
		return o, ErrDarwinCoordinator
	}
	if o.StateDir == "" {
		o.StateDir = DarwinDeviceStateDir
	}
	if o.Interface == "" {
		o.Interface = darwinInterface
	}
	return o.normalize()
}

// installDarwin installs or updates the device daemon.
func installDarwin(ctx context.Context, s sysOps, o Options) (Result, error) {
	o, err := normalizeDarwin(o)
	if err != nil {
		return Result{}, err
	}
	if s.euid() != 0 {
		return Result{}, fmt.Errorf("%w: sudo openscale service install", ErrNeedsRoot)
	}
	var res Result
	bin, note, err := installBinary(s)
	if err != nil {
		return res, err
	}
	res.Binary = bin
	if note != "" {
		res.Notes = append(res.Notes, note)
	}
	if err := s.trusted(s.path(bin)); err != nil {
		return res, fmt.Errorf("servis programı güvenli bir yerde değil (F-124): %w", err)
	}
	if err := prepareStateDir(ctx, s, o); err != nil {
		return res, err
	}
	params := paramsDir + "/" + string(o.Role) + ".json"
	if err := writeParams(s, params, o); err != nil {
		return res, err
	}
	plist, err := launchd.Plist(darwinDeviceJob(bin, params, o.StateDir))
	if err != nil {
		return res, err
	}
	plistPath := launchd.Path(darwinDeviceLabel)
	if err := checkOwnedPlist(s, plistPath); err != nil {
		return res, err
	}
	if err := writeFile(s, plistPath, plist, 0o644); err != nil {
		return res, err
	}
	if err := writeFile(s, darwinNewsyslogConf, []byte(darwinNewsyslog()), 0o644); err != nil {
		return res, err
	}
	res.Notes = append(res.Notes, installSystemAutostart(s, "darwin", bin)...) // ADR-0194
	target := launchd.Target(darwinDeviceLabel)
	// enable clears an earlier "launchctl disable", so the daemon loads at
	// boot again.
	if _, err := s.launchctl(ctx, "enable", target); err != nil {
		return res, fmt.Errorf("launchctl enable: %w", err)
	}
	joined, why := joinedLinux(s, o)
	switch {
	case !joined:
		res.Notes = append(res.Notes, why+"; servis kuruldu ama başlatılmadı. Katıldıktan sonra: sudo openscale service start")
	case o.NoStart:
		res.Notes = append(res.Notes, "Servis açılışta başlayacak; şimdi başlatmak için: sudo openscale service start")
	default:
		// A loaded daemon keeps its old property list until it is
		// unloaded; bootout + bootstrap picks up new parameters.
		if loadedDarwin(ctx, s) {
			_, _ = s.launchctl(ctx, "bootout", target)
		}
		if _, err := s.launchctl(ctx, "bootstrap", "system", plistPath); err != nil {
			return res, fmt.Errorf("launchctl bootstrap: %w", err)
		}
		res.Started = true
	}
	return res, nil
}

// checkOwnedPlist refuses to overwrite a daemon file that "service
// install" did not write (for example one the owner made by hand).
func checkOwnedPlist(s sysOps, p string) error {
	data, err := os.ReadFile(s.path(p))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !launchd.HasMarker(data, darwinPlistMarker) {
		return fmt.Errorf("%s elle yazılmış görünüyor; üzerine yazılmadı (silip yeniden deneyin)", p)
	}
	return nil
}

func controlDarwin(ctx context.Context, s sysOps, verb string, r Role) error {
	if r != RoleDevice {
		return ErrDarwinCoordinator
	}
	if s.euid() != 0 {
		return fmt.Errorf("%w: sudo openscale service %s", ErrNeedsRoot, verb)
	}
	plistPath := launchd.Path(darwinDeviceLabel)
	if !s.exists(plistPath) {
		return errors.New("servis kurulu değil; önce: sudo openscale service install")
	}
	target := launchd.Target(darwinDeviceLabel)
	loaded := loadedDarwin(ctx, s)
	switch verb {
	case "start":
		if loaded {
			_, err := s.launchctl(ctx, "kickstart", target)
			return err
		}
		_, err := s.launchctl(ctx, "bootstrap", "system", plistPath)
		return err
	case "stop":
		// Unloading stops the daemon until the next boot or start, like
		// "systemctl stop"; KeepAlive would restart a killed one.
		if !loaded {
			return nil
		}
		_, err := s.launchctl(ctx, "bootout", target)
		return err
	case "restart":
		if loaded {
			_, err := s.launchctl(ctx, "kickstart", "-k", target)
			return err
		}
		_, err := s.launchctl(ctx, "bootstrap", "system", plistPath)
		return err
	}
	return fmt.Errorf("bilinmeyen işlem %q", verb)
}

func statusDarwin(ctx context.Context, s sysOps, r Role) (Status, error) {
	if r != RoleDevice {
		return Status{}, ErrDarwinCoordinator
	}
	plistPath := launchd.Path(darwinDeviceLabel)
	st := Status{Installed: s.exists(plistPath)}
	if !st.Installed {
		st.State = "kurulu değil"
		return st, nil
	}
	st.Binary = plistPath
	disabled, _ := s.launchctl(ctx, "print-disabled", "system")
	st.Enabled = !launchd.Disabled(disabled, darwinDeviceLabel)
	out, err := s.launchctl(ctx, "print", launchd.Target(darwinDeviceLabel))
	if err != nil {
		st.State = "yüklü değil (durdurulmuş)"
		return st, nil
	}
	p := launchd.ParsePrint(out)
	st.State = p.State
	if st.State == "" {
		st.State = "yüklü"
	}
	st.PID = p.PID
	st.Running = p.State == "running" && p.PID > 0
	return st, nil
}

func uninstallDarwin(ctx context.Context, s sysOps, r Role) ([]string, error) {
	if r != RoleDevice {
		return nil, ErrDarwinCoordinator
	}
	if s.euid() != 0 {
		return nil, fmt.Errorf("%w: sudo openscale service uninstall", ErrNeedsRoot)
	}
	var notes []string
	plistPath := launchd.Path(darwinDeviceLabel)
	if err := checkOwnedPlist(s, plistPath); err != nil {
		return nil, err
	}
	if loadedDarwin(ctx, s) {
		_, _ = s.launchctl(ctx, "bootout", launchd.Target(darwinDeviceLabel))
	}
	if err := os.Remove(s.path(plistPath)); err == nil {
		notes = append(notes, plistPath+" kaldırıldı.")
	} else if !errors.Is(err, fs.ErrNotExist) {
		return notes, err
	}
	if removed, err := removeOwned(s, darwinNewsyslogConf); err != nil {
		return notes, err
	} else if removed {
		notes = append(notes, darwinNewsyslogConf+" kaldırıldı.")
	}
	autoNotes, _ := removeSystemAutostart(s, "darwin") // ADR-0194
	notes = append(notes, autoNotes...)
	notes = append(notes, "Durum klasörü (anahtarlar), "+paramsDir+"/"+string(r)+".json ve "+darwinDeviceLog+" yerinde bırakıldı.")
	return notes, nil
}
