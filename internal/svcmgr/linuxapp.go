package svcmgr

// The Linux desktop app's background service (ADR-0234): the same
// service the Windows and macOS apps run (internal/service: panel, tray
// API, set-up in the panel, tunnel), here as the systemd unit
// openscale-app.service ("openscale service run" as root). The tray
// ("openscale tray") runs as the signed-in user and talks to it only
// through /run/openscale/tray.sock. It is the desktop alternative to the
// command line device unit (openscale-device.service, "openscale up");
// the two never run side by side. Like appdaemon.go the work is plain
// file and command work behind sysOps, so it is tested on every system.

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
)

// Names and paths of the Linux app service.
const (
	LinuxAppUnit     = "openscale-app.service"
	LinuxAppStateDir = "/var/lib/openscale/app"
	// LinuxAppRuntimeDir holds the tray socket; systemd creates it
	// (root, 0755) when the unit starts and removes it when it stops.
	LinuxAppRuntimeDir = "/run/openscale"
	linuxAppMarker     = "# Installed by \"openscale app install-service\"; \"openscale app uninstall-service\" removes it."
)

// ErrLinuxDeviceUnit: the command line device unit is installed; two
// tunnels on one computer would fight over routes and DNS.
var ErrLinuxDeviceUnit = errors.New("komut satırı cihaz servisi (openscale-device.service) kurulu; uygulama servisi yanına kurulmaz. Önce: sudo openscale service uninstall --role device")

// LinuxAppUnitFile renders the unit for program bin. The service needs
// root for the tunnel, routes, nftables, DNS and the kill switch's own
// boot unit, so the file system is not made read-only; the rest of the
// usual hardening applies.
func LinuxAppUnitFile(bin string) (string, error) {
	if !strings.HasPrefix(bin, "/") || strings.ContainsAny(bin, " \t\r\n\"'\\%$;") {
		return "", fmt.Errorf("servis programı yolu birim dosyasına yazılamaz: %q", bin)
	}
	return linuxAppMarker + `
# OpenScale desktop app service (ADR-0234): panel, tray API and tunnel.
# The tray talks to it through /run/openscale/tray.sock.
[Unit]
Description=OpenScale app service (panel, tray and tunnel)
After=network-online.target time-sync.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=` + bin + ` service run
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
UMask=0077
RuntimeDirectory=openscale
RuntimeDirectoryMode=0755
StateDirectory=openscale/app
StateDirectoryMode=0700
Environment=PATH=/usr/sbin:/usr/bin:/sbin:/bin
# No core dumps (#638, ADR-0184): the service holds the device keys.
LimitCORE=0
MemoryHigh=384M
MemoryMax=512M
TasksMax=1024
ProtectHome=read-only
PrivateTmp=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
`, nil
}

func linuxAppUnitPath() string { return etcUnitDir + "/" + LinuxAppUnit }

// linuxDeviceInstalled reports whether the device unit exists anywhere.
func linuxDeviceInstalled(s sysOps) bool {
	for _, dir := range []string{pkgUnitDir, pkgUnitDirOld, etcUnitDir} {
		if s.exists(dir + "/" + RoleDevice.Unit()) {
			return true
		}
	}
	return false
}

// checkLinuxAppUnit refuses to overwrite a unit file someone else wrote.
func checkLinuxAppUnit(s sysOps) error {
	data, err := os.ReadFile(s.path(linuxAppUnitPath()))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if line, _, _ := strings.Cut(string(data), "\n"); strings.TrimRight(line, "\r") != linuxAppMarker {
		return fmt.Errorf("%s elle yazılmış görünüyor; üzerine yazılmadı", linuxAppUnitPath())
	}
	return nil
}

// installLinuxApp installs or updates the app unit and (re)starts it.
func installLinuxApp(ctx context.Context, s sysOps) (Result, error) {
	var res Result
	if s.euid() != 0 {
		return res, fmt.Errorf("%w: sudo openscale app install-service", ErrNeedsRoot)
	}
	if linuxDeviceInstalled(s) {
		return res, ErrLinuxDeviceUnit
	}
	if err := checkLinuxAppUnit(s); err != nil {
		return res, err
	}
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
	if err := prepareStateDir(ctx, s, Options{Role: RoleDevice, StateDir: LinuxAppStateDir}); err != nil {
		return res, err
	}
	unit, err := LinuxAppUnitFile(bin)
	if err != nil {
		return res, err
	}
	if err := writeFile(s, linuxAppUnitPath(), []byte(unit), 0o644); err != nil {
		return res, err
	}
	res.Notes = append(res.Notes, installSystemAutostart(s, "linux", bin)...) // ADR-0194
	if _, err := s.systemctl(ctx, "daemon-reload"); err != nil {
		return res, fmt.Errorf("systemctl daemon-reload: %w", err)
	}
	if _, err := s.systemctl(ctx, "enable", LinuxAppUnit); err != nil {
		return res, fmt.Errorf("systemctl enable: %w", err)
	}
	// restart runs the new program when the unit already ran.
	if _, err := s.systemctl(ctx, "restart", LinuxAppUnit); err != nil {
		return res, fmt.Errorf("systemctl restart: %w", err)
	}
	res.Started = true
	return res, nil
}

// restartLinuxApp restarts the app unit (root).
func restartLinuxApp(ctx context.Context, s sysOps) error {
	if s.euid() != 0 {
		return fmt.Errorf("%w: sudo openscale app restart-service", ErrNeedsRoot)
	}
	if !s.exists(linuxAppUnitPath()) {
		return errors.New("uygulama servisi kurulu değil")
	}
	if _, err := s.systemctl(ctx, "restart", LinuxAppUnit); err != nil {
		return fmt.Errorf("systemctl restart: %w", err)
	}
	return nil
}

// uninstallLinuxApp stops and removes the app unit; the state folder
// (keys and network) stays.
func uninstallLinuxApp(ctx context.Context, s sysOps) ([]string, error) {
	if s.euid() != 0 {
		return nil, fmt.Errorf("%w: sudo openscale app uninstall-service", ErrNeedsRoot)
	}
	if err := checkLinuxAppUnit(s); err != nil {
		return nil, err
	}
	var notes []string
	_, _ = s.systemctl(ctx, "disable", "--now", LinuxAppUnit)
	if removed, err := removeLinuxAppUnit(s); err != nil {
		return notes, err
	} else if removed {
		notes = append(notes, linuxAppUnitPath()+" kaldırıldı.")
	}
	more, err := removeSystemAutostart(s, "linux")
	notes = append(notes, more...)
	if err != nil {
		return notes, err
	}
	if _, err := s.systemctl(ctx, "daemon-reload"); err != nil {
		notes = append(notes, "systemctl daemon-reload başarısız: "+err.Error())
	}
	notes = append(notes, "Durum klasörü (anahtarlar ve ağ) "+LinuxAppStateDir+" yerinde bırakıldı.")
	return notes, nil
}

func removeLinuxAppUnit(s sysOps) (bool, error) {
	if err := checkLinuxAppUnit(s); err != nil {
		return false, err
	}
	err := os.Remove(s.path(linuxAppUnitPath()))
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

// linuxAppInstalled reports whether the app unit file is there.
func linuxAppInstalled(s sysOps) bool { return s.exists(linuxAppUnitPath()) }

// LinuxAppGroup is the group whose members may use the tray socket
// besides root; "openscale app install-service" adds the user who
// authorized it (ADR-0234). It is the operator group of the local API
// too (F-097).
const LinuxAppGroup = "openscale"

// linuxAppProgram returns the program the installed unit runs.
func linuxAppProgram(s sysOps) (string, error) {
	data, err := os.ReadFile(s.path(linuxAppUnitPath()))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "ExecStart=")
		if !ok {
			continue
		}
		bin, args, _ := strings.Cut(rest, " ")
		if args == "service run" && strings.HasPrefix(bin, "/") {
			return bin, nil
		}
	}
	return "", errors.New("uygulama servisinin programı birim dosyasında bulunamadı")
}

// validUserName refuses names a tool could read as an option.
func validUserName(name string) bool {
	if name == "" || len(name) > 64 || name[0] == '-' {
		return false
	}
	for _, c := range name {
		if c <= ' ' || c == ':' || c == '/' || c == 0x5c || c == 0x7f {
			return false
		}
	}
	return true
}

// addToLinuxAppGroup creates the group when it is missing and adds user.
// groupExists and member answer from the group database.
func addToLinuxAppGroup(ctx context.Context, s sysOps, user string, groupExists, member bool) ([]string, error) {
	if s.euid() != 0 {
		return nil, ErrNeedsRoot
	}
	if !validUserName(user) {
		return nil, fmt.Errorf("kullanıcı adı geçersiz: %q", user)
	}
	var notes []string
	if !groupExists {
		if _, err := s.run(ctx, "groupadd", "--system", LinuxAppGroup); err != nil {
			return notes, fmt.Errorf("%s grubu oluşturulamadı: %w", LinuxAppGroup, err)
		}
		notes = append(notes, LinuxAppGroup+" grubu oluşturuldu.")
	}
	if member {
		return notes, nil
	}
	if _, err := s.run(ctx, "gpasswd", "-a", user, LinuxAppGroup); err != nil {
		if _, err2 := s.run(ctx, "usermod", "-a", "-G", LinuxAppGroup, user); err2 != nil {
			return notes, fmt.Errorf("%s %s grubuna eklenemedi: %w", user, LinuxAppGroup, errors.Join(err, err2))
		}
	}
	notes = append(notes, user+" kullanıcısı "+LinuxAppGroup+" grubuna eklendi; tepsi bu kullanıcıyla servise bağlanabilir.")
	return notes, nil
}
