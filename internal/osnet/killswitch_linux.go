//go:build linux

package osnet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/securefile"
)

// The Linux kill switch (ADR-0023, Linux bölümü) is the nftables table
// "inet openscale_killswitch". nftables tables live in the kernel, so the
// table stays when OpenScale crashes or is killed; only an explicit
// removal ("openscale killswitch off", leaving the exit node, turning the
// kill switch off) takes it away. A reboot clears the kernel's tables, so
// the configuration is also saved, and the optional boot unit
// (openscale-killswitch.service) restores it before the network comes up
// (#74).

const (
	ksMaxStateFile = 4 << 10
	ksUnitName     = "openscale-killswitch.service"
)

// ksLinux holds the paths and system calls the Linux kill switch uses;
// tests replace them so nothing touches the host.
type ksLinux struct {
	ops      sysOps
	stateDir string
	unitDir  string
	write    func(path string, data []byte) error
	readFile func(path string, limit int64) ([]byte, error)
	remove   func(path string) error
	mu       sync.Mutex
}

var hostKillSwitch = &ksLinux{
	ops:      hostOps,
	stateDir: "/var/lib/openscale",
	unitDir:  "/etc/systemd/system",
	write:    securefile.Replace,
	readFile: securefile.ReadPrivate,
	remove:   os.Remove,
}

// ksSaved is the saved configuration the boot unit restores.
type ksSaved struct {
	Interface string `json:"interface,omitempty"`
	AllowLAN  bool   `json:"allow_lan,omitempty"`
}

func (k *ksLinux) statePath() string { return filepath.Join(k.stateDir, "killswitch.json") }
func (k *ksLinux) unitPath() string  { return filepath.Join(k.unitDir, ksUnitName) }

// KillSwitchSupported reports whether this system has a persistent kill
// switch: on Linux, whether nft is installed.
func KillSwitchSupported() bool { return hostKillSwitch.ops.has("nft") }

// InstallKillSwitch replaces the kill switch table with the rules for cfg
// in one nft transaction and saves cfg for the boot unit.
func InstallKillSwitch(cfg KillSwitchConfig) error { return hostKillSwitch.install(cfg) }

// RemoveKillSwitch deletes the table and the saved configuration. Nothing
// installed is not an error.
func RemoveKillSwitch() error { return hostKillSwitch.removeAll() }

// KillSwitchInstalled reports whether the kill switch table exists.
func KillSwitchInstalled() (bool, error) { return hostKillSwitch.installed() }

// RestoreKillSwitch installs the saved kill switch again, if one is saved
// (the boot unit runs this before the network starts). It reports whether
// a saved configuration was found.
func RestoreKillSwitch() (bool, error) { return hostKillSwitch.restore() }

// KillSwitchBootSupported reports whether the kill switch can be restored
// at boot: systemd is needed.
func KillSwitchBootSupported() bool { return hostKillSwitch.ops.has("systemctl") }

// EnableKillSwitchBoot installs and enables the boot unit that restores
// the saved kill switch before the network starts (#74). exe is the
// absolute path of the openscale program.
func EnableKillSwitchBoot(exe string) error { return hostKillSwitch.enableBoot(exe) }

// DisableKillSwitchBoot disables and removes the boot unit.
func DisableKillSwitchBoot() error { return hostKillSwitch.disableBoot() }

// KillSwitchBootEnabled reports whether the boot unit is installed.
func KillSwitchBootEnabled() (bool, error) { return hostKillSwitch.bootEnabled() }

// AllowCaptivePortal opens the kill switch for HTTP and HTTPS to the given
// local gateway addresses for d (#85). The kernel removes the exception
// when d ends, also if OpenScale is no longer running.
func AllowCaptivePortal(addrs []netip.Addr, d time.Duration) error {
	return hostKillSwitch.allowCaptive(addrs, d)
}

// RevokeCaptivePortal ends a captive portal exception early.
func RevokeCaptivePortal() error { return hostKillSwitch.revokeCaptive() }

func (k *ksLinux) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 30*time.Second)
}

func (k *ksLinux) install(cfg KillSwitchConfig) error {
	script, err := nftKillSwitchScript(cfg)
	if err != nil {
		return err
	}
	if !k.ops.has("nft") {
		return errors.New("kill switch için nft (nftables) gerekli; bulunamadı")
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	ctx, cancel := k.ctx()
	defer cancel()
	if _, err := k.ops.run(ctx, []byte(script), "nft", "-f", "-"); err != nil {
		return fmt.Errorf("kill switch kuralları yüklenemedi: %w", err)
	}
	data, err := json.Marshal(ksSaved{Interface: cfg.Interface, AllowLAN: cfg.AllowLAN})
	if err != nil {
		return err
	}
	if err := k.write(k.statePath(), data); err != nil {
		// The table is in place; only the restore after a reboot is
		// missing. Report it, the protection itself works.
		return fmt.Errorf("kill switch kuruldu ama açılış için kaydedilemedi: %w", err)
	}
	return nil
}

// nftMissing reports whether an nft error says the object does not exist.
func nftMissing(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "No such file or directory") || strings.Contains(s, "does not exist")
}

func (k *ksLinux) removeAll() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	var errs []error
	if k.ops.has("nft") {
		ctx, cancel := k.ctx()
		defer cancel()
		if _, err := k.ops.run(ctx, nil, "nft", "delete", "table", "inet", killSwitchTable); err != nil && !nftMissing(err) {
			errs = append(errs, fmt.Errorf("kill switch tablosu silinemedi: %w", err))
		}
	}
	if err := k.remove(k.statePath()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		errs = append(errs, fmt.Errorf("kayıtlı kill switch ayarı silinemedi: %w", err))
	}
	return errors.Join(errs...)
}

func (k *ksLinux) installed() (bool, error) {
	if !k.ops.has("nft") {
		return false, nil
	}
	ctx, cancel := k.ctx()
	defer cancel()
	_, err := k.ops.run(ctx, nil, "nft", "list", "table", "inet", killSwitchTable)
	switch {
	case err == nil:
		return true, nil
	case nftMissing(err):
		return false, nil
	default:
		return false, fmt.Errorf("kill switch durumu okunamadı: %w", err)
	}
}

func (k *ksLinux) loadSaved() (KillSwitchConfig, bool, error) {
	data, err := k.readFile(k.statePath(), ksMaxStateFile)
	if errors.Is(err, fs.ErrNotExist) {
		return KillSwitchConfig{}, false, nil
	}
	if err != nil {
		return KillSwitchConfig{}, false, err
	}
	var s ksSaved
	if err := json.Unmarshal(data, &s); err != nil {
		return KillSwitchConfig{}, false, fmt.Errorf("kayıtlı kill switch ayarı bozuk: %w", err)
	}
	if s.Interface != "" && !validNftIfname(s.Interface) {
		return KillSwitchConfig{}, false, errors.New("kayıtlı kill switch ayarında geçersiz arayüz adı")
	}
	return KillSwitchConfig{Interface: s.Interface, AllowLAN: s.AllowLAN}, true, nil
}

func (k *ksLinux) restore() (bool, error) {
	cfg, ok, err := k.loadSaved()
	if err != nil || !ok {
		return false, err
	}
	return true, k.install(cfg)
}

// validUnitExe reports whether exe can be written into ExecStart without
// quoting: an absolute path of plain characters.
func validUnitExe(exe string) bool {
	if !filepath.IsAbs(exe) || len(exe) > 4096 {
		return false
	}
	return !strings.ContainsAny(exe, " \t\n\r\"'\\$%;`")
}

// killSwitchUnit is the boot unit. It runs before network-pre.target, the
// same place as the distribution's nftables.service, so no interface has
// an address before the kill switch is back.
func killSwitchUnit(exe string) string {
	return `[Unit]
Description=OpenScale kalıcı kill switch (açılışta ağdan önce geri yüklenir)
DefaultDependencies=no
Wants=network-pre.target
Before=network-pre.target shutdown.target
Conflicts=shutdown.target
RequiresMountsFor=/var/lib/openscale
ConditionPathExists=/var/lib/openscale/killswitch.json

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=` + exe + ` killswitch restore

[Install]
WantedBy=sysinit.target
`
}

func (k *ksLinux) enableBoot(exe string) error {
	if !validUnitExe(exe) {
		return fmt.Errorf("program yolu açılış birimine yazılamaz: %q", exe)
	}
	if !k.ops.has("systemctl") {
		return errors.New("açılış koruması için systemd (systemctl) gerekli; bulunamadı")
	}
	if err := k.write(k.unitPath(), []byte(killSwitchUnit(exe))); err != nil {
		return fmt.Errorf("açılış birimi yazılamadı: %w", err)
	}
	ctx, cancel := k.ctx()
	defer cancel()
	if _, err := k.ops.run(ctx, nil, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	if _, err := k.ops.run(ctx, nil, "systemctl", "enable", ksUnitName); err != nil {
		return err
	}
	return nil
}

func (k *ksLinux) disableBoot() error {
	ctx, cancel := k.ctx()
	defer cancel()
	var errs []error
	if k.ops.has("systemctl") {
		_, _ = k.ops.run(ctx, nil, "systemctl", "disable", ksUnitName)
	}
	if err := k.remove(k.unitPath()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		errs = append(errs, fmt.Errorf("açılış birimi silinemedi: %w", err))
	}
	if k.ops.has("systemctl") {
		if _, err := k.ops.run(ctx, nil, "systemctl", "daemon-reload"); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (k *ksLinux) bootEnabled() (bool, error) {
	_, err := k.ops.read(k.unitPath())
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (k *ksLinux) allowCaptive(addrs []netip.Addr, d time.Duration) error {
	addrs, err := validCaptive(addrs, d)
	if err != nil {
		return err
	}
	on, err := k.installed()
	if err != nil {
		return err
	}
	if !on {
		return ErrKillSwitchNotInstalled
	}
	ctx, cancel := k.ctx()
	defer cancel()
	if _, err := k.ops.run(ctx, nil, "nft", nftCaptiveArgs(addrs, d)...); err != nil {
		return fmt.Errorf("giriş sayfası istisnası eklenemedi: %w", err)
	}
	return nil
}

func (k *ksLinux) revokeCaptive() error {
	if !k.ops.has("nft") {
		return nil
	}
	ctx, cancel := k.ctx()
	defer cancel()
	if _, err := k.ops.run(ctx, nil, "nft", "flush", "set", "inet", killSwitchTable, captiveSet); err != nil && !nftMissing(err) {
		return fmt.Errorf("giriş sayfası istisnası kaldırılamadı: %w", err)
	}
	return nil
}
