package osnet

// The macOS persistent kill switch (#73, ADR-0100; the macOS counterpart
// of ADR-0023). The rules live in the pf anchor "com.openscale"; pf rules
// live in the kernel, so they stay when OpenScale crashes or is killed and
// only an explicit removal takes them away. The main ruleset is the
// system's /etc/pf.conf with one extra line that evaluates the anchor; pf
// is enabled with a reference token (pfctl -E) so OpenScale never turns
// off a pf that someone else needs. A reboot clears the kernel's rules,
// so the configuration is saved and the optional launch daemon
// com.openscale.killswitch restores it at boot (#74). Untagged so the
// rules and the command sequence are tested on every platform;
// killswitch_darwin.go wires it to the real system.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/launchd"
)

const (
	// pfAnchor holds every kill switch rule.
	pfAnchor = "com.openscale"
	// pfAnchorLine is appended to the main ruleset so pf evaluates the
	// anchor.
	pfAnchorLine = `anchor "com.openscale"`
	// pfSTUNSubAnchor is evaluated inside "com.openscale" (g3_opsec.go
	// loads it as "com.openscale/stun").
	pfSTUNSubAnchor = "stun"
	pfConfPath      = "/etc/pf.conf"
	maxPFConf       = 1 << 20
	pfStateFile     = "killswitch.json"
	// pfBootLabel is the launch daemon that restores the kill switch at
	// boot.
	pfBootLabel = "com.openscale.killswitch"
	// pfBootMarker marks the boot daemon file as OpenScale's.
	pfBootMarker = "openscale killswitch boot: OpenScale kill switch geri yükleyicisi (ADR-0100)"
)

// ErrCaptiveUnsupportedDarwin explains why the captive portal exception
// (#85) is missing on macOS: pf tables have no per-entry timeout, so an
// exception would outlive a crashed or finished OpenScale process.
var ErrCaptiveUnsupportedDarwin = errors.New("macOS'ta giriş sayfası istisnası yok: pf tablolarında süreli kayıt olmadığından istisna OpenScale kapansa da açık kalırdı; giriş sayfası için geçici olarak 'openscale killswitch off' kullanın")

// lanList renders the local ranges of one family as a pf address list.
func lanList(v6 bool) string {
	src := lanPrefixes4
	if v6 {
		src = lanPrefixes6
	}
	out := make([]string, len(src))
	for i, p := range src {
		out[i] = p.Masked().String()
	}
	return "{ " + strings.Join(out, ", ") + " }"
}

// pfMaxStateFile bounds the saved configuration.
const pfMaxStateFile = 4 << 10

// validLaunchdExe reports whether exe can be the boot daemon's program:
// an absolute path of plain characters.
func validLaunchdExe(exe string) bool {
	if !strings.HasPrefix(exe, "/") || len(exe) > 1024 {
		return false
	}
	return !strings.ContainsAny(exe, " \t\n\r\"'\\$%;`<>&")
}

// pfKillSwitchRules returns the anchor's ruleset: the pf counterpart of
// the WFP plan (killSwitchPlan) and the nftables table. Every rule is
// "quick", so the first match decides and the order below is the
// priority. The permits are loopback, the tunnel interface, DHCP, DHCPv6,
// neighbor discovery, OpenScale's own connections and, if allowed, the
// local network; DNS outside the tunnel is blocked for every program.
//
// pf cannot match a program path (KillSwitchConfig.AppPath is ignored):
// OpenScale's own sockets are matched by their owner, root, and only for
// UDP (WireGuard, coordinator) and TCP to ports 80 and 443 (TCP fallback,
// captive portal check). Other root processes get the same exception;
// ADR-0100 lists this as a residual risk.
func pfKillSwitchRules(cfg KillSwitchConfig) (string, error) {
	if cfg.Interface != "" && !validDarwinIface(cfg.Interface) {
		return "", fmt.Errorf("geçersiz arayüz adı %q", cfg.Interface)
	}
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	w("# OpenScale kalıcı kill switch (ADR-0023, ADR-0100). Kaldırmak için: openscale killswitch off")
	w("pass quick on lo0 all")
	w("anchor %q", pfDNSSubAnchor) // #717 DNS zorlama (dnsenforce.go); boşken etkisiz
	if cfg.Interface != "" {
		w("pass quick on %s all", cfg.Interface)
	}
	w("pass out quick inet proto udp from any port 68 to any port 67")
	w("pass in quick inet proto udp from any port 67 to any port 68")
	w("pass out quick inet6 proto udp from any port %d to any port %d", dhcpv6ClientPort, dhcpv6ServerPort)
	w("pass in quick inet6 proto udp from any port %d to any port %d", dhcpv6ServerPort, dhcpv6ClientPort)
	// Neighbor discovery (RFC 4861) and multicast listener messages keep
	// the IPv6 link alive.
	w("pass quick inet6 proto icmp6 icmp6-type { 130, 131, 132, 133, 134, 135, 136, 137, 143 }")
	w("block drop out quick proto { tcp, udp } from any to any port { %d, %d }", dnsPort, dotPort)
	w("block drop in quick proto { tcp, udp } from any port { %d, %d } to any", dnsPort, dotPort)
	w("pass out quick proto udp from any to any user root")
	w("pass out quick proto tcp from any to any port { 80, 443 } user root")
	// WebRTC/STUN block (#625, ADR-0189): the sub-anchor is empty until
	// `openscale opsec webrtc --apply` loads "com.openscale/stun". It sits
	// after OpenScale's own exceptions, so the device's NAT discovery
	// (root) is not caught, and before the LAN permits, so a browser's
	// STUN to the internet is dropped whether or not the LAN is allowed.
	w("anchor %q", pfSTUNSubAnchor)
	if cfg.AllowLAN {
		w("pass out quick inet from any to %s", lanList(false))
		w("pass out quick inet6 from any to %s", lanList(true))
		w("pass in quick inet from %s to any", lanList(false))
		w("pass in quick inet6 from %s to any", lanList(true))
	}
	w("block drop quick all")
	return b.String(), nil
}

// pfMainRuleset is the system's pf.conf with the anchor line appended.
func pfMainRuleset(conf []byte) []byte {
	if pfReferencesAnchor(conf) {
		return conf
	}
	out := append([]byte(nil), conf...)
	if len(out) > 0 && out[len(out)-1] != '\n' {
		out = append(out, '\n')
	}
	out = append(out, "# OpenScale kill switch (ADR-0100)\n"+pfAnchorLine+"\n"...)
	return out
}

// pfReferencesAnchor reports whether a ruleset (pf.conf text or `pfctl
// -sr` output) evaluates the OpenScale anchor.
func pfReferencesAnchor(rules []byte) bool {
	s := bufio.NewScanner(bytes.NewReader(rules))
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == pfAnchorLine || strings.HasPrefix(line, pfAnchorLine+" ") {
			return true
		}
	}
	return false
}

// parsePFToken reads the reference token `pfctl -E` prints.
func parsePFToken(out []byte) (string, bool) {
	s := bufio.NewScanner(bytes.NewReader(out))
	for s.Scan() {
		k, v, ok := strings.Cut(s.Text(), ":")
		if !ok || strings.TrimSpace(k) != "Token" {
			continue
		}
		v = strings.TrimSpace(v)
		if n, err := strconv.ParseUint(v, 10, 64); err == nil && n > 0 {
			return v, true
		}
	}
	return "", false
}

// pfEnabled reports whether `pfctl -s info` says pf is enabled.
func pfEnabled(out []byte) bool {
	s := bufio.NewScanner(bytes.NewReader(out))
	for s.Scan() {
		if strings.HasPrefix(strings.TrimSpace(s.Text()), "Status: Enabled") {
			return true
		}
	}
	return false
}

// pfSaved is the saved kill switch configuration.
type pfSaved struct {
	Interface string `json:"interface,omitempty"`
	AllowLAN  bool   `json:"allow_lan,omitempty"`
	// Token is the pf reference OpenScale holds (pfctl -E).
	Token string `json:"token,omitempty"`
}

// pfKillSwitch holds the paths and system calls of the macOS kill switch;
// tests replace them so nothing touches the host.
type pfKillSwitch struct {
	run       darwinRunner
	stateDir  string
	launchDir string
	pfConf    string
	// write stores private state (0600); writePublic stores the boot
	// daemon (0644, as launchd requires).
	write       func(path string, data []byte) error
	writePublic func(path string, data []byte) error
	read        func(path string, limit int64) ([]byte, error)
	remove      func(path string) error
	exists      func(path string) bool
	mu          sync.Mutex
}

func (k *pfKillSwitch) statePath() string { return k.stateDir + "/" + pfStateFile }
func (k *pfKillSwitch) bootPath() string  { return k.launchDir + "/" + pfBootLabel + ".plist" }

func (k *pfKillSwitch) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 30*time.Second)
}

func (k *pfKillSwitch) supported() bool { return k.exists(darwinPfctl) }

func (k *pfKillSwitch) loadSaved() (pfSaved, bool, error) {
	data, err := k.read(k.statePath(), pfMaxStateFile)
	if errors.Is(err, fs.ErrNotExist) {
		return pfSaved{}, false, nil
	}
	if err != nil {
		return pfSaved{}, false, err
	}
	var s pfSaved
	if err := json.Unmarshal(data, &s); err != nil {
		return pfSaved{}, false, fmt.Errorf("kayıtlı kill switch ayarı bozuk: %w", err)
	}
	if s.Interface != "" && !validDarwinIface(s.Interface) {
		return pfSaved{}, false, errors.New("kayıtlı kill switch ayarında geçersiz arayüz adı")
	}
	if s.Token != "" {
		if _, err := strconv.ParseUint(s.Token, 10, 64); err != nil {
			s.Token = ""
		}
	}
	return s, true, nil
}

// mainReferences reports whether the loaded main ruleset evaluates the
// anchor.
func (k *pfKillSwitch) mainReferences(ctx context.Context) (bool, error) {
	out, err := k.run(ctx, nil, darwinPfctl, "-s", "rules")
	if err != nil {
		return false, fmt.Errorf("pf kuralları okunamadı: %w", err)
	}
	return pfReferencesAnchor(out), nil
}

// install loads the anchor, hooks it into the main ruleset, enables pf
// with OpenScale's own reference and saves cfg. The anchor is loaded
// first: until the main ruleset points at it, it changes nothing, and
// from the moment it does, it is complete.
func (k *pfKillSwitch) install(cfg KillSwitchConfig) error {
	rules, err := pfKillSwitchRules(cfg)
	if err != nil {
		return err
	}
	if !k.supported() {
		return errors.New("kill switch için pfctl gerekli; bulunamadı")
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	ctx, cancel := k.ctx()
	defer cancel()
	prev, _, _ := k.loadSaved()
	if _, err := k.run(ctx, []byte(rules), darwinPfctl, "-a", pfAnchor, "-f", "-"); err != nil {
		return fmt.Errorf("kill switch kuralları yüklenemedi: %w", err)
	}
	refs, err := k.mainReferences(ctx)
	if err != nil {
		return err
	}
	if !refs {
		conf, err := k.read(k.pfConf, maxPFConf)
		if err != nil {
			return fmt.Errorf("%s okunamadı: %w", k.pfConf, err)
		}
		if _, err := k.run(ctx, pfMainRuleset(conf), darwinPfctl, "-f", "-"); err != nil {
			return fmt.Errorf("pf ana kural kümesi yüklenemedi: %w", err)
		}
	}
	out, err := k.run(ctx, nil, darwinPfctl, "-E")
	if err != nil {
		return fmt.Errorf("pf etkinleştirilemedi: %w", err)
	}
	token, ok := parsePFToken(out)
	if !ok {
		return errors.New("pf etkinleştirildi ama başvuru belirteci okunamadı")
	}
	// One reference is enough: release the one an earlier install took.
	// After a reboot it is stale and pf refuses it, which is fine.
	if prev.Token != "" && prev.Token != token {
		_, _ = k.run(ctx, nil, darwinPfctl, "-X", prev.Token)
	}
	data, err := json.Marshal(pfSaved{Interface: cfg.Interface, AllowLAN: cfg.AllowLAN, Token: token})
	if err != nil {
		return err
	}
	if err := k.write(k.statePath(), data); err != nil {
		// The rules are in place; only the restore after a reboot and the
		// release of the pf reference are missing.
		return fmt.Errorf("kill switch kuruldu ama açılış için kaydedilemedi: %w", err)
	}
	return nil
}

// pfMissing reports whether a pfctl error says the anchor does not exist.
func pfMissing(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "No such file or directory") || strings.Contains(s, "does not exist")
}

// removeAll flushes the anchor, takes the anchor line out of the main
// ruleset by reloading the system's pf.conf, releases OpenScale's pf
// reference (pf turns off only if nobody else holds one) and deletes the
// saved configuration. Nothing installed is not an error.
func (k *pfKillSwitch) removeAll() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	var errs []error
	saved, _, _ := k.loadSaved()
	if k.supported() {
		ctx, cancel := k.ctx()
		defer cancel()
		if _, err := k.run(ctx, nil, darwinPfctl, "-a", pfAnchor, "-F", "all"); err != nil && !pfMissing(err) {
			errs = append(errs, fmt.Errorf("kill switch kuralları silinemedi: %w", err))
		}
		if refs, err := k.mainReferences(ctx); err != nil {
			errs = append(errs, err)
		} else if refs {
			if _, err := k.run(ctx, nil, darwinPfctl, "-f", k.pfConf); err != nil {
				errs = append(errs, fmt.Errorf("pf ana kural kümesi geri yüklenemedi: %w", err))
			}
		}
		if saved.Token != "" {
			_, _ = k.run(ctx, nil, darwinPfctl, "-X", saved.Token)
		}
	}
	if err := k.remove(k.statePath()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		errs = append(errs, fmt.Errorf("kayıtlı kill switch ayarı silinemedi: %w", err))
	}
	return errors.Join(errs...)
}

// installed reports whether the kill switch blocks traffic now: the anchor
// holds the final block, the main ruleset evaluates it and pf is on.
func (k *pfKillSwitch) installed() (bool, error) {
	if !k.supported() {
		return false, nil
	}
	ctx, cancel := k.ctx()
	defer cancel()
	out, err := k.run(ctx, nil, darwinPfctl, "-a", pfAnchor, "-s", "rules")
	if err != nil {
		if pfMissing(err) {
			return false, nil
		}
		return false, fmt.Errorf("kill switch durumu okunamadı: %w", err)
	}
	if !bytes.Contains(out, []byte("block drop quick all")) {
		return false, nil
	}
	refs, err := k.mainReferences(ctx)
	if err != nil || !refs {
		return false, err
	}
	info, err := k.run(ctx, nil, darwinPfctl, "-s", "info")
	if err != nil {
		return false, fmt.Errorf("pf durumu okunamadı: %w", err)
	}
	return pfEnabled(info), nil
}

func (k *pfKillSwitch) restore() (bool, error) {
	s, ok, err := k.loadSaved()
	if err != nil || !ok {
		return false, err
	}
	return true, k.install(KillSwitchConfig{Interface: s.Interface, AllowLAN: s.AllowLAN})
}

// bootJob is the launch daemon that restores the kill switch at boot.
// launchd starts daemons early, but macOS has no ordering point before
// the network comes up (unlike systemd's network-pre.target): a short
// window at boot remains (ADR-0100).
func bootJob(exe string) launchd.Job {
	return launchd.Job{
		Label:     pfBootLabel,
		Program:   []string{exe, "killswitch", "restore"},
		Marker:    pfBootMarker,
		RunAtLoad: true,
		Env:       map[string]string{"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
	}
}

func (k *pfKillSwitch) bootSupported() bool { return k.exists(darwinLaunchctl) }

func (k *pfKillSwitch) enableBoot(exe string) error {
	if !validLaunchdExe(exe) {
		return fmt.Errorf("program yolu açılış görevine yazılamaz: %q", exe)
	}
	data, err := launchd.Plist(bootJob(exe))
	if err != nil {
		return err
	}
	if err := k.writePublic(k.bootPath(), data); err != nil {
		return fmt.Errorf("açılış görevi yazılamadı: %w", err)
	}
	// Files in /Library/LaunchDaemons load at every boot by themselves;
	// enable only clears an earlier "launchctl disable".
	ctx, cancel := k.ctx()
	defer cancel()
	if _, err := k.run(ctx, nil, darwinLaunchctl, "enable", launchd.Target(pfBootLabel)); err != nil {
		return err
	}
	return nil
}

func (k *pfKillSwitch) disableBoot() error {
	data, err := k.read(k.bootPath(), 64<<10)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !launchd.HasMarker(data, pfBootMarker) {
		return fmt.Errorf("%s OpenScale'e ait değil; dokunulmadı", k.bootPath())
	}
	ctx, cancel := k.ctx()
	defer cancel()
	// Loaded only if it ran since boot; not loaded is fine.
	_, _ = k.run(ctx, nil, darwinLaunchctl, "bootout", launchd.Target(pfBootLabel))
	if err := k.remove(k.bootPath()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("açılış görevi silinemedi: %w", err)
	}
	return nil
}

func (k *pfKillSwitch) bootEnabled() (bool, error) {
	return k.exists(k.bootPath()), nil
}
