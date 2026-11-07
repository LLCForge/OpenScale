package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/leaktest"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/osnet"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/service"
)

// Leak protection of "openscale up" and its commands (ADR-0023, P07):
// the persistent kill switch on Linux (#72, #74), the captive portal
// exception (#85), the leak test (#77, #75, #76, #93) and cooperation with
// the host firewall (#283).

// leakSysOps are the system calls behind these commands; tests replace
// them, so no test changes the host firewall.
type leakSysOps struct {
	supported     func() bool
	elevated      func() bool
	install       func(osnet.KillSwitchConfig) error
	remove        func() error
	installed     func() (bool, error)
	restore       func() (bool, error)
	bootSupported func() bool
	bootEnable    func(exe string) error
	bootDisable   func() error
	bootEnabled   func() (bool, error)
	allowCaptive  func([]netip.Addr, time.Duration) error
	revokeCaptive func() error
	gateways      func() ([]netip.Addr, error)
	hostFirewall  func(ctx context.Context, iface, mode string) ([]osnet.HostFirewallFinding, error)
	executable    func() (string, error)
	leakGuard     func() (bool, error)
	resolvers     func() ([]osnet.SystemResolver, error)
	localAddrs    func(skip string) []netip.Addr
	prober        leaktest.Prober
	goos          string
}

var leakOps = leakSysOps{
	supported:     osnet.KillSwitchSupported,
	elevated:      killSwitch.elevated,
	install:       osnet.InstallKillSwitch,
	remove:        osnet.RemoveKillSwitch,
	installed:     osnet.KillSwitchInstalled,
	restore:       osnet.RestoreKillSwitch,
	bootSupported: osnet.KillSwitchBootSupported,
	bootEnable:    osnet.EnableKillSwitchBoot,
	bootDisable:   osnet.DisableKillSwitchBoot,
	bootEnabled:   osnet.KillSwitchBootEnabled,
	allowCaptive:  osnet.AllowCaptivePortal,
	revokeCaptive: osnet.RevokeCaptivePortal,
	gateways:      osnet.DefaultGateways4,
	hostFirewall:  osnet.CheckHostFirewall,
	executable:    executablePath,
	leakGuard:     osnet.LeakGuardInstalled,
	resolvers:     osnet.SystemResolvers,
	localAddrs:    leaktest.LocalAddrs,
	prober:        leaktest.NetProber{},
	goos:          runtime.GOOS,
}

func executablePath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}

// upLeakFlags are the leak protection flags of "openscale up".
type upLeakFlags struct {
	killSwitch *bool
	allowLAN   *bool
	hostFW     *string
}

func addUpLeakFlags(fs *flag.FlagSet) *upLeakFlags {
	return &upLeakFlags{
		killSwitch: fs.Bool("kill-switch", false, "çıkış düğümü kullanılırken kalıcı kill switch kur (Linux: nftables tablosu inet openscale_killswitch); OpenScale durur veya çökerse de trafik tünel dışına çıkmaz, kaldırmak için: openscale killswitch off"),
		allowLAN:   fs.Bool("exit-allow-lan", false, "kill switch açıkken yerel ağa izin ver (yerel ağdaki DNS yine engelli)"),
		hostFW:     fs.String("host-firewall", osnet.HostFirewallAuto, "işletim sistemi güvenlik duvarıyla uyum (Linux): auto (firewalld bölgesini bu çalışma için düzelt, diğerlerinde uyar), warn (yalnızca uyar) veya off"),
	}
}

func (l *upLeakFlags) validate(exitNode string) error {
	if err := osnet.ValidHostFirewallMode(strings.TrimSpace(*l.hostFW)); err != nil {
		return usageError("--host-firewall: %v", err)
	}
	if *l.allowLAN && !*l.killSwitch {
		return usageError("--exit-allow-lan yalnızca --kill-switch ile kullanılabilir")
	}
	if *l.killSwitch && exitNode == "" {
		return usageError("--kill-switch yalnızca --exit-node ile kullanılabilir")
	}
	if *l.killSwitch && !leakOps.supported() {
		return usageError("--kill-switch: bu sistemde kalıcı kill switch yok (Linux'ta nft gerekir)")
	}
	return nil
}

// checkHostFirewall reports host firewalls that would drop tunnel traffic.
func (l *upLeakFlags) checkHostFirewall(ctx context.Context, env *Env, iface string) {
	found, err := leakOps.hostFirewall(ctx, iface, strings.TrimSpace(*l.hostFW))
	if err != nil {
		fmt.Fprintf(env.Stderr, "uyarı: güvenlik duvarı denetlenemedi: %v\n", err)
		return
	}
	for _, f := range found {
		if f.Fixed {
			fmt.Fprintf(env.Stdout, "Güvenlik duvarı: %s\n", f.Message)
			continue
		}
		fmt.Fprintf(env.Stderr, "uyarı: %s. Düzeltmek için: %s (kapatmak için --host-firewall off)\n", f.Message, f.Fix)
	}
}

// prepare installs the kill switch before the tunnel carries anything, or
// warns about one left behind by an earlier run.
func (l *upLeakFlags) prepare(env *Env, iface string) error {
	if !*l.killSwitch {
		if on, err := leakOps.installed(); err == nil && on {
			fmt.Fprintln(env.Stderr, "uyarı: önceki bir çalışmanın kill switch'i kurulu; internet trafiği yalnızca tünelden çıkabilir. Kaldırmak için: openscale killswitch off")
		}
		return nil
	}
	g := l.guard(context.Background(), nil)
	if err := g.Prepare(iface); err != nil {
		return err
	}
	fmt.Fprintln(env.Stdout, "Kill switch kuruldu: internet trafiği yalnızca OpenScale tünelinden çıkabilir.")
	return nil
}

func (l *upLeakFlags) guard(ctx context.Context, inner osnet.ExitRouter) *osnet.KillSwitchGuard {
	return &osnet.KillSwitchGuard{
		Inner:    inner,
		AllowLAN: *l.allowLAN,
		Stopping: func() bool { return ctx.Err() != nil },
		Install:  leakOps.install,
		Remove:   leakOps.remove,
	}
}

// exitRouter wraps inner with the kill switch when it is on.
func (l *upLeakFlags) exitRouter(ctx context.Context, inner osnet.ExitRouter) osnet.ExitRouter {
	if !*l.killSwitch {
		return inner
	}
	return l.guard(ctx, inner)
}

// done tells the owner the kill switch stayed after the tunnel stopped.
func (l *upLeakFlags) done(env *Env) {
	if !*l.killSwitch {
		return
	}
	if on, err := leakOps.installed(); err == nil && on {
		fmt.Fprintln(env.Stdout, "Kill switch yerinde bırakıldı: internet trafiği OpenScale yeniden başlayana kadar engelli. Kaldırmak için: openscale killswitch off")
	}
}

func requireElevated() error {
	if !leakOps.elevated() {
		return errors.New("bu komut yönetici/root yetkisi ister (Linux: sudo; Windows: Yönetici PowerShell)")
	}
	return nil
}

// cmdKillSwitchRestore puts the saved kill switch back; the boot unit runs
// it before the network starts (#74).
func cmdKillSwitchRestore(env *Env, args []string) error {
	fs := newFlagSet(env, "killswitch restore")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := requireElevated(); err != nil {
		return err
	}
	ok, err := leakOps.restore()
	if err != nil {
		return err
	}
	if !ok {
		fmt.Fprintln(env.Stdout, "Kayıtlı kill switch yok; yapılacak bir şey yok.")
		return nil
	}
	fmt.Fprintln(env.Stdout, "Kill switch geri yüklendi: internet trafiği yalnızca OpenScale tünelinden çıkabilir.")
	return nil
}

// cmdKillSwitchBoot turns the boot-time protection on or off (#74).
func cmdKillSwitchBoot(env *Env, args []string) error {
	fs := newFlagSet(env, "killswitch boot")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageError("kullanım: openscale killswitch boot on|off|status")
	}
	if leakOps.goos == "windows" {
		fmt.Fprintln(env.Stdout, "Windows'ta kill switch filtreleri kalıcıdır; açılışta, servis başlamadan önce de etkindir. Ayrı bir açılış ayarı gerekmez.")
		return nil
	}
	switch pos[0] {
	case "status":
		on, err := leakOps.bootEnabled()
		if err != nil {
			return err
		}
		if on {
			fmt.Fprintln(env.Stdout, "Açılış koruması açık: kayıtlı kill switch açılışta ağdan önce geri yüklenir.")
		} else {
			fmt.Fprintln(env.Stdout, "Açılış koruması kapalı.")
		}
		return nil
	case "on":
		if err := requireElevated(); err != nil {
			return err
		}
		if !leakOps.bootSupported() {
			return errors.New("açılış koruması için systemd gerekli")
		}
		exe, err := leakOps.executable()
		if err != nil {
			return err
		}
		if err := leakOps.bootEnable(exe); err != nil {
			return err
		}
		fmt.Fprintln(env.Stdout, "Açılış koruması açıldı (openscale-killswitch.service): kill switch kuruluyken bilgisayar yeniden başlarsa ağdan önce geri yüklenir.")
		fmt.Fprintln(env.Stdout, "Kill switch kurulu değilse açılışta hiçbir şey yapılmaz.")
		return nil
	case "off":
		if err := requireElevated(); err != nil {
			return err
		}
		if err := leakOps.bootDisable(); err != nil {
			return err
		}
		fmt.Fprintln(env.Stdout, "Açılış koruması kapatıldı.")
		return nil
	}
	return usageError("kullanım: openscale killswitch boot on|off|status")
}

// cmdKillSwitchCaptive opens the kill switch for the local gateway's
// login page for a short time (#85).
func cmdKillSwitchCaptive(env *Env, args []string) error {
	fs := newFlagSet(env, "killswitch captive")
	dur := fs.Duration("sure", osnet.CaptiveDefaultDuration, fmt.Sprintf("istisnanın süresi (en fazla %s)", osnet.CaptiveMaxDuration))
	off := fs.Bool("off", false, "açık istisnayı hemen kapat")
	var extra listFlag
	fs.Var(&extra, "addr", "ağ geçidi dışında izin verilecek yerel IPv4 adresi (giriş sayfasının adresi; tekrarlanabilir)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := requireElevated(); err != nil {
		return err
	}
	if *off {
		if err := leakOps.revokeCaptive(); err != nil {
			return err
		}
		fmt.Fprintln(env.Stdout, "Giriş sayfası istisnası kapatıldı.")
		return nil
	}
	if *dur <= 0 || *dur > osnet.CaptiveMaxDuration {
		return usageError("--sure 1s ile %s arasında olmalı", osnet.CaptiveMaxDuration)
	}
	var addrs []netip.Addr
	if gws, err := leakOps.gateways(); err == nil {
		for _, g := range gws {
			if osnet.CaptiveAddressAllowed(g) && len(addrs) < 2 {
				addrs = append(addrs, g)
			}
		}
	}
	for _, s := range extra.vals {
		a, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil || !osnet.CaptiveAddressAllowed(a) {
			return usageError("--addr %q yerel bir IPv4 adresi değil", s)
		}
		addrs = append(addrs, a)
	}
	if len(addrs) == 0 {
		return errors.New("yerel ağ geçidi bulunamadı; giriş sayfasının adresini --addr ile verin")
	}
	if err := leakOps.allowCaptive(addrs, *dur); err != nil {
		return err
	}
	names := make([]string, len(addrs))
	for i, a := range addrs {
		names[i] = a.String()
	}
	fmt.Fprintf(env.Stdout, "Giriş sayfası istisnası açıldı: %s adresine HTTP/HTTPS (80, 443) %s boyunca izinli.\n", strings.Join(names, ", "), dur.String())
	fmt.Fprintf(env.Stdout, "Tarayıcıda http://%s/ adresini açıp ağa giriş yapın. Başka hiçbir trafik açılmadı; DNS yine yalnızca tünelden.\n", names[0])
	if leakOps.goos != "windows" {
		fmt.Fprintln(env.Stdout, "Süre dolunca istisna çekirdek tarafından kendiliğinden kapanır; erken kapatmak için: openscale killswitch captive --off")
		return nil
	}
	// The WFP permits live in this process's dynamic session: wait here
	// until the time is up or the owner stops the command.
	fmt.Fprintln(env.Stdout, "Bu pencere açık kaldığı sürece istisna geçerlidir; Ctrl+C ile hemen kapanır.")
	t := time.NewTimer(*dur)
	defer t.Stop()
	select {
	case <-t.C:
	case <-envContext(env).Done():
	}
	_ = leakOps.revokeCaptive()
	fmt.Fprintln(env.Stdout, "Giriş sayfası istisnası kapandı.")
	return nil
}

// statusReply is the part of the diagnostics status the leak test uses.
type statusReply struct {
	panel.DiagStatus
}

// cmdExitNodeTest checks whether traffic really leaves through the exit
// node (#77): it asks only this network's coordinator and the exit node's
// own resolver.
func cmdExitNodeTest(env *Env, args []string) error {
	fs := newFlagSet(env, "exit-node test")
	df := addDiagFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	c, err := df.client(env)
	if err != nil {
		return err
	}
	var st statusReply
	if err := c.get(env, "/status", &st); err != nil {
		return err
	}
	if st.ExitNode == "" {
		return leaktest.ErrNoExitNode
	}
	var nc netCheckReply
	_ = c.get(env, "/netcheck", &nc)

	dir := ""
	if c.service {
		dir = filepath.Join(localAPI.dataDir(), service.DeviceDir)
	} else if dir, err = resolveStateDir(env, *df.stateDir); err != nil {
		return err
	}
	store, err := member.Open(dir)
	if err != nil {
		return fmt.Errorf("ağ belgesi okunamadı: %w", err)
	}
	in, err := service.LeakInput(st.DiagStatus, nc.MappedEndpoint, store.Document())
	if err != nil {
		return err
	}
	in.LocalAddrs = leakOps.localAddrs(st.Interface)
	on, ksErr := leakOps.installed()
	in.KillSwitch, in.KillSwitchKnown = on, ksErr == nil
	if leakOps.goos == "windows" {
		// The WFP kill switch holds the DNS client and IPv6 to the tunnel.
		in.DNSGuard, in.IPv6Guard = on, on
	} else {
		guard, _ := leakOps.leakGuard()
		in.DNSGuard, in.IPv6Guard = guard || on, guard || on
		if res, err := leakOps.resolvers(); err == nil {
			in.Resolvers = []leaktest.Resolver{}
			for _, r := range res {
				in.Resolvers = append(in.Resolvers, leaktest.Resolver{Link: r.Link, Addr: r.Addr})
			}
		}
	}
	ctx, cancel := context.WithTimeout(envContext(env), 30*time.Second)
	defer cancel()
	rep, err := leaktest.Run(ctx, in, leakOps.prober, env.Now())
	if err != nil {
		return err
	}
	leaktest.AddLocation(&rep, leakLocale()) // #404: information only
	if *df.json {
		return printJSON(env.Stdout, rep)
	}
	printLeakReport(env, rep)
	if rep.Leak {
		return errors.New("sızıntı bulundu")
	}
	return nil
}

func printLeakReport(env *Env, rep leaktest.Report) {
	w := env.Stdout
	fmt.Fprintf(w, "Çıkış düğümü: %s\n", rep.ExitNode)
	if rep.SeenIPv4 != "" {
		fmt.Fprintf(w, "Koordinatörün gördüğü IPv4: %s\n", rep.SeenIPv4)
	}
	if rep.SeenIPv6 != "" {
		fmt.Fprintf(w, "Koordinatörün gördüğü IPv6: %s\n", rep.SeenIPv6)
	}
	labels := map[string]string{leaktest.LevelOK: "tamam", leaktest.LevelInfo: "bilgi", leaktest.LevelWarn: "uyarı", leaktest.LevelLeak: "SIZINTI"}
	for _, c := range rep.Checks {
		fmt.Fprintf(w, "  [%s] %s: %s\n", labels[c.Level], c.Title, c.Detail)
	}
	fmt.Fprintln(w, "Test yalnızca bu ağın koordinatörüne ve çıkış düğümünün çözücüsüne sordu; üçüncü taraf bir servis kullanılmadı.")
}
