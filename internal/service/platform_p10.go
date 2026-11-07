package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/filter"
	"github.com/openscale/openscale/internal/memprofile"
	"github.com/openscale/openscale/internal/osnet"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/svcmgr"
	"github.com/openscale/openscale/internal/winapp"
	"github.com/openscale/openscale/internal/wintunembed"
)

// Platform support (P10).
//
// Repair after a major operating system update (#498): the service keeps
// the build it last started on in update/os-build.json. When a start finds
// another build (a Windows feature update, a new kernel or distribution
// release) it waits until the tunnel is up and then checks, and where it
// can repairs, what OpenScale put in place: the persistent kill switch is
// installed again (one WFP transaction or one nft table replacement), the
// Windows firewall rules are created again when they are gone, the Wintun
// driver is checked, third-party WFP filters that could defeat the kill
// switch are counted (#499). DNS (NRPT, resolvectl) is verified every 15
// seconds by the DNS watch and needs no step here. The same repair can be
// started from the panel or the command line.
//
// The status also reports the memory profile (#392), the resource limits
// of the service (#494), Server Core (#493) and WSL (#490).

const (
	osBuildFile    = "os-build.json"
	maxOSBuildFile = 64 << 10
)

// platformTunnelWait bounds how long the automatic repair waits for the
// tunnel; without one it checks what it can. Variables for tests.
var (
	platformTunnelWait = 2 * time.Minute
	platformTunnelPoll = 2 * time.Second
)

// osBuildState is os-build.json.
type osBuildState struct {
	Build      osnet.OSBuild           `json:"build"`
	Update     *panel.PlatformOSUpdate `json:"update,omitempty"`
	LastRepair *panel.PlatformRepair   `json:"last_repair,omitempty"`
}

// platformProbes are the system queries; tests replace them.
type platformProbes struct {
	build               func() osnet.OSBuild
	killSwitchInstalled func() (bool, error)
	// firewallPresent and firewallEnsure are nil where there are no
	// OpenScale firewall rules (outside Windows).
	firewallPresent func() (bool, error)
	firewallEnsure  func(overlay netip.Prefix) error
	// wintunVersion is nil outside Windows.
	wintunVersion func() (string, error)
	// wfpRisks counts third-party filters; nil outside Windows.
	wfpRisks func() (int, error)
	// tunDevice checks /dev/net/tun; nil outside Linux.
	tunDevice  func() error
	serverCore func() bool
	wsl        func() osnet.WSLInfo
}

func defaultPlatformProbes() platformProbes {
	p := platformProbes{
		build:               osnet.CurrentOSBuild,
		killSwitchInstalled: osnet.KillSwitchInstalled,
		serverCore:          winapp.IsServerCore,
		wsl:                 func() osnet.WSLInfo { return osnet.DetectWSL("") },
	}
	switch runtime.GOOS {
	case "windows":
		p.firewallPresent = winapp.FirewallRulesPresent
		p.firewallEnsure = func(overlay netip.Prefix) error {
			exe, err := os.Executable()
			if err != nil {
				return err
			}
			return winapp.EnsureFirewallRules(exe, overlay.String())
		}
		p.wintunVersion = wintunembed.DriverVersion
		p.wfpRisks = func() (int, error) {
			risks, err := osnet.KillSwitchBypassRisks()
			return len(risks), err
		}
	case "linux":
		p.tunDevice = func() error {
			st, err := os.Stat("/dev/net/tun")
			if err != nil {
				return err
			}
			if st.Mode()&fs.ModeCharDevice == 0 {
				return errors.New("/dev/net/tun bir karakter aygıtı değil")
			}
			return nil
		}
	}
	return p
}

// platformState is shared by the runtimes of this process (one in
// production).
var platformState struct {
	mu        sync.Mutex
	probes    *platformProbes
	repairing bool
}

func probes() platformProbes {
	platformState.mu.Lock()
	defer platformState.mu.Unlock()
	if platformState.probes == nil {
		p := defaultPlatformProbes()
		platformState.probes = &p
	}
	return *platformState.probes
}

func (r *Runtime) osBuildPath() string { return r.path(UpdateDir, osBuildFile) }

func (r *Runtime) loadOSBuild() (osBuildState, error) {
	var st osBuildState
	data, err := securefile.ReadLimited(r.osBuildPath(), maxOSBuildFile)
	if errors.Is(err, fs.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(data, &st); err != nil {
		// A damaged file only loses the history; the next save replaces it.
		return osBuildState{}, nil
	}
	return st, nil
}

func (r *Runtime) saveOSBuild(st osBuildState) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(r.path(UpdateDir), 0o700); err != nil {
		return err
	}
	return securefile.Replace(r.osBuildPath(), data)
}

// platformStartup records the build and, after a major update, starts the
// repair once the tunnel is up. Run calls it before the roles start.
func (r *Runtime) platformStartup(ctx context.Context) {
	p := probes()
	cur := p.build()
	platformState.mu.Lock()
	st, err := r.loadOSBuild()
	if err != nil {
		r.logger.Warn("os build state", "error", err.Error())
	}
	changed := cur.MajorChange(st.Build)
	if changed {
		st.Update = &panel.PlatformOSUpdate{From: st.Build.String(), To: cur.String(), DetectedAt: r.cfg.Now().UTC()}
	}
	if cur.Known() {
		st.Build = cur
		if err := r.saveOSBuild(st); err != nil {
			r.logger.Warn("os build state", "error", err.Error())
		}
	}
	platformState.mu.Unlock()
	if !changed {
		return
	}
	r.logger.Warn("operating system was updated; checking OpenScale's system settings", "from", st.Update.From, "to", st.Update.To)
	r.eventLog().Add(panel.DiagEvent{At: r.cfg.Now(), Kind: "os-update",
		Message: fmt.Sprintf("İşletim sistemi güncellendi (%s → %s); OpenScale'in sistem ayarları denetlenip onarılacak.", st.Update.From, st.Update.To)})
	r.spawn(func() {
		select {
		case <-r.ready:
		case <-ctx.Done():
			return
		}
		r.waitTunnel(ctx, platformTunnelWait)
		if ctx.Err() != nil {
			return
		}
		rep := r.runPlatformRepair(ctx, "os-update", st.Update)
		problems := 0
		for _, c := range rep.Checks {
			if c.Level == panel.PlatformError || c.Level == panel.PlatformWarn {
				problems++
			}
		}
		r.logger.Info("repair after operating system update done", "checks", len(rep.Checks), "problems", problems)
	})
}

// waitTunnel waits until the tunnel interface exists, at most max.
func (r *Runtime) waitTunnel(ctx context.Context, max time.Duration) {
	deadline := time.NewTimer(max)
	defer deadline.Stop()
	tick := time.NewTicker(platformTunnelPoll)
	defer tick.Stop()
	for r.tunnelInterface() == "" {
		select {
		case <-ctx.Done():
			return
		case <-deadline.C:
			return
		case <-tick.C:
		}
	}
}

// runPlatformRepair runs every check, saves the result and returns it.
func (r *Runtime) runPlatformRepair(ctx context.Context, reason string, upd *panel.PlatformOSUpdate) panel.PlatformRepair {
	platformState.mu.Lock()
	if platformState.repairing {
		platformState.mu.Unlock()
		return panel.PlatformRepair{At: r.cfg.Now().UTC(), Reason: reason,
			Checks: []panel.PlatformCheck{{Area: "onarım", Level: panel.PlatformWarn, Message: "Başka bir onarım sürüyor; bitince yeniden deneyin."}}}
	}
	platformState.repairing = true
	platformState.mu.Unlock()
	defer func() {
		platformState.mu.Lock()
		platformState.repairing = false
		platformState.mu.Unlock()
	}()

	rep := panel.PlatformRepair{At: r.cfg.Now().UTC(), Reason: reason, Checks: r.platformChecks(ctx, probes())}
	if upd != nil {
		rep.From, rep.To = upd.From, upd.To
	}
	for _, c := range rep.Checks {
		if c.Level == panel.PlatformError || c.Level == panel.PlatformRepaired {
			r.eventLog().Add(panel.DiagEvent{At: rep.At, Kind: "platform-repair", Message: c.Area + ": " + c.Message})
		}
	}
	platformState.mu.Lock()
	st, _ := r.loadOSBuild()
	st.LastRepair = &rep
	if reason == "os-update" {
		// The update has been handled; the status stops showing it.
		st.Update = nil
	}
	if err := r.saveOSBuild(st); err != nil {
		r.logger.Warn("os build state", "error", err.Error())
	}
	platformState.mu.Unlock()
	return rep
}

func (r *Runtime) platformChecks(ctx context.Context, p platformProbes) []panel.PlatformCheck {
	var out []panel.PlatformCheck
	add := func(area, level, msg string) {
		out = append(out, panel.PlatformCheck{Area: area, Level: level, Message: msg})
	}
	iface := r.tunnelInterface()

	// Kill switch: install again when the settings want it. The install
	// replaces OpenScale's filters in one transaction, so there is no gap.
	if r.killSwitchAvailable() {
		st, err := r.currentSettings()
		switch {
		case err != nil:
			add("kill switch", panel.PlatformError, "Ayarlar okunamadı: "+err.Error())
		case st.killSwitchOn() && exitWanted(st):
			before, berr := p.killSwitchInstalled()
			if err := r.syncKillSwitch(iface); err != nil {
				add("kill switch", panel.PlatformError, "Yeniden kurulamadı: "+err.Error())
			} else if berr == nil && !before {
				add("kill switch", panel.PlatformRepaired, "Filtreler kayıptı (güncelleme silmiş olabilir); yeniden kuruldu.")
			} else {
				add("kill switch", panel.PlatformOK, "Filtreler yeniden kuruldu.")
			}
		default:
			add("kill switch", panel.PlatformOK, "Çıkış düğümü kullanılmıyor; kill switch gerekmiyor.")
		}
	}

	// Windows firewall rules.
	if p.firewallPresent != nil {
		ok, err := p.firewallPresent()
		switch {
		case err != nil:
			add("güvenlik duvarı", panel.PlatformWarn, "Kurallar denetlenemedi: "+err.Error())
		case ok:
			add("güvenlik duvarı", panel.PlatformOK, "OpenScale gelen trafik kuralları yerinde.")
		default:
			prefixes, perr := r.overlayPrefixes()
			if perr != nil || p.firewallEnsure == nil {
				add("güvenlik duvarı", panel.PlatformWarn, "Kurallar yok; tünel açıldığında yeniden oluşturulur.")
			} else if err := p.firewallEnsure(prefixes[0]); err != nil {
				add("güvenlik duvarı", panel.PlatformError, "Kurallar yok ve yeniden oluşturulamadı: "+err.Error())
			} else {
				add("güvenlik duvarı", panel.PlatformRepaired, "Kurallar kayıptı; yeniden oluşturuldu.")
			}
		}
	}

	// Wintun driver.
	if p.wintunVersion != nil {
		v, err := p.wintunVersion()
		switch {
		case err == nil:
			add("Wintun", panel.PlatformOK, "Sürücü "+v+" çalışıyor.")
		case errors.Is(err, wintunembed.ErrDriverNotLoaded) && iface == "":
			add("Wintun", panel.PlatformOK, "Sürücü tünel açılınca yüklenir.")
		case errors.Is(err, wintunembed.ErrDriverNotLoaded):
			add("Wintun", panel.PlatformError, "Tünel açık görünüyor ama sürücü yüklü değil; servisi yeniden başlatın.")
		default:
			add("Wintun", panel.PlatformWarn, "Sürücü denetlenemedi: "+err.Error())
		}
	}

	// Third-party WFP filters (#499).
	if p.wfpRisks != nil {
		n, err := p.wfpRisks()
		switch {
		case err != nil:
			add("WFP", panel.PlatformWarn, "Başka programların filtreleri okunamadı: "+err.Error())
		case n > 0:
			add("WFP", panel.PlatformWarn, fmt.Sprintf("Kill switch'i etkileyebilecek %d başka filtre var; ayrıntı: openscale edge audit.", n))
		default:
			add("WFP", panel.PlatformOK, "Kill switch'i etkileyebilecek başka filtre yok.")
		}
	}

	// Linux TUN device.
	if p.tunDevice != nil {
		if err := p.tunDevice(); err != nil {
			add("TUN", panel.PlatformError, "/dev/net/tun kullanılamıyor (çekirdek modülü 'tun' yüklü mü?): "+err.Error())
		} else {
			add("TUN", panel.PlatformOK, "/dev/net/tun yerinde.")
		}
	}

	// DNS needs no step: the DNS watch verifies it every 15 seconds.
	if r.cfg.Hooks.VerifyNetworkDNS != nil {
		add("DNS", panel.PlatformOK, "DNS ayarları 15 saniyede bir denetlenir ve değişmişse yeniden uygulanır.")
	}
	if ctx.Err() != nil {
		add("onarım", panel.PlatformWarn, "Onarım zaman aşımına uğradı; bazı adımlar yapılmamış olabilir.")
	}
	return out
}

// PlatformStatus implements panel.PlatformApp.
func (r *Runtime) PlatformStatus() (panel.PlatformStatus, error) {
	p := probes()
	b := p.build()
	out := panel.PlatformStatus{
		OS: panel.PlatformOS{Family: b.Family, Version: b.Version, Build: b.Build, Patch: b.Patch,
			Edition: b.Edition, Arch: runtime.GOARCH, ServerCore: p.serverCore()},
		Memory: platformMemory(),
		Limits: platformLimits(),
	}
	platformState.mu.Lock()
	st, err := r.loadOSBuild()
	out.Repairing = platformState.repairing
	platformState.mu.Unlock()
	if err != nil {
		return out, err
	}
	out.OSUpdate, out.LastRepair = st.Update, st.LastRepair
	if w := p.wsl(); w.Installed || w.Inside {
		out.WSL = &panel.PlatformWSL{Installed: w.Installed, Inside: w.Inside, Version: w.Version, Mode: w.Mode, Notes: w.Notes}
	}
	if out.OS.ServerCore {
		out.Notes = append(out.Notes, "Windows Server Core: tepsi simgesi yok; yönetim komut satırıyla veya başka bir bilgisayardan uzak panelle yapılır.")
	}
	if out.OSUpdate != nil {
		out.Notes = append(out.Notes, "İşletim sistemi güncellendi; onarım tünel açılınca kendiliğinden çalışır.")
	}
	return out, nil
}

// PlatformRepair implements panel.PlatformApp.
func (r *Runtime) PlatformRepair(ctx context.Context) (panel.PlatformStatus, error) {
	r.runPlatformRepair(ctx, "manual", nil)
	return r.PlatformStatus()
}

func platformMemory() panel.PlatformMemory {
	cur := memprofile.Current()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	m := panel.PlatformMemory{Profile: cur.Profile.Name, Live: ms.HeapInuse + ms.StackInuse,
		MaxFlows: memprofile.FillConnTrack(filter.Limits{}).MaxFlows}
	if cur.MemoryLimitSet {
		m.MemoryLimit = cur.Profile.MemoryLimit
	}
	if cur.GCSet {
		m.GCPercent = cur.Profile.GCPercent
	}
	if cur.Profile.Name == memprofile.NameLow {
		m.Budget = memprofile.LowBudget
	}
	return m
}

func platformLimits() *panel.PlatformLimits {
	if l, ok := winapp.CurrentResourceLimits(); ok {
		return &panel.PlatformLimits{Mechanism: "job", MemoryMax: l.MemoryMax, CPUPercent: l.CPUPercent, Applied: l.Applied, Error: l.Error}
	}
	if l, ok := svcmgr.CurrentCgroupLimits(); ok {
		return &panel.PlatformLimits{Mechanism: "systemd", MemoryMax: l.MemoryMax, Applied: true}
	}
	return nil
}
