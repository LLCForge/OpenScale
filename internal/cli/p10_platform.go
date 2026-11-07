package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/openscale/openscale/internal/memprofile"
	"github.com/openscale/openscale/internal/netprofile"
	"github.com/openscale/openscale/internal/osnet"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/svcmgr"
	"github.com/openscale/openscale/internal/winapp"
	"github.com/openscale/openscale/internal/wintunembed"
)

// Platform support (P10, ADR-0162-0164): the platform status and the
// repair after an operating system update (#498), WSL2 advice (#490), the
// portable Windows mode (#497) and the check for several networks at the
// same time (#500).

func p10PlatformCommands() []command {
	return []command{
		{"platform status", "Platform durumu (platform ile aynı)", cmdPlatformStatus},
		{"platform repair", "Güvenlik duvarı kuralları, kill switch, Wintun ve WFP denetimini şimdi çalıştırır ve onarır", cmdPlatformRepair},
		{"platform wsl", "WSL2 ile birlikte kullanım önerileri (ağ kipi, MTU, DNS)", cmdPlatformWSL},
		{"platform", "Platform durumu: işletim sistemi derlemesi, güncelleme sonrası onarım, bellek profili, kaynak sınırları, WSL", cmdPlatformStatus},
		{"portable", "Taşınabilir Windows kipi: USB'den, servis kurmadan geçici tünel; kapanışta kurduklarını kaldırır", cmdPortable},
		{"network concurrent", "Birden çok ağın aynı anda açık kalıp kalamayacağını denetler: <ad> <ad>...", cmdNetworkConcurrent},
	}
}

func cmdPlatformStatus(env *Env, args []string) error {
	fs := newFlagSet(env, "platform")
	df := addDiagFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	var st panel.PlatformStatus
	c, err := df.client(env)
	if err == nil {
		err = c.get(env, "/platform", &st)
	}
	if err != nil {
		// Without the service: what this process can see by itself.
		st = localPlatformStatus()
		st.Notes = append(st.Notes, "Servise ulaşılamadı ("+err.Error()+"); yalnızca bu komutun gördüğü bilgiler gösteriliyor.")
	}
	if *df.json {
		return printJSON(env.Stdout, st)
	}
	printPlatformStatus(env.Stdout, st)
	return nil
}

func cmdPlatformRepair(env *Env, args []string) error {
	fs := newFlagSet(env, "platform repair")
	df := addDiagFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	c, err := df.client(env)
	if err != nil {
		return err
	}
	var st panel.PlatformStatus
	if err := c.post(env, "/platform/repair", struct{}{}, &st); err != nil {
		return err
	}
	if *df.json {
		return printJSON(env.Stdout, st)
	}
	printPlatformStatus(env.Stdout, st)
	return nil
}

func localPlatformStatus() panel.PlatformStatus {
	b := osnet.CurrentOSBuild()
	cur := memprofile.Current()
	st := panel.PlatformStatus{
		Schema: panel.PlatformSchema,
		OS: panel.PlatformOS{Family: b.Family, Version: b.Version, Build: b.Build, Patch: b.Patch, Edition: b.Edition,
			Arch: runtime.GOARCH, ServerCore: winapp.IsServerCore()},
		Memory: panel.PlatformMemory{Profile: cur.Profile.Name},
	}
	home, _ := os.UserHomeDir()
	if w := osnet.DetectWSL(home); w.Installed || w.Inside {
		st.WSL = &panel.PlatformWSL{Installed: w.Installed, Inside: w.Inside, Version: w.Version, Mode: w.Mode, Notes: w.Notes}
	}
	return st
}

func printPlatformStatus(w io.Writer, st panel.PlatformStatus) {
	o := st.OS
	line := fmt.Sprintf("İşletim sistemi: %s %s, derleme %s", o.Family, o.Version, o.Build)
	if o.Patch != "" {
		line += "." + o.Patch
	}
	line += " (" + o.Arch + ")"
	if o.Edition != "" {
		line += ", " + o.Edition
	}
	fmt.Fprintln(w, line)
	if st.OSUpdate != nil {
		fmt.Fprintf(w, "Güncelleme algılandı: %s -> %s (%s)\n", st.OSUpdate.From, st.OSUpdate.To, st.OSUpdate.DetectedAt.Local().Format("02.01.2006 15:04"))
	}
	if r := st.LastRepair; r != nil {
		why := "elle"
		if r.Reason == "os-update" {
			why = "güncelleme sonrası"
		}
		fmt.Fprintf(w, "Son onarım (%s): %s\n", why, r.At.Local().Format("02.01.2006 15:04"))
		for _, c := range r.Checks {
			fmt.Fprintf(w, "  [%s] %s: %s\n", platformLevelText(c.Level), c.Area, c.Message)
		}
	}
	if st.Repairing {
		fmt.Fprintln(w, "Onarım sürüyor.")
	}
	m := st.Memory
	mem := "Bellek profili: " + m.Profile
	if m.Live > 0 {
		mem += fmt.Sprintf(", canlı Go belleği %d KiB", m.Live>>10)
	}
	if m.Budget > 0 {
		mem += fmt.Sprintf(" (hedef %d MiB)", m.Budget>>20)
	}
	if m.MemoryLimit > 0 {
		mem += fmt.Sprintf(", yumuşak sınır %d MiB", m.MemoryLimit>>20)
	}
	fmt.Fprintln(w, mem)
	if l := st.Limits; l != nil {
		text := "Servis kaynak sınırı (" + l.Mechanism + "): "
		if l.MemoryMax > 0 {
			text += fmt.Sprintf("bellek %d MiB", l.MemoryMax>>20)
		} else {
			text += "bellek sınırsız"
		}
		if l.CPUPercent > 0 {
			text += fmt.Sprintf(", işlemci %%%d", l.CPUPercent)
		}
		if !l.Applied {
			text += ", uygulanmadı"
		}
		if l.Error != "" {
			text += " (" + l.Error + ")"
		}
		fmt.Fprintln(w, text)
	}
	if st.WSL != nil {
		fmt.Fprintln(w, "WSL:")
		for _, n := range st.WSL.Notes {
			fmt.Fprintln(w, "  - "+n)
		}
	}
	for _, n := range st.Notes {
		fmt.Fprintln(w, "Not: "+n)
	}
}

func platformLevelText(level string) string {
	switch level {
	case panel.PlatformOK:
		return "TAMAM"
	case panel.PlatformRepaired:
		return "ONARILDI"
	case panel.PlatformWarn:
		return "UYARI"
	case panel.PlatformError:
		return "HATA"
	}
	return strings.ToUpper(level)
}

func cmdPlatformWSL(env *Env, args []string) error {
	fs := newFlagSet(env, "platform wsl")
	asJSON := fs.Bool("json", false, "makine okunur JSON çıktı")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	home, _ := os.UserHomeDir()
	w := osnet.DetectWSL(home)
	if *asJSON {
		return printJSON(env.Stdout, w)
	}
	if !w.Installed && !w.Inside {
		fmt.Fprintln(env.Stdout, "Bu bilgisayarda WSL bulunamadı.")
		return nil
	}
	if w.Mode != "" {
		fmt.Fprintln(env.Stdout, "WSL2 ağ kipi: "+w.Mode)
	}
	for _, n := range w.Notes {
		fmt.Fprintln(env.Stdout, "- "+n)
	}
	return nil
}

// Portable mode (#497, ADR-0163).

// portableDirName is the state directory next to the program on the USB
// stick; the device identity travels with the stick.
const portableDirName = "OpenScale-portable"

// portableTrustWord confirms the warning that the host computer can read
// the device key while the tunnel runs.
const portableTrustWord = "GUVENIYORUM"

// portableHost are the system queries of the portable mode.
type portableHost struct {
	goos                string
	exe                 func() (string, error)
	elevated            func() bool
	serviceInstalled    func() (bool, error)
	killSwitchInstalled func() (bool, error)
	firewallPresent     func() (bool, error)
	driverVersion       func() (string, error)
}

// portablePlan is what a portable run will do and undo.
type portablePlan struct {
	StateDir string
	// RemoveKillSwitch, RemoveFirewall and DeleteDriver are true when the
	// run, not someone else, will have created that thing.
	RemoveKillSwitch bool
	RemoveFirewall   bool
	DeleteDriver     bool
}

var defaultPortableHost = portableHost{
	goos:     runtime.GOOS,
	exe:      os.Executable,
	elevated: winapp.IsElevated,
	serviceInstalled: func() (bool, error) {
		st, err := svcmgr.Get(context.Background(), svcmgr.RoleDevice)
		return st.Installed, err
	},
	killSwitchInstalled: osnet.KillSwitchInstalled,
	firewallPresent:     winapp.FirewallRulesPresent,
	driverVersion:       wintunembed.DriverVersion,
}

func planPortable(h portableHost, stateDir string) (portablePlan, error) {
	if h.goos != "windows" {
		return portablePlan{}, errors.New("taşınabilir kip yalnızca Windows'ta; Linux ve macOS'ta 'openscale up --state-dir <klasör>' zaten servis kurmadan çalışır")
	}
	if !h.elevated() {
		return portablePlan{}, errors.New("taşınabilir kip yönetici yetkisi ister (Wintun sürücüsü ve rotalar); programı 'Yönetici olarak çalıştır' ile açın")
	}
	installed, err := h.serviceInstalled()
	if err != nil {
		return portablePlan{}, fmt.Errorf("servis durumu okunamadı: %w", err)
	}
	if installed {
		return portablePlan{}, errors.New("bu bilgisayarda OpenScale servisi kurulu; taşınabilir kip kurulu bir OpenScale'in kill switch ve güvenlik duvarı ayarlarına dokunmamak için çalışmaz")
	}
	if stateDir == "" {
		exe, err := h.exe()
		if err != nil {
			return portablePlan{}, err
		}
		if exe, err = filepath.EvalSymlinks(exe); err != nil {
			return portablePlan{}, err
		}
		stateDir = filepath.Join(filepath.Dir(exe), portableDirName)
	}
	if !filepath.IsAbs(stateDir) {
		return portablePlan{}, errors.New("taşınabilir kip klasörü tam yol olmalı")
	}
	if _, err := os.Stat(filepath.Join(stateDir, "anchor.json")); err != nil {
		return portablePlan{}, fmt.Errorf("%s bu cihazın üyeliğini içermiyor; önce bir kez: openscale join --state-dir \"%s\" <katılım paketi> (veya invite-join --state-dir)", stateDir, stateDir)
	}
	p := portablePlan{StateDir: stateDir}
	if on, err := h.killSwitchInstalled(); err == nil {
		p.RemoveKillSwitch = !on
	}
	if on, err := h.firewallPresent(); err == nil {
		p.RemoveFirewall = !on
	}
	if _, err := h.driverVersion(); errors.Is(err, wintunembed.ErrDriverNotLoaded) {
		p.DeleteDriver = true
	}
	return p, nil
}

// portableWarning is shown before every portable run.
const portableWarning = "UYARI: Taşınabilir kip yalnızca güvendiğiniz bir bilgisayarda kullanılmalı. Tünel açıkken bu bilgisayarın yöneticisi (ve bilgisayardaki kötü amaçlı bir yazılım) USB bellekteki cihaz anahtarını okuyabilir. Şüphelenirseniz cihazı sahibin panelinden iptal edin."

func cmdPortable(env *Env, args []string) error {
	// --state-dir and --confirm belong to this command; every other
	// argument goes to "up" (for example --exit-node).
	stateDir, confirm := new(string), new(string)
	rest, err := splitPortableArgs(args, stateDir, confirm)
	if err != nil {
		return err
	}
	plan, err := planPortable(defaultPortableHost, *stateDir)
	if err != nil {
		return err
	}
	fmt.Fprintln(env.Stderr, portableWarning)
	if err := confirmCritical(env, *confirm, portableTrustWord, "Bu bilgisayara güveniyorsanız"); err != nil {
		return err
	}
	upArgs := append([]string{"--state-dir", plan.StateDir}, rest...)
	runErr := cmdUp(env, upArgs)
	for _, note := range portableCleanup(plan, portableUndo{
		removeKillSwitch: osnet.RemoveKillSwitch,
		removeFirewall:   winapp.RemoveFirewallRules,
		deleteDriver:     wintunembed.DeleteDriver,
	}) {
		fmt.Fprintln(env.Stdout, note)
	}
	return runErr
}

// splitPortableArgs takes --state-dir and --confirm (in either form) and
// returns the other arguments for "up".
func splitPortableArgs(args []string, stateDir, confirm *string) ([]string, error) {
	var rest []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		for _, f := range []struct {
			name string
			dst  *string
		}{{"state-dir", stateDir}, {"confirm", confirm}} {
			for _, p := range []string{"--" + f.name, "-" + f.name} {
				if a == p {
					if i+1 >= len(args) {
						return nil, usageError("%s bir değer ister", p)
					}
					*f.dst, a = args[i+1], ""
					i++
				} else if v, ok := strings.CutPrefix(a, p+"="); ok {
					*f.dst, a = v, ""
				}
			}
		}
		if a != "" {
			rest = append(rest, a)
		}
	}
	return rest, nil
}

// portableUndo are the removal steps.
type portableUndo struct {
	removeKillSwitch func() error
	removeFirewall   func() error
	deleteDriver     func() error
}

// portableCleanup removes what the run created; things that were already
// there before it started stay.
func portableCleanup(p portablePlan, u portableUndo) []string {
	var notes []string
	step := func(want bool, what string, fn func() error) {
		if !want {
			return
		}
		if err := fn(); err != nil {
			notes = append(notes, fmt.Sprintf("%s kaldırılamadı: %v", what, err))
			return
		}
		notes = append(notes, what+" kaldırıldı.")
	}
	step(p.RemoveKillSwitch, "Kill switch", u.removeKillSwitch)
	step(p.RemoveFirewall, "Güvenlik duvarı kuralları", u.removeFirewall)
	step(p.DeleteDriver, "Wintun sürücüsü", u.deleteDriver)
	notes = append(notes, "Taşınabilir kip bitti. Windows'un kendi kayıtları (Prefetch, olay günlüğü, ağ profili listesi, sürücü kurulum günlüğü) bu bilgisayarda kalabilir; ayrıntı: docs/tasinabilir-kip.md.")
	return notes
}

// Several networks at the same time (#500, ADR-0164).

func cmdNetworkConcurrent(env *Env, args []string) error {
	fs := newFlagSet(env, "network concurrent")
	asJSON := fs.Bool("json", false, "makine okunur JSON çıktı")
	names, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(names) < 2 {
		return usageError("en az iki ağ profili adı verin: openscale network concurrent <ad> <ad>")
	}
	base, err := profileBase(env)
	if err != nil {
		return err
	}
	plan, err := netprofile.CheckConcurrent(base, names)
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(env.Stdout, plan)
	}
	for _, p := range plan.Profiles {
		role := "ek ağ (çıkış düğümü ve kill switch yok)"
		if p.Primary {
			role = "birincil ağ"
		}
		fmt.Fprintf(env.Stdout, "%s: %s, %s, arayüz %s, %s\n", p.Name, p.IPv4, p.DNSDomain, p.Interface, role)
	}
	if !plan.OK() {
		for _, c := range plan.Conflicts {
			fmt.Fprintln(env.Stdout, "ÇAKIŞMA: "+c)
		}
		return errors.New("bu ağlar aynı anda açık kalamaz")
	}
	fmt.Fprintln(env.Stdout, "Bu ağlar aynı anda açılabilir. Her biri ayrı bir yönetici terminalinde:")
	for _, p := range plan.Profiles {
		if p.Primary {
			fmt.Fprintf(env.Stdout, "  openscale --network %s up --interface %s\n", p.Name, p.Interface)
		} else {
			fmt.Fprintf(env.Stdout, "  openscale --network %s up --interface %s --listen-port 0\n", p.Name, p.Interface)
		}
	}
	fmt.Fprintln(env.Stdout, "Servis ve masaüstü uygulaması şimdilik tek ağ açar (ADR-0164); aynı anda iki tünel gerçek bir sistemde henüz denenmedi.")
	return nil
}
