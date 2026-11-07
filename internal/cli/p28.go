package cli

// P28, advanced topology (Faz 9): network profiles (F-109, #291,
// ADR-0135), the network range change tool (F-185, #330) and relay
// admission (F-096, #287), both ADR-0136.

import (
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/coordinator"
	"github.com/openscale/openscale/internal/netprofile"
	"github.com/openscale/openscale/internal/trust"
)

// readdressWord confirms a range change: every device gets a new address.
const readdressWord = "ARALIK"

func p28Commands() []command {
	return []command{
		{"network list", "Bu cihazın üye olduğu ağ profillerini listeler", cmdNetworkList},
		{"network switch", "Etkin ağ profilini değiştirir: <ad> (aynı anda tek ağ etkin)", cmdNetworkSwitch},
		{"network readdress", "Ağ aralığını değiştirir, bütün cihazlara yeni adres atar (--dry-run ile önizleme)", cmdNetworkReaddress},
	}
}

// profileCommands are the commands that work on the profile list itself;
// a global --network selection makes no sense for them.
var profileCommands = []string{"network list", "network switch", "network concurrent"}

// createProfileCommands may create the selected profile's directory:
// they are how a device becomes a member of one more network.
var createProfileCommands = []string{"join", "invite-join", "keygen"}

func hasCommandPrefix(args []string, names []string) bool {
	for _, n := range names {
		parts := strings.Fields(n)
		if len(args) >= len(parts) && strings.Join(args[:len(parts)], " ") == n {
			return true
		}
	}
	return false
}

// selectNetwork handles the global "--network <ad>" option in front of a
// command. It returns the remaining arguments and an Env whose
// DefaultStateDir points at the selected profile, or at the active one
// when no option was given. Without profiles nothing changes: the active
// profile is then the default one, which is the old state directory.
func selectNetwork(args []string, env *Env) ([]string, *Env, error) {
	name, given := "", false
	if len(args) > 0 {
		switch a := args[0]; {
		case a == "--network" || a == "-network":
			if len(args) < 2 || strings.HasPrefix(args[1], "-") {
				return nil, env, usageError("--network bir ağ profili adı ister")
			}
			name, args, given = args[1], args[2:], true
		case strings.HasPrefix(a, "--network=") || strings.HasPrefix(a, "-network="):
			name, args, given = a[strings.IndexByte(a, '=')+1:], args[1:], true
		}
	}
	if given {
		if err := netprofile.ValidName(name); err != nil {
			return nil, env, usageError("geçersiz ağ profili adı %q: a-z, 0-9 ve '-' kullan (en çok %d karakter)", name, netprofile.MaxNameLen)
		}
		if hasCommandPrefix(args, profileCommands) {
			return nil, env, usageError("--network bu komutla kullanılmaz")
		}
	}
	if env.DefaultStateDir == nil || hasCommandPrefix(args, profileCommands) {
		if given {
			return nil, env, usageError("--network için varsayılan durum klasörü yok")
		}
		return args, env, nil
	}
	create := given && hasCommandPrefix(args, createProfileCommands)
	base := env.DefaultStateDir
	e := *env
	e.DefaultStateDir = func() (string, error) {
		b, err := base()
		if err != nil {
			return "", err
		}
		return netprofile.Resolve(b, name, create)
	}
	return args, &e, nil
}

func profileBase(env *Env) (string, error) {
	if env.DefaultStateDir == nil {
		return "", errors.New("varsayılan durum klasörü yok")
	}
	b, err := env.DefaultStateDir()
	if err != nil {
		return "", fmt.Errorf("varsayılan klasör bulunamadı: %w", err)
	}
	return b, nil
}

func cmdNetworkList(env *Env, args []string) error {
	fs := newFlagSet(env, "network list")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	base, err := profileBase(env)
	if err != nil {
		return err
	}
	profiles, listErr := netprofile.List(base)
	if profiles == nil && listErr != nil {
		return listErr
	}
	w := env.Stdout
	fmt.Fprintln(w, "Ağ profilleri (* etkin):")
	for _, p := range profiles {
		mark := " "
		if p.Active {
			mark = "*"
		}
		switch {
		case p.Joined:
			label := p.NetworkID
			if p.DisplayName != "" {
				label = p.DisplayName + " (" + p.NetworkID + ")"
			}
			fmt.Fprintf(w, " %s %-16s %s\n", mark, p.Name, label)
		case p.Problem != "":
			fmt.Fprintf(w, " %s %-16s açılamadı: %s\n", mark, p.Name, p.Problem)
		default:
			fmt.Fprintf(w, " %s %-16s henüz bir ağa katılmamış\n", mark, p.Name)
		}
		if p.Duplicate {
			fmt.Fprintf(w, "   UYARI: %s başka bir profille aynı ağa üye; birini kaldır.\n", p.Name)
		}
	}
	if listErr != nil {
		fmt.Fprintf(w, "UYARI: etkin profil okunamadı: %v\n", listErr)
	}
	fmt.Fprintln(w, "Yeni ağa katılmak için: openscale --network <ad> join ...")
	return nil
}

func cmdNetworkSwitch(env *Env, args []string) error {
	fs := newFlagSet(env, "network switch")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return usageError("%v", err)
	}
	if fs.NArg() != 1 {
		return usageError("tek bir ağ profili adı ver: openscale network switch <ad>")
	}
	name := fs.Arg(0)
	if err := netprofile.ValidName(name); err != nil {
		return usageError("geçersiz ağ profili adı %q", name)
	}
	base, err := profileBase(env)
	if err != nil {
		return err
	}
	if err := netprofile.Switch(base, name); err != nil {
		switch {
		case errors.Is(err, netprofile.ErrUnknown):
			return fmt.Errorf("%q adlı ağ profili yok; 'openscale network list' ile bak", name)
		case errors.Is(err, netprofile.ErrNotJoined):
			return fmt.Errorf("%q profili henüz bir ağa katılmamış; önce 'openscale --network %s join' çalıştır", name, name)
		}
		return err
	}
	fmt.Fprintf(env.Stdout, "Etkin ağ profili: %s\n", name)
	fmt.Fprintln(env.Stdout, "Çalışan tünel eski ağda kalır: 'openscale up' komutunu (veya servisi) yeniden başlat.")
	return nil
}

func cmdNetworkReaddress(env *Env, args []string) error {
	fs := newFlagSet(env, "network readdress")
	common := addEditFlags(fs)
	ipv4 := fs.String("ipv4", "", "yeni özel ağ IPv4 aralığı (ör. 10.44.0.0/16)")
	ipv6 := fs.String("ipv6", "", "yeni özel ağ IPv6 aralığı (boş: değişmez)")
	confirm := fs.String("confirm", "", "imzalamak için açık onay: "+readdressWord)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *common.dir == "" {
		return usageError("--dir zorunlu")
	}
	var p4, p6 netip.Prefix
	var err error
	if *ipv4 == "" && *ipv6 == "" {
		return usageError("--ipv4 veya --ipv6 ver")
	}
	if *ipv4 != "" {
		if p4, err = netip.ParsePrefix(*ipv4); err != nil || !p4.Addr().Is4() {
			return usageError("--ipv4 geçerli bir IPv4 aralığı değil")
		}
	}
	if *ipv6 != "" {
		if p6, err = netip.ParsePrefix(*ipv6); err != nil || !p6.Addr().Is6() {
			return usageError("--ipv6 geçerli bir IPv6 aralığı değil")
		}
	}
	validity, err := daysFlag(*common.validityDays, 1, int(trust.MaxValidity.Hours()/24), "validity")
	if err != nil {
		return err
	}
	n, err := admin.Load(*common.dir, env.adminOptions())
	if err != nil {
		return err
	}
	plan, moves, err := n.PrepareReaddress(env.Now(), validity, p4, p6)
	if err != nil {
		if errors.Is(err, trust.ErrReaddressStale) {
			return fmt.Errorf("belgede eski aralığa işaret eden başvurular var; önce bunları düzenle: %w", err)
		}
		return err
	}
	w := env.Stdout
	fmt.Fprintf(w, "Yeni aralık: %s / %s\n", plan.Next.IPv4Prefix, plan.Next.IPv6Prefix)
	fmt.Fprintf(w, "Adres değişiklikleri (%d):\n", len(moves))
	for _, m := range moves {
		kind := map[string]string{"device": "cihaz", "invite": "davet", "coordinator": "koordinatör"}[m.Kind]
		fmt.Fprintf(w, "  %-12s %-20s %s -> %s\n", kind, m.Name, m.From, m.To)
	}
	if *common.dryRun {
		fmt.Fprintln(w, "Kuru çalıştırma: hiçbir şey imzalanmadı.")
		return nil
	}
	what := fmt.Sprintf("Ağ aralığı değişiyor; %d adres taşınacak ve bütün tüneller yeniden kurulacak", len(moves))
	if err := confirmCritical(env, *confirm, readdressWord, what); err != nil {
		return err
	}
	passphrase, err := existingPassphrase(env, *common.passFile)
	if err != nil {
		return err
	}
	defer wipe(passphrase)
	if err := n.Commit(plan, passphrase); err != nil {
		return err
	}
	fmt.Fprintf(w, "Ağ belgesi sürüm %d olarak imzalandı. Koordinatörü ve cihazları yeni belgeyle yeniden başlat.\n", plan.Next.Version)
	return nil
}

// relayAdmissionPath returns the admission file of a coordinator state
// directory when --relay-admission is on (F-096, ADR-0136).
func relayAdmissionPath(stateDir string, on bool) string {
	if !on {
		return ""
	}
	return filepath.Join(stateDir, coordinator.RelayAdmissionFile)
}
