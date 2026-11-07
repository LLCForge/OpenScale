package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/osnet"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/sysinfo"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/upstream"
)

// Upstream exit commands (ADR-0142): a Linux exit node sends members'
// internet traffic through an outside WireGuard provider such as Mullvad.
// The commands only touch files under <state-dir>/upstream; a running
// "openscale up" reads them again every few seconds.

func upstreamCommands() []command {
	return []command{
		{"exit-node upstream import", "Sağlayıcının WireGuard .conf dosyasını üst çıkış profili olarak içe aktarır: <dosya.conf> [--name ad] [--label etiket] [--provider mullvad|warp|wireguard]", cmdUpstreamImport},
		{"exit-node upstream list", "Üst çıkış profillerini listeler (özel anahtar gösterilmez)", cmdUpstreamList},
		{"exit-node upstream use", "Üyelerin internet trafiğini bu profilin tünelinden çıkarır: <ad> [--on-down drop|direct]", cmdUpstreamUse},
		{"exit-node upstream off", "Üst çıkışı kapatır; üyeler yeniden bu sunucunun kendi adresinden çıkar", cmdUpstreamOff},
		{"exit-node upstream rm", "Etkin olmayan bir üst çıkış profilini siler: <ad>", cmdUpstreamRemove},
		{"exit-node upstream status", "Üst tünelin durumu: etkin sunucu, el sıkışma yaşı, bayt sayaçları", cmdUpstreamStatus},
		{"exit-node upstream tor enable", "Üyelerin internet trafiğini sistemde kurulu Tor'dan çıkarır (TCP ve DNS; UDP/ICMP/IPv6 düşer): [--trans-port 9040] [--dns-port 5353]", cmdTorEnable},
		{"exit-node upstream tor disable", "Tor çıkışını kapatır; üyeler yeniden bu sunucunun kendi adresinden çıkar", cmdTorDisable},
		{"exit-node upstream tor status", "Tor çıkışının durumu: kurallar, TransPort ve DNSPort dinliyor mu", cmdTorStatus},
		{"exit-node upstream tor torrc", "/etc/tor/torrc dosyasına eklenecek satırları basar (OpenScale torrc'yi değiştirmez)", cmdTorTorrc},
	}
}

// maxUpstreamSource bounds the downloaded file read by import.
const maxUpstreamSource = upstream.MaxConfSize

func upstreamStore(env *Env, stateDir string) (*upstream.Store, error) {
	dir, err := resolveStateDir(env, stateDir)
	if err != nil {
		return nil, err
	}
	return upstream.OpenStore(dir)
}

func warnUpstreamPlatform(env *Env) {
	if !osnet.UpstreamSupported() {
		fmt.Fprintln(env.Stderr, "uyarı: üst çıkış yalnızca Linux çıkış düğümlerinde çalışır; bu bilgisayarda profil yalnızca saklanır.")
	}
}

func cmdUpstreamImport(env *Env, args []string) error {
	fs := newFlagSet(env, "exit-node upstream import")
	stateDir := fs.String("state-dir", "", "cihazın durum klasörü (sunucuda genellikle /var/lib/openscale/device)")
	name := fs.String("name", "", "profil adı: küçük harf, rakam ve tire (varsayılan: dosya adından)")
	label := fs.String("label", "", "görünen ad, ör. \"Mullvad · İsveç\" (yalnızca gösterim)")
	replace := fs.Bool("replace", false, "aynı adlı profili değiştir")
	provider := fs.String("provider", "", "sağlayıcı türü: mullvad, warp veya wireguard (yalnızca gösterim ve rapor)")
	if err := parseFlagsWithArgs(fs, args, 1); err != nil {
		return err
	}
	if err := upstream.ValidateProvider(*provider); err != nil {
		return usageError("%v", err)
	}
	src := fs.Arg(0)
	profile := *name
	if profile == "" {
		profile = upstream.NameFromFile(src)
	}
	if err := upstream.ValidateName(profile); err != nil {
		return usageError("%v; --name ile bir ad ver", err)
	}
	data, err := securefile.ReadLimited(src, maxUpstreamSource)
	if err != nil {
		return fmt.Errorf("yapılandırma dosyası okunamadı: %w", err)
	}
	defer clear(data)
	st, err := upstreamStore(env, *stateDir)
	if err != nil {
		return err
	}
	cfg, err := st.ImportWith(profile, *label, data, upstream.ImportOptions{
		Replace: *replace, Resolve: importResolver(env), Provider: *provider,
	})
	if err != nil {
		return err
	}
	defer cfg.Wipe()
	w := env.Stdout
	fmt.Fprintf(w, "Üst çıkış profili içe aktarıldı: %s\n", profile)
	if cfg.EndpointHost != "" {
		// The only name resolution of an upstream exit: now, by the owner.
		fmt.Fprintf(env.Stderr, "uyarı: Endpoint bir addı (%s); içe aktarma anında bir kez %s olarak çözüldü ve IP olarak saklandı.\n", cfg.EndpointHost, cfg.Endpoint.Addr())
		fmt.Fprintln(env.Stderr, "       Tünel çalışırken ad çözümlemesi yapılmaz. Sağlayıcı adresi değiştirirse dosyayı --replace ile yeniden içe aktar.")
	}
	if cfg.MTU != 0 {
		fmt.Fprintf(w, "  MTU:             %d (dosyadan; 'use --mtu' ile değiştirilebilir)\n", cfg.MTU)
	}
	if *label != "" {
		fmt.Fprintf(w, "  Etiket:          %s\n", *label)
	}
	fmt.Fprintf(w, "  Sunucu:          %s\n", cfg.Endpoint)
	fmt.Fprintf(w, "  Tünel adresi:    %s", cfg.Address4)
	if cfg.Address6.IsValid() {
		fmt.Fprintf(w, ", %s", cfg.Address6)
	} else {
		fmt.Fprint(w, " (IPv6 yok: üyelerin IPv6 internet trafiği engellenir)")
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  DNS (tünel içi):  %s\n", addrList(cfg.DNS))
	fmt.Fprintf(w, "  Açık anahtar:    %s (sağlayıcı hesabındaki cihazla aynı olmalı)\n", cfg.PublicKeyString())
	fmt.Fprintf(w, "Kayıt: %s (0600)\n", st.Dir())
	if info, err := os.Stat(src); err == nil && runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		fmt.Fprintf(env.Stderr, "uyarı: %s başka kullanıcılarca okunabilir ve özel anahtarı içeriyor; artık gerekmiyorsa silin (shred -u).\n", src)
	} else {
		fmt.Fprintln(w, "İndirilen özgün dosya özel anahtarı içeriyor; artık gerekmiyorsa silin.")
	}
	fmt.Fprintf(w, "Kullanmak için: openscale exit-node upstream use %s\n", profile)
	warnUpstreamPlatform(env)
	return nil
}

func addrList(as []netip.Addr) string {
	out := ""
	for i, a := range as {
		if i > 0 {
			out += ", "
		}
		out += a.String()
	}
	return out
}

// upstreamProfileJSON is one profile in "list --json"; it never holds a key
// other than the public one.
type upstreamProfileJSON struct {
	Name      string   `json:"name"`
	Label     string   `json:"label,omitempty"`
	Active    bool     `json:"active"`
	Endpoint  string   `json:"endpoint,omitempty"`
	Address4  string   `json:"address4,omitempty"`
	Address6  string   `json:"address6,omitempty"`
	DNS       []string `json:"dns,omitempty"`
	PublicKey string   `json:"public_key,omitempty"`
}

func cmdUpstreamList(env *Env, args []string) error {
	fs := newFlagSet(env, "exit-node upstream list")
	stateDir := fs.String("state-dir", "", "cihazın durum klasörü")
	asJSON := fs.Bool("json", false, "JSON çıktı")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	st, err := upstreamStore(env, *stateDir)
	if err != nil {
		return err
	}
	profiles, err := st.List()
	if err != nil {
		return err
	}
	if *asJSON {
		out := make([]upstreamProfileJSON, 0, len(profiles))
		for _, p := range profiles {
			j := upstreamProfileJSON{Name: p.Name, Label: p.Label, Active: p.Active, Address4: p.Address4, Address6: p.Address6, DNS: p.DNS, PublicKey: p.PublicKey}
			if p.Endpoint.IsValid() {
				j.Endpoint = p.Endpoint.String()
			}
			out = append(out, j)
		}
		return printJSON(env.Stdout, out)
	}
	w := env.Stdout
	if len(profiles) == 0 {
		fmt.Fprintln(w, "Üst çıkış profili yok. İçe aktarmak için: openscale exit-node upstream import <dosya.conf>")
		return nil
	}
	for _, p := range profiles {
		mark := " "
		if p.Active {
			mark = "*"
		}
		line := fmt.Sprintf("%s %-20s", mark, p.Name)
		if p.Endpoint.IsValid() {
			line += "  " + p.Endpoint.String()
		} else {
			line += "  (okunamadı: izinleri veya dosyayı denetle)"
		}
		if p.Label != "" {
			line += "  " + p.Label
		}
		fmt.Fprintln(w, line)
	}
	fmt.Fprintln(w, "* etkin profil")
	return nil
}

func cmdUpstreamUse(env *Env, args []string) error {
	fs := newFlagSet(env, "exit-node upstream use")
	stateDir := fs.String("state-dir", "", "cihazın durum klasörü")
	onDown := fs.String("on-down", "", "tünel düşerse: drop (varsayılan; üyelerin trafiği kesilir) veya direct (bu sunucunun kendi adresinden çıkar; gizlilik kaybı)")
	mtu := fs.Int("mtu", 0, fmt.Sprintf("üst tünel MTU değeri (%d-%d; 0: değiştirme, varsayılan %d)", upstream.MinMTU, upstream.MaxMTU, upstream.DefaultMTU))
	if err := parseFlagsWithArgs(fs, args, 1); err != nil {
		return err
	}
	name := fs.Arg(0)
	if err := upstream.ValidateName(name); err != nil {
		return usageError("%v", err)
	}
	switch *onDown {
	case "", upstream.OnDownDrop, upstream.OnDownDirect:
	default:
		return usageError("--on-down drop veya direct olmalı")
	}
	if *mtu != 0 && (*mtu < upstream.MinMTU || *mtu > upstream.MaxMTU) {
		return usageError("--mtu %d ile %d arasında olmalı", upstream.MinMTU, upstream.MaxMTU)
	}
	st, err := upstreamStore(env, *stateDir)
	if err != nil {
		return err
	}
	// The profile must be readable now, not only when the tunnel starts.
	cfg, err := st.Load(name)
	if err != nil {
		return err
	}
	cfg.Wipe()
	before, err := st.Settings()
	if err != nil {
		return err
	}
	if err := st.Use(name); err != nil {
		return err
	}
	if before.TorEnabled() {
		fmt.Fprintln(env.Stdout, "Tor çıkışı kapatıldı; üst çıkış artık bu WireGuard profilini kullanır.")
	}
	if err := st.UpdateSettings(func(s *upstream.Settings) error {
		if *onDown != "" {
			s.OnDown = *onDown
		}
		if *mtu != 0 {
			s.MTU = *mtu
		}
		return nil
	}); err != nil {
		return err
	}
	s, err := st.Settings()
	if err != nil {
		return err
	}
	w := env.Stdout
	fmt.Fprintf(w, "Etkin üst çıkış: %s", name)
	if l := s.Label(name); l != "" {
		fmt.Fprintf(w, " (%s)", l)
	}
	fmt.Fprintln(w)
	if s.FailOpen() {
		fmt.Fprintln(env.Stderr, "UYARI: --on-down direct seçili. Üst tünel düşerse üyelerin trafiği bu sunucunun kendi IP adresinden çıkar;")
		fmt.Fprintln(env.Stderr, "       siteler ve sunucunun sağlayıcısı üyelerin trafiğini bu adresle görür. Gizlilik için 'drop' önerilir.")
	} else {
		fmt.Fprintln(w, "Tünel düşerse üyelerin internet trafiği kesilir; bu sunucunun adresinden çıkmaz.")
	}
	fmt.Fprintln(w, "Çalışan 'openscale up' değişikliği birkaç saniye içinde uygular. Denetim: openscale exit-node upstream status")
	warnUpstreamPlatform(env)
	return nil
}

func cmdUpstreamOff(env *Env, args []string) error {
	fs := newFlagSet(env, "exit-node upstream off")
	stateDir := fs.String("state-dir", "", "cihazın durum klasörü")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	st, err := upstreamStore(env, *stateDir)
	if err != nil {
		return err
	}
	if err := st.UpdateSettings(func(s *upstream.Settings) error {
		s.Active = ""
		s.Tor = nil
		return nil
	}); err != nil {
		return err
	}
	fmt.Fprintln(env.Stdout, "Üst çıkış kapatıldı (WireGuard profili ve Tor). Bu sunucu çıkış düğümüyse üyelerin trafiği artık kendi adresinden çıkar.")
	fmt.Fprintln(env.Stdout, "Not: OPENSCALE_EXIT_UPSTREAM veya --exit-upstream ayarlıysa bir sonraki başlatmada yeniden açılır.")
	return nil
}

func cmdUpstreamRemove(env *Env, args []string) error {
	fs := newFlagSet(env, "exit-node upstream rm")
	stateDir := fs.String("state-dir", "", "cihazın durum klasörü")
	if err := parseFlagsWithArgs(fs, args, 1); err != nil {
		return err
	}
	st, err := upstreamStore(env, *stateDir)
	if err != nil {
		return err
	}
	if err := st.Remove(fs.Arg(0)); err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Profil silindi: %s\n", fs.Arg(0))
	fmt.Fprintln(env.Stdout, "Sağlayıcı hesabındaki cihaz kaydını (anahtarı) da kaldırmayı unutma.")
	return nil
}

func cmdUpstreamStatus(env *Env, args []string) error {
	fs := newFlagSet(env, "exit-node upstream status")
	stateDir := fs.String("state-dir", "", "cihazın durum klasörü")
	asJSON := fs.Bool("json", false, "JSON çıktı")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	st, err := upstreamStore(env, *stateDir)
	if err != nil {
		return err
	}
	settings, err := st.Settings()
	if err != nil {
		return err
	}
	status, ok, err := st.ReadStatus()
	if err != nil {
		return err
	}
	now := env.Now()
	stale := !ok || status.Stale(now)
	if *asJSON {
		return printJSON(env.Stdout, struct {
			Settings upstream.Settings `json:"settings"`
			Status   *upstream.Status  `json:"status,omitempty"`
			Stale    bool              `json:"stale"`
		}{settings, statusPtr(status, ok), stale})
	}
	w := env.Stdout
	if settings.TorEnabled() {
		printTorStatus(env, settings, status, stale)
		return nil
	}
	if settings.Active == "" {
		fmt.Fprintln(w, "Üst çıkış: kapalı")
	} else {
		fmt.Fprintf(w, "Seçili profil:   %s", settings.Active)
		if l := settings.Label(settings.Active); l != "" {
			fmt.Fprintf(w, " (%s)", l)
		}
		fmt.Fprintln(w)
		fmt.Fprintf(w, "Tür:             %s\n", settings.Kind())
		if settings.FailOpen() {
			fmt.Fprintln(w, "Tünel düşerse:   doğrudan çık (UYARI: üyeler bu sunucunun adresinden görünür)")
		} else {
			fmt.Fprintln(w, "Tünel düşerse:   trafik kesilir (sızıntı yok)")
		}
	}
	if stale {
		fmt.Fprintln(w, "Çalışan tünel:   rapor yok veya eski; 'openscale up' bu cihazda çalışıyor mu ve cihaz çıkış düğümü mü?")
		return nil
	}
	fmt.Fprintf(w, "Durum:           %s\n", upstreamModeText(status.Mode))
	if status.Active != "" {
		fmt.Fprintf(w, "Etkin sunucu:    %s  %s (arayüz %s)\n", status.Active, status.Endpoint, status.Interface)
		if status.LastHandshake > 0 {
			age := now.Sub(time.Unix(status.LastHandshake, 0)).Round(time.Second)
			fmt.Fprintf(w, "Son el sıkışma:  %s önce\n", age)
		} else {
			fmt.Fprintln(w, "Son el sıkışma:  hiç (sağlayıcıya ulaşılamıyor ya da anahtar sağlayıcıda kayıtlı değil)")
		}
		fmt.Fprintf(w, "Alınan/gönderilen: %s / %s\n", humanBytes(status.RxBytes), humanBytes(status.TxBytes))
		if status.Reconnects > 0 {
			fmt.Fprintf(w, "Yeniden bağlanma: %d\n", status.Reconnects)
		}
	}
	if status.Error != "" {
		fmt.Fprintf(w, "Son hata:        %s\n", status.Error)
	}
	// The visible exit address is not measured here: the coordinator's
	// echo sees this device's overlay address, not the provider's.
	fmt.Fprintln(w, "Not: görünen çıkış IP'si buradan ölçülmez; yalnızca el sıkışma ve bayt sayaçları raporlanır.")
	return nil
}

func statusPtr(s upstream.Status, ok bool) *upstream.Status {
	if !ok {
		return nil
	}
	return &s
}

func upstreamModeText(mode string) string {
	switch mode {
	case upstream.ModeTunnel:
		return "bağlı: üyelerin internet trafiği üst tünelden çıkıyor"
	case upstream.ModeBlocked:
		return "bağlantı yok: üyelerin internet trafiği kesiliyor (sızıntı yok)"
	case upstream.ModeDirect:
		return "bağlantı yok: üyelerin trafiği bu sunucunun kendi adresinden çıkıyor (on-down direct)"
	default:
		return "kapalı"
	}
}

// upUpstream is the upstream exit of a running "openscale up" (ADR-0142);
// a nil value does nothing.
type upUpstream struct {
	mgr *upstream.Manager
}

// startUpUpstream prepares the upstream manager on a Linux exit node. A
// non-empty flag makes that profile active (it must exist). Elsewhere the
// flag is refused and nothing runs.
func startUpUpstream(env *Env, dir, flagValue, iface string, store *member.Store, secrets *trust.DeviceSecrets, logger *slog.Logger) (*upUpstream, error) {
	if !osnet.UpstreamSupported() {
		if flagValue != "" {
			return nil, usageError("--exit-upstream yalnızca Linux çıkış düğümlerinde kullanılabilir")
		}
		return &upUpstream{}, nil
	}
	if flagValue == "" {
		// Without the flag the manager runs only when the folder exists,
		// so devices that never imported a profile get no new folder.
		if _, err := os.Stat(filepath.Join(dir, upstream.DirName)); errors.Is(err, fs.ErrNotExist) {
			return &upUpstream{}, nil
		}
	}
	st, err := upstream.OpenStore(dir)
	if err != nil {
		return nil, err
	}
	if flagValue != "" {
		if err := upstream.ValidateName(flagValue); err != nil {
			return nil, usageError("--exit-upstream: %v", err)
		}
		cfg, err := st.Load(flagValue)
		if err != nil {
			return nil, fmt.Errorf("--exit-upstream: %w", err)
		}
		cfg.Wipe()
		if err := st.Use(flagValue); err != nil {
			return nil, err
		}
	}
	mgr, err := upstream.NewManager(upstream.ManagerConfig{
		Store: st,
		Deps:  upstream.HostDeps(logger),
		Overlay: func() (upstream.Overlay, error) {
			doc := store.Document()
			if doc == nil {
				return upstream.Overlay{}, errors.New("ağ belgesi yok")
			}
			ov := upstream.Overlay{Interface: iface, V4: doc.IPv4Prefix, V6: doc.IPv6Prefix}
			// The Tor exit's health check looks for TransPort on this
			// device's own address; unknown is not an error.
			if self, err := selfDevice(doc, secrets); err == nil {
				ov.Self4 = self.IPv4
			}
			return ov, nil
		},
	})
	if err != nil {
		return nil, err
	}
	if s, err := st.Settings(); err == nil && s.Active != "" {
		fmt.Fprintf(env.Stdout, "Üst çıkış seçili: %s (bu cihaz çıkış düğümü olduğunda üyelerin trafiği bu tünelden çıkar).\n", s.Active)
	} else if err == nil && s.TorEnabled() {
		fmt.Fprintln(env.Stdout, "Tor çıkışı seçili: bu cihaz çıkış düğümü olduğunda üyelerin TCP ve DNS trafiği Tor'dan çıkar; UDP, ICMP ve IPv6 düşer.")
	}
	return &upUpstream{mgr: mgr}, nil
}

// dnsVia is node.Config.ExitDNSVia; nil without a manager.
func (u *upUpstream) dnsVia() func() (netip.AddrPort, netip.Addr, bool) {
	if u == nil || u.mgr == nil {
		return nil
	}
	return u.mgr.DNS
}

// roleOn runs before forwarding is turned on; an error keeps the exit node
// off (fail closed, ADR-0142).
func (u *upUpstream) roleOn() error {
	if u == nil || u.mgr == nil {
		return nil
	}
	u.mgr.SetRole(true)
	return u.mgr.Ready()
}

// roleOff runs after forwarding is turned off.
func (u *upUpstream) roleOff() {
	if u != nil && u.mgr != nil {
		u.mgr.SetRole(false)
	}
}

// run checks the tunnel until the returned stop function is called; stop
// removes the tunnel and its routing.
func (u *upUpstream) run(env *Env) func() {
	if u == nil || u.mgr == nil {
		return func() {}
	}
	ctx, cancel := context.WithCancel(envContext(env))
	done := make(chan struct{})
	go func() {
		defer close(done)
		u.mgr.Run(ctx)
	}()
	// The owner's panel shows the provider label and mode through the
	// system report (ADR-0142, sysinfo/upstream.go).
	sysinfo.SetUpstream(u.reportState)
	return func() {
		sysinfo.SetUpstream(nil)
		cancel()
		<-done
		u.mgr.Close()
	}
}

// reportState is the upstream exit as the system report carries it: only
// while a profile is active, never the provider's address.
func (u *upUpstream) reportState() (sysinfo.UpstreamState, bool) {
	return upstreamReportState(u.mgr.Status())
}

// upstreamReportState maps the manager's status to the report. The Tor
// exit has no active profile (Status.Active is ""), so its kind decides
// whether anything is reported; the panel shows "Tor" and its state.
func upstreamReportState(st upstream.Status) (sysinfo.UpstreamState, bool) {
	if st.Active == "" && st.Kind != upstream.KindTor {
		return sysinfo.UpstreamState{}, false
	}
	label := st.Label
	if label == "" {
		label = st.Active
	}
	return sysinfo.UpstreamState{Label: label, Mode: st.Mode, LastHandshake: st.LastHandshake, Kind: st.Kind}, true
}
