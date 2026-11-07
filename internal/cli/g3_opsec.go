package cli

import (
	"encoding/json"
	"fmt"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/filter"
	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/obfs"
	"github.com/openscale/openscale/internal/osnet"
)

// G3 commands (ADR-0186..0191): network opsec settings of this device,
// kept in opsec.json in the state directory and read by the tunnel at
// start; the two system changes (DHCP host name, WebRTC/STUN block) are
// only planned unless --apply is given.

func init() { registerCommands(g3Commands()...) } // g4_registry.go

func g3Commands() []command {
	return []command{
		{"opsec show", "Bu cihazın ağ gizliliği ayarlarını gösterir (opsec.json): [--state-dir KLASÖR] [--json]", cmdOpsecShow},
		{"opsec obfs", "WireGuard trafiğini gizler: --mode off|auto|on [--buckets 256,512,1280,1452] [--jitter 20ms] [--tls-sni AD --tls-pin sha256/... | --tls-off]", cmdOpsecObfs},
		{"opsec chain", "Çift sıçramalı çıkış: --entry GİRİŞ_DÜĞÜMÜ (boş: kapalı); son düğüm 'openscale exit' ile seçilir", cmdOpsecChain},
		{"opsec canary", "Çıkış düğümü MITM kanaryası: --add sunucu:443[=sha256/...] --remove sunucu:443 [--minutes 30]", cmdOpsecCanary},
		{"opsec dns-pin", "Çıkış DNS'i (DoH/DoT) için SPKI sabitlemesi: --pin sha256/... (tekrarlanabilir) [--require] [--clear]", cmdOpsecDNSPin},
		{"opsec decoy", "Tuzak portlar ve karantina: --ports ssh,rdp,smb,8080 [--quarantine-on-scan] [--quarantine-minutes 0] [--clear]", cmdOpsecDecoy},
		{"opsec dhcp-name", "Güvenilmeyen ağda DHCP'ye rastgele bilgisayar adı (önce plan gösterir): [--conn BAĞLANTI] [--name AD] [--original ESKİ] [--apply | --restore]", cmdOpsecDHCPName},
		{"opsec webrtc", "Tünel dışına STUN (WebRTC) UDP'sini engeller (önce plan gösterir): --iface TÜNEL_ARAYÜZÜ [--apply | --remove]", cmdOpsecWebRTC},
		{"coordinator obfs-cert", "Koordinatörün TLS gizleme sertifikasını oluşturur veya okur ve cihazlar için SPKI sabitlemesini yazar: --state-dir KLASÖR --name AD", cmdCoordinatorObfsCert},
	}
}

// editOpsec loads the settings, applies change, validates and saves.
func editOpsec(env *Env, stateDir string, change func(*node.OpsecSettings) error) error {
	dir, err := resolveStateDir(env, stateDir)
	if err != nil {
		return err
	}
	s, err := node.LoadOpsecSettings(dir)
	if err != nil {
		return err
	}
	if err := change(&s); err != nil {
		return err
	}
	if err := node.SaveOpsecSettings(dir, s); err != nil {
		return err
	}
	fmt.Fprintln(env.Stdout, "Kaydedildi. Tünel yeniden başlayınca geçerli olur (masaüstü hizmeti veya 'openscale up').")
	return nil
}

// g3ListFlag collects a repeatable string flag.
type g3ListFlag []string

func (l *g3ListFlag) String() string     { return strings.Join(*l, ",") }
func (l *g3ListFlag) Set(v string) error { *l = append(*l, v); return nil }

func cmdOpsecShow(env *Env, args []string) error {
	fs := newFlagSet(env, "opsec show")
	stateDir := fs.String("state-dir", "", "cihazın durum klasörü")
	asJSON := fs.Bool("json", false, "JSON olarak yaz")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	dir, err := resolveStateDir(env, *stateDir)
	if err != nil {
		return err
	}
	s, err := node.LoadOpsecSettings(dir)
	if err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(env.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(s)
	}
	mode := s.Obfs.Mode
	if mode == "" {
		mode = "off"
	}
	w := env.Stdout
	fmt.Fprintf(w, "Trafik gizleme:      %s", mode)
	if len(s.Obfs.Buckets) > 0 {
		fmt.Fprintf(w, ", kovalar %v", s.Obfs.Buckets)
	}
	if s.Obfs.JitterMS > 0 {
		fmt.Fprintf(w, ", gürültü en çok %d ms", s.Obfs.JitterMS)
	}
	fmt.Fprintln(w)
	if t := s.Obfs.TLS; t != nil {
		fmt.Fprintf(w, "TCP/443 TLS:         SNI %s, %d sabitleme\n", t.ServerName, len(t.Pins))
	} else {
		fmt.Fprintln(w, "TCP/443 TLS:         kapalı")
	}
	fmt.Fprintf(w, "Çift sıçrama girişi: %s\n", orNone(s.ExitChainEntry))
	fmt.Fprintf(w, "MITM kanaryası:      %d sunucu\n", len(s.ExitCanary))
	fmt.Fprintf(w, "Çıkış DNS sabitleme: %d sabitleme, zorunlu: %s\n", len(s.ExitDNSPins), onOff(s.ExitDNSRequirePins))
	fmt.Fprintf(w, "Tuzak portlar:       %v, taramada karantina: %s\n", s.DecoyPorts, onOff(s.QuarantineOnScan))
	fmt.Fprintf(w, "Klon izleme:         %s\n", onOff(!s.CloneWatchOff))
	return nil
}

func orNone(s string) string {
	if s == "" {
		return "yok"
	}
	return s
}

func parseBuckets(s string) ([]int, error) {
	if s == "" {
		return nil, nil
	}
	var out []int
	for _, p := range strings.Split(s, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			return nil, usageError("kova %q sayı değil", p)
		}
		out = append(out, n)
	}
	return out, nil
}

func cmdOpsecObfs(env *Env, args []string) error {
	fs := newFlagSet(env, "opsec obfs")
	stateDir := fs.String("state-dir", "", "cihazın durum klasörü")
	mode := fs.String("mode", "", "off, auto veya on (zorunlu)")
	buckets := fs.String("buckets", "", "dolgu kovaları, bayt, virgülle (boş: 256,512,1280,1452)")
	jitter := fs.Duration("jitter", 0, "toplu aktarıma en çok bu kadar rastgele gecikme (0: kapalı; 1ms-100ms)")
	sni := fs.String("tls-sni", "", "TCP/443 yedeğini TLS içine al; sunucu adı (SNI)")
	var pins g3ListFlag
	fs.Var(&pins, "tls-pin", "koordinatör sertifikasının SPKI sabitlemesi (tekrarlanabilir; 'openscale coordinator obfs-cert' yazar)")
	tlsOff := fs.Bool("tls-off", false, "TLS gizlemeyi kapat")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	m, err := obfs.ParseMode(*mode)
	if err != nil || *mode == "" {
		return usageError("--mode off, auto veya on olmalı")
	}
	b, err := parseBuckets(*buckets)
	if err != nil {
		return err
	}
	return editOpsec(env, *stateDir, func(s *node.OpsecSettings) error {
		s.Obfs.Mode = m.String()
		s.Obfs.Buckets = b
		s.Obfs.JitterMS = int(*jitter / time.Millisecond)
		if m == obfs.ModeOff {
			s.Obfs.Buckets, s.Obfs.JitterMS = nil, 0
		}
		switch {
		case *tlsOff:
			s.Obfs.TLS = nil
		case *sni != "":
			s.Obfs.TLS = &obfs.ClientTLS{ServerName: *sni, Pins: pins}
		case len(pins) > 0:
			return usageError("--tls-pin için --tls-sni gerekli")
		}
		if m == obfs.ModeOn {
			fmt.Fprintln(env.Stdout, "Uyarı: 'on' kipinde bütün eşler ve koordinatör bu sürümü (gizlemeyi tanıyan) kullanmalı; emin değilsen 'auto' seç.")
		}
		return nil
	})
}

func cmdOpsecChain(env *Env, args []string) error {
	fs := newFlagSet(env, "opsec chain")
	stateDir := fs.String("state-dir", "", "cihazın durum klasörü")
	entry := fs.String("entry", "", "giriş çıkış düğümünün adı (boş: kapalı)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	return editOpsec(env, *stateDir, func(s *node.OpsecSettings) error {
		s.ExitChainEntry = *entry
		if *entry != "" {
			fmt.Fprintln(env.Stdout, "Not: zincirin motor bağlantısı kısmi (ADR-0187); durum 'openscale diag' ve panelde 'hazır, bağlı değil' görünür.")
		}
		return nil
	})
}

func cmdOpsecCanary(env *Env, args []string) error {
	fs := newFlagSet(env, "opsec canary")
	stateDir := fs.String("state-dir", "", "cihazın durum klasörü")
	var add, remove g3ListFlag
	fs.Var(&add, "add", "sunucu:port veya sunucu:port=sha256/... (tekrarlanabilir)")
	fs.Var(&remove, "remove", "çıkarılacak sunucu:port (tekrarlanabilir)")
	minutes := fs.Int("minutes", 0, "denetim aralığı, dakika (0: 30)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	return editOpsec(env, *stateDir, func(s *node.OpsecSettings) error {
		s.ExitCanary = slices.DeleteFunc(s.ExitCanary, func(t node.CanaryTarget) bool { return slices.Contains(remove, t.Address) })
		for _, a := range add {
			addr, pin, _ := strings.Cut(a, "=")
			t := node.CanaryTarget{Address: addr}
			if pin != "" {
				t.Pins = []string{pin}
			}
			s.ExitCanary = slices.DeleteFunc(s.ExitCanary, func(x node.CanaryTarget) bool { return x.Address == addr })
			s.ExitCanary = append(s.ExitCanary, t)
		}
		if *minutes != 0 {
			s.ExitCanaryMinutes = *minutes
		}
		return nil
	})
}

func cmdOpsecDNSPin(env *Env, args []string) error {
	fs := newFlagSet(env, "opsec dns-pin")
	stateDir := fs.String("state-dir", "", "cihazın durum klasörü")
	var pins g3ListFlag
	fs.Var(&pins, "pin", "sha256/<base64> (tekrarlanabilir)")
	require := fs.Bool("require", false, "sabitlenmemiş üst çözücüye hiç sorma (sorgular düşer)")
	clearAll := fs.Bool("clear", false, "sabitlemeleri kaldır")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	return editOpsec(env, *stateDir, func(s *node.OpsecSettings) error {
		if *clearAll {
			s.ExitDNSPins, s.ExitDNSRequirePins = nil, false
			return nil
		}
		if len(pins) == 0 && !*require {
			return usageError("--pin veya --require gerekli")
		}
		if len(pins) > 0 {
			s.ExitDNSPins = pins
		}
		s.ExitDNSRequirePins = *require
		fmt.Fprintln(env.Stdout, "Not: sabitleme yalnızca https:// veya tls:// --exit-dns-upstream ile çalışır; tünel başlarken denetlenir.")
		return nil
	})
}

func cmdOpsecDecoy(env *Env, args []string) error {
	fs := newFlagSet(env, "opsec decoy")
	stateDir := fs.String("state-dir", "", "cihazın durum klasörü")
	ports := fs.String("ports", "", "tuzak portlar: ssh, rdp, smb veya sayı, virgülle (bu cihazda gerçekten çalışmayan portlar)")
	onScan := fs.Bool("quarantine-on-scan", false, "port taramasında süreli engel yerine karantina")
	minutes := fs.Int("quarantine-minutes", 0, "karantina süresi, dakika (0: sahip kaldırana dek)")
	clearAll := fs.Bool("clear", false, "tuzakları ve taramada karantinayı kapat")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	var list []uint16
	if *ports != "" {
		var err error
		if list, err = filter.DecoyPortsFor(strings.Split(*ports, ",")); err != nil {
			return err
		}
	}
	return editOpsec(env, *stateDir, func(s *node.OpsecSettings) error {
		if *clearAll {
			s.DecoyPorts, s.QuarantineOnScan, s.QuarantineMinutes = nil, false, 0
			return nil
		}
		s.DecoyPorts, s.QuarantineOnScan, s.QuarantineMinutes = list, *onScan, *minutes
		return nil
	})
}

// printPlan writes the planned commands.
func printPlan(env *Env, title string, cmds []osnet.Command) {
	fmt.Fprintln(env.Stdout, title)
	for _, c := range cmds {
		fmt.Fprintln(env.Stdout, "  "+c.String())
	}
}

func cmdOpsecDHCPName(env *Env, args []string) error {
	fs := newFlagSet(env, "opsec dhcp-name")
	conn := fs.String("conn", "", "Linux: NetworkManager bağlantı adı; macOS: arayüz (ör. en0)")
	name := fs.String("name", "", "gönderilecek ad (boş: rastgele)")
	original := fs.String("original", "", "geri almada kullanılacak eski ad")
	apply := fs.Bool("apply", false, "planı şimdi uygula (yönetici yetkisi; sistem ayarını değiştirir)")
	restore := fs.Bool("restore", false, "eski adı geri yükle")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *apply && *restore {
		return usageError("--apply ve --restore birlikte kullanılamaz")
	}
	n := *name
	if n == "" {
		var err error
		if n, err = osnet.RandomHostname(runtime.GOOS, nil); err != nil {
			return err
		}
	}
	applyCmds, restoreCmds, err := osnet.DHCPHostnamePlan(runtime.GOOS, *conn, n, *original)
	if err != nil {
		return err
	}
	printPlan(env, "Uygulama planı:", applyCmds)
	if len(restoreCmds) > 0 {
		printPlan(env, "Geri alma planı:", restoreCmds)
	}
	switch {
	case *apply:
		if err := osnet.RunPlan(envContext(env), applyCmds, nil); err != nil {
			return err
		}
		fmt.Fprintf(env.Stdout, "DHCP isteğinde artık %q gönderilecek.\n", n)
	case *restore:
		if len(restoreCmds) == 0 {
			return usageError("geri almak için --original gerekli")
		}
		return osnet.RunPlan(envContext(env), restoreCmds, nil)
	default:
		fmt.Fprintln(env.Stdout, "Hiçbir şey değiştirilmedi. Uygulamak için --apply ekle.")
	}
	return nil
}

func cmdOpsecWebRTC(env *Env, args []string) error {
	fs := newFlagSet(env, "opsec webrtc")
	iface := fs.String("iface", "", "tünel arayüzünün adı (zorunlu)")
	apply := fs.Bool("apply", false, "engeli şimdi kur (yönetici yetkisi)")
	remove := fs.Bool("remove", false, "engeli kaldır")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *apply && *remove {
		return usageError("--apply ve --remove birlikte kullanılamaz")
	}
	applyCmds, removeCmds, err := osnet.STUNBlockPlan(runtime.GOOS, *iface)
	if err != nil {
		return err
	}
	printPlan(env, "Kurma planı:", applyCmds)
	printPlan(env, "Kaldırma planı:", removeCmds)
	switch {
	case *apply:
		return osnet.RunPlan(envContext(env), applyCmds, nil)
	case *remove:
		return osnet.RunPlan(envContext(env), removeCmds, nil)
	}
	fmt.Fprintln(env.Stdout, "Hiçbir şey değiştirilmedi. Kurmak için --apply ekle.")
	return nil
}

func cmdCoordinatorObfsCert(env *Env, args []string) error {
	fs := newFlagSet(env, "coordinator obfs-cert")
	stateDir := fs.String("state-dir", "", "koordinatörün durum klasörü (zorunlu)")
	var names g3ListFlag
	fs.Var(&names, "name", "sertifikadaki ad (tekrarlanabilir; cihazların SNI değeri ilk addır)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *stateDir == "" || len(names) == 0 {
		return usageError("--state-dir ve --name zorunlu")
	}
	_, pin, err := obfs.LoadOrCreateCertificate(*stateDir, names, env.Now())
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "SPKI sabitlemesi: %s\n", pin)
	fmt.Fprintf(env.Stdout, "Cihazlarda: openscale opsec obfs --mode auto --tls-sni %s --tls-pin %s\n", names[0], pin)
	return nil
}
