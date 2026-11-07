package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	iofs "io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/cloudinit"
	"github.com/openscale/openscale/internal/coordinator"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/release"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/srvaudit"
	"github.com/openscale/openscale/internal/updater"
	"github.com/openscale/openscale/internal/usage"
)

// Coordinator and server operations (P09, ADR-0153): server audit (#478),
// external surface check (#479), cloud-init user data (#480), failover
// drill (#481), relay usage (#482) and the coordinator migration
// preflight (#485).

func serverOpsCommands() []command {
	return []command{
		{"server audit", "Sunucu sertleştirmesini salt okunur denetler ve puanlar (Linux; root önerilir): [--role coordinator|exit] [--json]", cmdServerAudit},
		{"server surface", "Koordinatörün dış yüzeyini tünel dışından yoklar: UDP portu açık mı, tanımadığı paketlere sessiz mi, başka TCP portu açık mı", cmdServerSurface},
		{"server cloud-init", "VPS için cloud-init user-data üretir (koordinatör veya çıkış düğümü; paket imzalı manifestoyla sabitlenir)", cmdServerCloudInit},
		{"coordinator usage", "Aktarıcının cihaz başına aylık aktardığı bayt toplamını gösterir (yalnızca toplam; akış/hedef tutulmaz)", cmdCoordinatorUsage},
		{"coordinator reach", "Çalışan koordinatöre hangi cihazların kendi anahtarıyla el sıkıştığını sorar: [--save dosya]", cmdCoordinatorReach},
		{"coordinator preflight", "Taşıma ön denetimi: hedef koordinatöre ulaşamayan çevrimiçi cihazları listeler: [--online birincil.json] [--save sonuç.json]", cmdCoordinatorPreflight},
		{"coordinator drill", "Yük devretme tatbikatı: koordinatörü süreli sessize alır ve cihazların dönüşünü ölçer: --duration 5m | --cancel | --status", cmdCoordinatorDrill},
	}
}

const opsTimeout = 10 * time.Second

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func parsePorts(s string) ([]uint16, error) {
	var out []uint16
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		n, err := strconv.ParseUint(f, 10, 16)
		if err != nil || n == 0 {
			return nil, usageError("geçersiz port %q", f)
		}
		out = append(out, uint16(n))
	}
	return out, nil
}

func printChecks(w io.Writer, checks []srvaudit.Check) {
	for _, c := range checks {
		fmt.Fprintf(w, "  [%-10s] %-36s %s\n", c.Status.Label(), c.Title, c.Detail)
		if c.Fix != "" && c.Status != srvaudit.Pass {
			fmt.Fprintf(w, "  %-12s %-36s öneri: %s\n", "", "", c.Fix)
		}
	}
}

// --- #478 ---

func cmdServerAudit(env *Env, args []string) error {
	fs := newFlagSet(env, "server audit")
	role := fs.String("role", srvaudit.RoleCoordinator, "sunucunun rolü: coordinator veya exit")
	expectUDP := fs.String("expect-udp", "", "dışarıya açık olması beklenen UDP portları, virgülle (varsayılan: rolün WireGuard portu)")
	expectTCP := fs.String("expect-tcp", "", "dışarıya açık olması beklenen TCP portları, virgülle (varsayılan: 22 ve koordinatörün TCP taşıma portu)")
	minScore := fs.Int("min-score", 0, "puan bunun altındaysa hata koduyla çık (0-100)")
	asJSON := fs.Bool("json", false, "JSON çıktı")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *role != srvaudit.RoleCoordinator && *role != srvaudit.RoleExit {
		return usageError("--role coordinator veya exit olmalı")
	}
	if *minScore < 0 || *minScore > 100 {
		return usageError("--min-score 0 ile 100 arasında olmalı")
	}
	udp, err := parsePorts(*expectUDP)
	if err != nil {
		return err
	}
	tcp, err := parsePorts(*expectTCP)
	if err != nil {
		return err
	}
	rep, err := srvaudit.Audit(srvaudit.Options{Role: *role, ExpectUDP: udp, ExpectTCP: tcp})
	if err != nil {
		return err
	}
	if *asJSON {
		if err := writeJSON(env.Stdout, rep); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(env.Stdout, "Sunucu sertleştirme denetimi (%s): %d/100\n", rep.Role, rep.Score)
		printChecks(env.Stdout, rep.Checks)
		fmt.Fprintln(env.Stdout, "Denetim yalnızca okur; hiçbir ayarı değiştirmez. Sonuç sunucunun kendi beyanıdır (ADR-0109).")
	}
	if rep.Score < *minScore {
		return fmt.Errorf("puan %d, istenen en az %d", rep.Score, *minScore)
	}
	return nil
}

// --- #479 ---

func cmdServerSurface(env *Env, args []string) error {
	fs := newFlagSet(env, "server surface")
	stateDir := fs.String("state-dir", "", "cihazın durum klasörü; koordinatör adresleri belgeden okunur (varsayılan: kullanıcı yapılandırma klasörü)")
	endpoint := fs.String("endpoint", "", "yoklanacak adres host:port (varsayılan: belgedeki bütün koordinatörler)")
	tcpPorts := fs.String("tcp-ports", "", "denenecek TCP portları, virgülle (varsayılan: sık açık bırakılan 18 port)")
	allowTCP := fs.String("allow-tcp", "22", "açık olması beklenen TCP portları (SSH, TCP taşıması), virgülle")
	timeout := fs.Duration("timeout", 2*time.Second, "her yanıt için bekleme süresi (200ms-10s)")
	asJSON := fs.Bool("json", false, "JSON çıktı")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *timeout < 200*time.Millisecond || *timeout > 10*time.Second {
		return usageError("--timeout 200ms ile 10s arasında olmalı")
	}
	allow, err := parsePorts(*allowTCP)
	if err != nil {
		return err
	}
	var ports []uint16
	if *tcpPorts != "" {
		if ports, err = parsePorts(*tcpPorts); err != nil {
			return err
		}
	}
	targets := []string{}
	if *endpoint != "" {
		targets = append(targets, strings.TrimSpace(*endpoint))
	} else {
		dir, err := resolveStateDir(env, *stateDir)
		if err != nil {
			return err
		}
		store, err := member.Open(dir)
		if err != nil {
			return err
		}
		for _, c := range store.Document().UsableCoordinators(env.Now()) {
			targets = append(targets, c.Endpoint)
		}
		if len(targets) == 0 {
			return errors.New("belgede koordinatör yok; --endpoint verin")
		}
	}
	var results []srvaudit.SurfaceResult
	worst := 100
	for _, t := range targets {
		res, err := srvaudit.Probe(envContext(env), srvaudit.SurfaceOptions{Endpoint: t, TCPPorts: ports, AllowTCP: allow, Timeout: *timeout})
		if err != nil {
			return fmt.Errorf("%s: %w", t, err)
		}
		results = append(results, res)
		worst = min(worst, res.Score)
		if !*asJSON {
			fmt.Fprintf(env.Stdout, "%s (%s): %d/100\n", res.Endpoint, res.Address, res.Score)
			printChecks(env.Stdout, res.Checks)
		}
	}
	if *asJSON {
		if err := writeJSON(env.Stdout, results); err != nil {
			return err
		}
	} else {
		fmt.Fprintln(env.Stdout, "Yoklama tünel dışından, bu cihazın internet bağlantısıyla yapıldı; yalnızca yukarıdaki adreslere paket gönderildi.")
	}
	if worst < 100 {
		return errors.New("dış yüzeyde sorun var")
	}
	return nil
}

// --- #480 ---

func cmdServerCloudInit(env *Env, args []string) error {
	fs := newFlagSet(env, "server cloud-init")
	role := fs.String("role", cloudinit.RoleCoordinator, "coordinator veya exit")
	hostname := fs.String("hostname", "openscale", "sunucu adı")
	var sshKeys multiFlag
	fs.Var(&sshKeys, "ssh-key", "yönetici SSH açık anahtarı (\"ssh-ed25519 AAAA... ad\" veya @dosya.pub); tekrarlanabilir, en az bir tane")
	manifest := fs.String("manifest", "", "imzalı sürüm manifestosu (openscale-<sürüm>.release.json; zorunlu)")
	rootKey := fs.String("root-key", "", "sürüm kök açık anahtarı (varsayılan: programa gömülü)")
	revocations := fs.String("revocations", "", "kök imzalı iptal listesi; bu cihazdaki, programa gömülü ve manifestonun yanındaki liste her durumda uygulanır")
	pkgURL := fs.String("package-url", "", "sunucunun .deb paketini indireceği https adresi, ör. https://indirme.ornek.com/openscale_1.2.3_amd64.deb (zorunlu)")
	arch := fs.String("arch", "amd64", "sunucunun mimarisi: amd64 veya arm64")
	authKey := fs.String("auth-key", "", "çıkış düğümü için ön onaylı kayıt anahtarı veya @dosya ('device preauth --exit-node')")
	listenPort := fs.Int("listen-port", 0, "WireGuard UDP portu (0: koordinatör 41820, çıkış düğümü 41821)")
	tcpListen := fs.Int("tcp-listen", 0, "koordinatörün TCP taşıma portu, ör. 443 (0: kapalı)")
	out := fs.String("out", "", "yazılacak user-data dosyası (zorunlu; '-' ekrana)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *manifest == "" || *pkgURL == "" || *out == "" {
		return usageError("--manifest, --package-url ve --out zorunlu")
	}
	if *arch != "amd64" && *arch != "arm64" {
		return usageError("--arch amd64 veya arm64 olmalı")
	}
	root, where, err := updater.LoadRootKey(*rootKey)
	if err != nil {
		return err
	}
	data, err := securefile.ReadLimited(*manifest, release.MaxSignedReleaseSize)
	if err != nil {
		return err
	}
	// SECURITY FIX: CWE-299 a revoked signing key must not reach a new server
	// through this path either (ADR-0195).
	list, err := cloudInitRevocations(env, root, *manifest, *revocations)
	if err != nil {
		return err
	}
	v, err := release.Verify(root, data, release.VerifyOptions{Now: env.Now(), Revocations: list})
	if err != nil {
		return fmt.Errorf("manifesto doğrulanamadı: %w", err)
	}
	var art *release.Artifact
	for i, a := range v.Manifest.Artifacts {
		if strings.HasPrefix(a.Name, "openscale_") && strings.HasSuffix(a.Name, "_"+*arch+".deb") {
			if art != nil {
				return errors.New("manifestoda bu mimari için birden çok .deb var")
			}
			art = &v.Manifest.Artifacts[i]
		}
	}
	if art == nil {
		return fmt.Errorf("manifestoda %s için .deb yok", *arch)
	}
	if !strings.HasSuffix(*pkgURL, "/"+art.Name) {
		fmt.Fprintf(env.Stderr, "uyarı: adres %s ile bitmiyor; dosya adı farklıysa da özet denetimi korur.\n", art.Name)
	}
	keys := make([]string, 0, len(sshKeys))
	for _, k := range sshKeys {
		text, err := readArg(k, 64<<10)
		if err != nil {
			return err
		}
		for _, line := range strings.Split(text, "\n") {
			if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
				keys = append(keys, line)
			}
		}
	}
	auth := ""
	if *authKey != "" {
		if auth, err = readArg(*authKey, 4<<20); err != nil {
			return err
		}
		auth = strings.TrimSpace(auth)
	}
	o := cloudinit.Options{
		Role: *role, Hostname: *hostname, SSHKeys: keys, PackageURL: strings.TrimSpace(*pkgURL),
		PackageSHA256: strings.ToLower(art.SHA256), PackageSize: art.Size, ListenPort: *listenPort, TCPListen: *tcpListen, AuthKey: auth,
	}
	ud, err := cloudinit.Generate(o)
	if err != nil {
		return err
	}
	if *out == "-" {
		_, err = env.Stdout.Write(ud)
		return err
	}
	if err := securefile.Replace(*out, ud); err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "user-data yazıldı: %s (%d bayt; sürüm %s, kök anahtar %s)\n", *out, len(ud), v.Manifest.Version, where)
	fmt.Fprintf(env.Stdout, "Paket: %s, SHA-256 %s\n", art.Name, art.SHA256)
	if len(ud) > cloudinit.WarnUserData {
		fmt.Fprintf(env.Stdout, "Not: dosya %d bayttan büyük; bazı sağlayıcılar daha büyük user-data kabul etmez.\n", cloudinit.WarnUserData)
	}
	if *role == cloudinit.RoleExit {
		fmt.Fprintln(env.Stdout, "UYARI: dosya ön onaylı kayıt anahtarını içerir; sağlayıcı user-data'yı okuyabilir. Kısa ömürlü anahtar kullanın ve kurulumdan sonra user-data'yı sağlayıcı panelinden silin.")
	} else {
		fmt.Fprintln(env.Stdout, "Sunucu açıldığında koordinatör anahtarının parmak izi konsola ve /root/openscale-coordinator.txt dosyasına yazılır; ardından 'network set-coordinator' (docs/sunucu-kurulumu.md).")
	}
	return nil
}

// cloudInitRevocations returns the list to enforce on a manifest used for a
// new server. This command often runs on an owner's own computer as an
// ordinary user: an update folder that user may not read only leaves the other
// lists, with a warning; every other failure refuses.
func cloudInitRevocations(env *Env, root release.PublicKey, manifest, givenFile string) (*release.Revocations, error) {
	var given *release.Revocations
	if givenFile != "" {
		data, err := securefile.ReadLimited(givenFile, release.MaxRevocationsSize)
		if err != nil {
			return nil, err
		}
		if given, err = release.VerifyRevocations(root, data); err != nil {
			return nil, fmt.Errorf("iptal listesi doğrulanamadı: %w", err)
		}
	}
	published, err := securefile.ReadLimited(filepath.Join(filepath.Dir(manifest), updater.RevocationsFile), release.MaxRevocationsSize)
	if err != nil && !errors.Is(err, iofs.ErrNotExist) {
		return nil, fmt.Errorf("iptal listesi okunamadı: %w", err)
	}
	logf := func(format string, args ...any) { fmt.Fprintf(env.Stdout, format+"\n", args...) }
	stateDir := ""
	if p, err := updater.DefaultPlatform(); err == nil {
		stateDir = p.StateDir
	}
	list, err := updater.EnforcedRevocations(stateDir, root, given, published, logf)
	if errors.Is(err, iofs.ErrPermission) {
		fmt.Fprintf(env.Stderr, "uyarı: güncelleme klasörü (%s) okunamadı; bu cihazın kayıtlı iptal listesi uygulanmadı.\n", stateDir)
		list, err = updater.EnforcedRevocations("", root, given, published, logf)
	}
	if err != nil {
		return nil, err
	}
	if list == nil {
		fmt.Fprintln(env.Stderr, "uyarı: imzalı iptal listesi yok; iptal edilmiş bir imzalama anahtarı tanınamaz. --revocations ile verebilirsiniz.")
	}
	return list, nil
}

// --- #482 ---

func cmdCoordinatorUsage(env *Env, args []string) error {
	fs := newFlagSet(env, "coordinator usage")
	stateDir := fs.String("state-dir", "", "koordinatörün durum klasörü (zorunlu)")
	month := fs.String("month", "", "ay, ör. 2026-10 (varsayılan: bu ay)")
	asJSON := fs.Bool("json", false, "JSON çıktı")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *stateDir == "" {
		return usageError("--state-dir zorunlu")
	}
	m, err := coordinator.ReadRelayUsage(*stateDir)
	if err != nil {
		return err
	}
	want := *month
	if want == "" {
		want = usage.MonthOf(env.Now())
	}
	names := map[string]string{}
	if store, err := member.Open(*stateDir); err == nil {
		for _, d := range store.Document().Devices {
			names[d.ID] = d.Name
		}
	}
	type row struct {
		Device string `json:"device"`
		ID     string `json:"id"`
		Bytes  uint64 `json:"bytes"`
	}
	var rows []row
	var total uint64
	for _, mo := range m.Snapshot() {
		if mo.Month != want {
			continue
		}
		for id, n := range mo.Bytes {
			name := names[id]
			if name == "" {
				name = "(belgede yok)"
			}
			rows = append(rows, row{Device: name, ID: id, Bytes: n})
			total += n
		}
	}
	slices.SortFunc(rows, func(a, b row) int {
		if a.Bytes != b.Bytes {
			if a.Bytes > b.Bytes {
				return -1
			}
			return 1
		}
		return strings.Compare(a.Device, b.Device)
	})
	if *asJSON {
		return writeJSON(env.Stdout, map[string]any{"schema": 1, "month": want, "total": total, "devices": rows})
	}
	fmt.Fprintf(env.Stdout, "Aktarıcı kullanımı %s (cihazın aktarıcıya gönderdiği bayt; dakikada bir kaydedilir):\n", want)
	if len(rows) == 0 {
		fmt.Fprintln(env.Stdout, "  Bu ay aktarıcıdan geçen trafik yok.")
		return nil
	}
	for _, r := range rows {
		fmt.Fprintf(env.Stdout, "  %-28s %12s\n", r.Device, humanBytes(r.Bytes))
	}
	fmt.Fprintf(env.Stdout, "  %-28s %12s\n", "Toplam", humanBytes(total))
	return nil
}

// --- #485 ---

func requestReach(env *Env, dir string) (coordinator.ReachReport, error) {
	reply, err := coordinator.RequestOp(envContext(env), dir, coordinator.OpReach, 0, opsTimeout)
	if err != nil {
		return coordinator.ReachReport{}, err
	}
	if reply.Reach == nil {
		return coordinator.ReachReport{}, errors.New("koordinatör erişim raporu göndermedi")
	}
	return *reply.Reach, nil
}

func cmdCoordinatorReach(env *Env, args []string) error {
	fs := newFlagSet(env, "coordinator reach")
	stateDir := fs.String("state-dir", "", "koordinatörün durum klasörü (zorunlu; koordinatörün kullanıcısı veya root olarak)")
	save := fs.String("save", "", "raporu bu dosyaya da yaz (diğer koordinatörde --online ile kullanılır)")
	asJSON := fs.Bool("json", false, "JSON çıktı")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *stateDir == "" {
		return usageError("--state-dir zorunlu")
	}
	r, err := requestReach(env, *stateDir)
	if err != nil {
		return err
	}
	if *save != "" {
		data, err := json.Marshal(r)
		if err != nil {
			return err
		}
		if err := securefile.Replace(*save, data); err != nil {
			return err
		}
	}
	if *asJSON {
		return writeJSON(env.Stdout, r)
	}
	role := "ek"
	if r.Primary {
		role = "birincil"
	}
	reached := 0
	for _, d := range r.Devices {
		state := "ulaşmıyor"
		if d.Reached {
			state, reached = "ulaşıyor", reached+1
		}
		last := "-"
		if !d.LastHandshake.IsZero() {
			hs := d.LastHandshake
			last = ago(&hs, env.Now())
		}
		fmt.Fprintf(env.Stdout, "  %-28s %-10s son el sıkışma: %s\n", d.Name, state, last)
	}
	fmt.Fprintf(env.Stdout, "Koordinatör %s (%s): %d/%d cihaz son %d sn içinde el sıkıştı.\n", r.Fingerprint, role, reached, len(r.Devices), r.WindowS)
	return nil
}

func cmdCoordinatorPreflight(env *Env, args []string) error {
	fs := newFlagSet(env, "coordinator preflight")
	stateDir := fs.String("state-dir", "", "hedef (ek) koordinatörün durum klasörü (zorunlu)")
	online := fs.String("online", "", "birincil koordinatörde 'coordinator reach --save' ile alınan rapor; yoksa ulaşmayan her cihaz sorunlu sayılır")
	save := fs.String("save", "", "sonucu bu dosyaya yaz ('network coordinator promote --preflight' için)")
	asJSON := fs.Bool("json", false, "JSON çıktı")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *stateDir == "" {
		return usageError("--state-dir zorunlu")
	}
	var onlineRep *coordinator.ReachReport
	if *online != "" {
		data, err := securefile.ReadLimited(*online, 4<<20)
		if err != nil {
			return err
		}
		var r coordinator.ReachReport
		if err := json.Unmarshal(data, &r); err != nil {
			return fmt.Errorf("--online raporu okunamadı: %w", err)
		}
		onlineRep = &r
	}
	target, err := requestReach(env, *stateDir)
	if err != nil {
		return err
	}
	res, err := coordinator.Preflight(target, onlineRep)
	if err != nil {
		return err
	}
	if *save != "" {
		data, err := json.Marshal(res)
		if err != nil {
			return err
		}
		if err := securefile.Replace(*save, data); err != nil {
			return err
		}
	}
	if *asJSON {
		if err := writeJSON(env.Stdout, res); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(env.Stdout, "Taşıma ön denetimi, hedef koordinatör %s:\n", res.Fingerprint)
		fmt.Fprintf(env.Stdout, "  Ulaşan:       %s\n", listOrDash(res.Reachable))
		fmt.Fprintf(env.Stdout, "  ULAŞAMAYAN:   %s\n", listOrDash(res.Unreachable))
		if res.Compared {
			fmt.Fprintf(env.Stdout, "  Çevrimdışı:   %s (geçiş süresinde eski koordinatörden öğrenir)\n", listOrDash(res.Offline))
		} else {
			fmt.Fprintln(env.Stdout, "  Not: --online verilmedi; çevrimdışı cihazlar da ulaşamayan sayıldı.")
		}
	}
	if err := coordinator.CheckPreflight(res, res.Coordinator, res.At); err != nil {
		return fmt.Errorf("ön denetim geçmedi: %w", err)
	}
	if !*asJSON {
		fmt.Fprintln(env.Stdout, "Ön denetim geçti: 'network coordinator promote --preflight <sonuç.json>' ile imzalayabilirsiniz.")
	}
	return nil
}

func listOrDash(l []string) string {
	if len(l) == 0 {
		return "-"
	}
	return strings.Join(l, ", ")
}

// checkPromotePreflight is the #485 gate of 'network coordinator promote'.
func checkPromotePreflight(env *Env, path, key string) error {
	if path == "" {
		fmt.Fprintln(env.Stderr, "uyarı: taşıma ön denetimi yapılmadı. Yeni koordinatörde 'openscale coordinator preflight --online <birincil.json> --save sonuç.json' çalıştırıp --preflight sonuç.json ile imzalamanız önerilir (#485).")
		return nil
	}
	data, err := securefile.ReadLimited(path, 4<<20)
	if err != nil {
		return err
	}
	res, err := coordinator.ParsePreflight(data)
	if err != nil {
		return err
	}
	if err := coordinator.CheckPreflight(res, key, env.Now()); err != nil {
		return fmt.Errorf("ön denetim imzalamaya izin vermiyor: %w", err)
	}
	if !res.Compared {
		fmt.Fprintln(env.Stderr, "uyarı: ön denetim birincil koordinatörün raporu olmadan yapılmış.")
	}
	return nil
}

// --- #481 ---

func cmdCoordinatorDrill(env *Env, args []string) error {
	fs := newFlagSet(env, "coordinator drill")
	stateDir := fs.String("state-dir", "", "tatbikat yapılacak koordinatörün durum klasörü (zorunlu)")
	duration := fs.Duration("duration", 0, fmt.Sprintf("sessiz kalma süresi (%s-%s)", coordinator.MinDrill, coordinator.MaxDrill))
	cancel := fs.Bool("cancel", false, "süren tatbikatın sessizliğini hemen bitir")
	status := fs.Bool("status", false, "son tatbikatın raporunu göster")
	asJSON := fs.Bool("json", false, "JSON çıktı")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *stateDir == "" {
		return usageError("--state-dir zorunlu")
	}
	modes := 0
	for _, b := range []bool{*duration != 0, *cancel, *status} {
		if b {
			modes++
		}
	}
	if modes != 1 {
		return usageError("--duration, --cancel veya --status seçeneklerinden yalnızca biri")
	}
	if *status {
		rep, err := coordinator.ReadDrillReport(*stateDir)
		if errors.Is(err, os.ErrNotExist) {
			fmt.Fprintln(env.Stdout, "Bu koordinatörde henüz tatbikat yapılmamış.")
			return nil
		}
		if err != nil {
			return err
		}
		return printDrill(env, rep, *asJSON)
	}
	if *duration != 0 && (*duration < coordinator.MinDrill || *duration > coordinator.MaxDrill) {
		return usageError("--duration %s ile %s arasında olmalı", coordinator.MinDrill, coordinator.MaxDrill)
	}
	op := coordinator.OpDrill
	if *cancel {
		op = coordinator.OpDrillCancel
	}
	ctx, stop := context.WithTimeout(envContext(env), opsTimeout+time.Second)
	defer stop()
	reply, err := coordinator.RequestOp(ctx, *stateDir, op, *duration, opsTimeout)
	if err != nil {
		return err
	}
	if reply.Drill == nil {
		return errors.New("koordinatör tatbikat raporu göndermedi")
	}
	if err := printDrill(env, *reply.Drill, *asJSON); err != nil {
		return err
	}
	if !*asJSON && op == coordinator.OpDrill {
		fmt.Fprintln(env.Stdout, "Sessizlik sürerken diğer koordinatörde 'openscale coordinator reach' cihazların oraya geçtiğini gösterir. Sonuç için: openscale coordinator drill --status")
	}
	return nil
}

func printDrill(env *Env, r coordinator.DrillReport, asJSON bool) error {
	if asJSON {
		return writeJSON(env.Stdout, r)
	}
	state := map[string]string{coordinator.DrillQuiet: "sessiz", coordinator.DrillObserving: "dönüşler bekleniyor", coordinator.DrillDone: "bitti"}[r.State]
	fmt.Fprintf(env.Stdout, "Tatbikat (%s): %s\n", r.Coordinator, state)
	fmt.Fprintf(env.Stdout, "  Sessizlik: %s - %s (kullanılabilir koordinatör: %d)\n", r.Started.Format(time.RFC3339), r.QuietUntil.Format(time.RFC3339), r.Coordinators)
	if r.Cancelled {
		fmt.Fprintln(env.Stdout, "  Sessizlik elle erken bitirildi.")
	}
	fmt.Fprintf(env.Stdout, "  Önce bağlı: %d cihaz (%s)\n", len(r.Before), listOrDash(r.Before))
	for _, d := range r.Returned {
		fmt.Fprintf(env.Stdout, "  Döndü:      %-24s %.0f sn sonra\n", d.Name, d.AfterS)
	}
	if r.State == coordinator.DrillDone {
		fmt.Fprintf(env.Stdout, "  Dönmeyen:   %s\n", listOrDash(r.Missing))
	}
	return nil
}
