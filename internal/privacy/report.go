package privacy

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

// The privacy report (#50) answers, from local files only: which data this
// computer keeps and where, what the coordinator can see, which peers were
// reached lately and which settings carry a leak risk. It never opens a
// network connection and never prints a key.

// Severity of a finding.
const (
	SeverityInfo = "bilgi"
	SeverityWarn = "uyarı"
)

// Sensitivity classes of stored files.
const (
	ClassSecret  = "gizli" // keys and tokens
	ClassPrivate = "özel"  // metadata about the network and its use
	ClassOther   = "diğer" // not created by OpenScale or unknown
	maxReadSize  = 1 << 20 // settings and caches are far smaller
	maxListFiles = 500
)

// DataDir is one directory the report inspects.
type DataDir struct {
	Path string `json:"path"`
	// Kind is "servis" (the Windows service) or "cli" (a state directory
	// used by "openscale up" or "coordinator run").
	Kind string `json:"kind"`
}

// ReportOptions are the report inputs.
type ReportOptions struct {
	Dirs []DataDir
	Now  time.Time
	// OSHostname is the computer name (os.Hostname).
	OSHostname string
	// Hardening is the status of the process making the report.
	Hardening HardeningStatus
}

// StoredFile is one file in a data directory.
type StoredFile struct {
	Path        string `json:"path"`
	Description string `json:"description"`
	Class       string `json:"class"`
	Size        int64  `json:"size"`
	Mode        string `json:"mode,omitempty"`
}

// Store is one inspected directory.
type Store struct {
	DataDir
	Exists bool         `json:"exists"`
	Error  string       `json:"error,omitempty"`
	Files  []StoredFile `json:"files,omitempty"`
}

// RecentPeer is a peer (or the coordinator) last seen at an address.
type RecentPeer struct {
	Name     string    `json:"name"`
	Endpoint string    `json:"endpoint"`
	Seen     time.Time `json:"seen"`
}

// Finding is a privacy-relevant setting or condition.
type Finding struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Text     string `json:"text"`
}

// Report is the whole privacy report.
type Report struct {
	GeneratedAt      time.Time       `json:"generated_at"`
	Stores           []Store         `json:"stores"`
	CoordinatorSees  []string        `json:"coordinator_sees"`
	CoordinatorNever []string        `json:"coordinator_never_sees"`
	Recent           []RecentPeer    `json:"recent"`
	Findings         []Finding       `json:"findings"`
	Hardening        HardeningStatus `json:"hardening"`
}

// fileClasses describes the files OpenScale writes, by base name.
var fileClasses = map[string][2]string{
	"device.key":           {ClassSecret, "cihazın özel anahtarları (WireGuard ve imza)"},
	"device.key.next":      {ClassSecret, "onay bekleyen yeni cihaz anahtarı"},
	"coordinator.key":      {ClassSecret, "koordinatörün özel anahtarı"},
	"root.key":             {ClassSecret, "ağın kök anahtarı (parolayla şifreli)"},
	"app.token":            {ClassSecret, "tepsi ve panel erişim belirteci"},
	"ssh_host_ed25519_key": {ClassSecret, "gömülü SSH sunucusunun anahtarı"},
	"anchor.json":          {ClassPrivate, "ağ kimliği ve kök anahtarın açık parmak izi"},
	"network.json":         {ClassPrivate, "imzalı ağ belgesi: cihaz adları, IP adresleri, kurallar"},
	"state.json":           {ClassPrivate, "kabul edilen en yüksek belge sürümü (geri alma koruması)"},
	"endpoints.json":       {ClassPrivate, "eşlerin son görüldüğü genel adresler (7 gün sonra silinir)"},
	"settings.json":        {ClassPrivate, "ayarlar: çıkış düğümü, koordinatör adres önbelleği, tercihler"},
	"backups.json":         {ClassPrivate, "kök anahtar yedeklerinin tarih ve etiketleri"},
	"service.log":          {ClassPrivate, "servis günlüğü (info ve üzerinde IP adresleri maskeli)"},
	"service.log.1":        {ClassPrivate, "döndürülmüş eski servis günlüğü"},
	"autoaccept.json":      {ClassPrivate, "dosya alma: otomatik kabul edilen cihazlar"},
	"received.json":        {ClassPrivate, "alınan dosyaların kaydı"},
	"wake-macs.json":       {ClassPrivate, "uyandırılabilecek cihazların MAC adresleri"},
	"known_hosts":          {ClassPrivate, "bağlanılan SSH sunucularının anahtarları"},
	"local-api.json":       {ClassSecret, "yerel API adresi ve erişim belirteci"},
	"panel-readonly":       {ClassPrivate, "panelin salt okunur olduğunu gösteren işaret"},
	"panel-remote.json":    {ClassSecret, "panele uzaktan erişim anahtarı ve uzak erişim parolasının Argon2id özeti (ADR-0107)"},
	"api-keys.json":        {ClassSecret, "salt okunur yönetim API anahtarlarının SHA-256 özetleri (ADR-0107)"},
	"webhook.json":         {ClassSecret, "olay webhook hedefi ve HMAC sırrı (ADR-0108)"},
	"ca.key":               {ClassSecret, "iç sertifika otoritesinin özel anahtarı (yalnızca dağıtıcı cihazda, ADR-0138)"},
	"ca.crt":               {ClassOther, "iç sertifika otoritesinin sertifikası (açık, ADR-0138)"},
	"tls.key":              {ClassSecret, "tünel içi servislerin TLS özel anahtarı (ADR-0138)"},
	"tls.crt":              {ClassPrivate, "tünel içi servislerin TLS sertifikası: cihaz adları ve tünel adresleri (ADR-0138)"},
	"serve.json":           {ClassPrivate, "tünelde yayınlanan servisler, hedef adresleri ve OIDC istemci sır özetleri (ADR-0139)"},
	"oidc.key":             {ClassSecret, "kimlik sağlayıcının imza anahtarı (ADR-0140)"},
	"wintun.dll":           {ClassOther, "WireGuard sürücü kitaplığı"},
}

func classify(rel string) (string, string) {
	base := filepath.Base(rel)
	if c, ok := fileClasses[base]; ok {
		return c[0], c[1]
	}
	if strings.HasPrefix(base, "v") && strings.HasSuffix(base, ".json") && strings.Contains(filepath.ToSlash(rel), "history") {
		return ClassPrivate, "ağ belgesinin eski bir sürümü (belge geçmişi)"
	}
	if strings.HasPrefix(base, ".") && strings.Contains(base, ".tmp") {
		return ClassPrivate, "yarım kalmış geçici dosya (servis başlarken silinir)"
	}
	return ClassOther, "OpenScale'in tanımadığı dosya"
}

// BuildReport collects the report. Missing or unreadable directories are
// reported, not fatal.
func BuildReport(opts ReportOptions) Report {
	r := Report{GeneratedAt: opts.Now.UTC().Truncate(time.Minute), Hardening: opts.Hardening}
	st := mergedSettings(opts.Dirs)
	var docs []*trust.Document
	for _, d := range opts.Dirs {
		s, f := inspectStore(d)
		r.Stores = append(r.Stores, s)
		r.Findings = append(r.Findings, f...)
		for _, dir := range memberDirs(d.Path) {
			store, err := member.Open(dir)
			if err != nil {
				continue
			}
			doc := store.Document()
			docs = append(docs, doc)
			r.Recent = append(r.Recent, recentPeers(dir, doc, opts.Now)...)
		}
	}
	sort.Slice(r.Recent, func(i, j int) bool { return r.Recent[i].Seen.After(r.Recent[j].Seen) })
	r.CoordinatorSees, r.CoordinatorNever = coordinatorView(st)
	r.Findings = append(r.Findings, settingFindings(st)...)
	r.Findings = append(r.Findings, hostnameFindings(opts.OSHostname, docs)...)
	r.Findings = append(r.Findings, hostnameExposure()...)
	r.Findings = append(r.Findings, dumpFindings(opts.Hardening)...)
	return r
}

func memberDirs(dir string) []string {
	return []string{dir, filepath.Join(dir, "device"), filepath.Join(dir, "coordinator")}
}

func inspectStore(d DataDir) (Store, []Finding) {
	s := Store{DataDir: d}
	var findings []Finding
	info, err := os.Stat(d.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	s.Exists = err == nil && info.IsDir()
	if err != nil {
		s.Error = describeFSError(err)
		return s, nil
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		findings = append(findings, Finding{SeverityWarn, "dir_permissions",
			fmt.Sprintf("%s klasörünün izinleri %s: başka kullanıcılar içeriği görebilir; 0700 olmalı", d.Path, info.Mode().Perm())})
	}
	err = filepath.WalkDir(d.Path, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			if s.Error == "" {
				s.Error = describeFSError(err)
			}
			return nil
		}
		if e.IsDir() || len(s.Files) >= maxListFiles {
			return nil
		}
		fi, err := e.Info()
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(d.Path, p)
		class, desc := classify(rel)
		f := StoredFile{Path: rel, Description: desc, Class: class, Size: fi.Size()}
		if runtime.GOOS != "windows" {
			f.Mode = fi.Mode().Perm().String()
			if class == ClassSecret && fi.Mode().Perm()&0o077 != 0 {
				findings = append(findings, Finding{SeverityWarn, "file_permissions",
					fmt.Sprintf("%s izinleri %s: gizli dosya yalnızca sahibine açık (0600) olmalı", p, fi.Mode().Perm())})
			}
		}
		s.Files = append(s.Files, f)
		return nil
	})
	if err != nil && s.Error == "" {
		s.Error = describeFSError(err)
	}
	return s, findings
}

func describeFSError(err error) string {
	if errors.Is(err, fs.ErrPermission) {
		return "okunamadı: erişim reddedildi (yönetici/root olarak çalıştırın)"
	}
	return "okunamadı: " + err.Error()
}

// settingsView holds the fields of the service settings the report needs.
// Unknown fields are ignored so the report survives newer versions.
type settingsView struct {
	Found            bool
	ExitNode         string `json:"exit_node"`
	KillSwitch       *bool  `json:"kill_switch"`
	ExitAllowLAN     bool   `json:"exit_allow_lan"`
	IgnoreNetworkDNS bool   `json:"ignore_network_dns"`
	ForceRelay       bool   `json:"force_relay"`
	Shields          bool   `json:"shields"`
	Tunnel           *struct {
		HideLocalCandidates bool     `json:"hide_local_candidates"`
		StaticEndpoints     []string `json:"static_endpoints"`
		MagicDNSAllDevices  bool     `json:"magicdns_all_devices"`
		LogLevel            string   `json:"log_level"`
	} `json:"tunnel"`
}

func mergedSettings(dirs []DataDir) settingsView {
	for _, d := range dirs {
		data, err := securefile.ReadLimited(filepath.Join(d.Path, "settings.json"), maxReadSize)
		if err != nil {
			continue
		}
		var st settingsView
		if json.Unmarshal(data, &st) == nil {
			st.Found = true
			return st
		}
	}
	return settingsView{}
}

func (s settingsView) hideLocal() bool { return s.Tunnel != nil && s.Tunnel.HideLocalCandidates }
func (s settingsView) logLevel() string {
	if s.Tunnel == nil {
		return ""
	}
	return strings.ToLower(s.Tunnel.LogLevel)
}

func coordinatorView(st settingsView) (sees, never []string) {
	sees = []string{
		"bu cihazın genel IP adresi ve UDP portu (koordinatöre gelen paketlerin kaynağı); yalnızca bellekte tutulur",
		"cihaz kimliği ve WireGuard açık anahtarı; imzalı ağ belgesindeki bütün cihaz adları, overlay IP'leri ve kurallar",
		"bağlantı zamanları ve senkronizasyon sıklığı",
	}
	if st.hideLocal() {
		sees = append(sees, "yerel ağ adresleri GÖNDERİLMEZ (hide-local-candidates açık)")
	} else {
		sees = append(sees, "yerel ağ adresleri (doğrudan bağlantı adayları); kapatmak için: openscale set hide-local-candidates=true")
	}
	if st.ForceRelay {
		sees = append(sees, "bütün eş trafiği koordinatör üzerinden aktarılır: içerik şifreli, ama zaman ve hacim görünür")
	} else {
		sees = append(sees, "doğrudan bağlantı kurulamayan eşlerin trafiği aktarılırsa yalnızca şifreli paketlerin zamanı ve boyutu")
	}
	never = []string{
		"trafiğin içeriği (uçtan uca WireGuard ile şifreli)",
		"özel anahtarlar, parolalar, kayıt isteklerinin sırları",
		"DNS sorguları (MagicDNS bu bilgisayarda çözülür)",
		"cihazların sistem raporu (yalnızca yönetici rolündeki cihazlar sorabilir)",
		"telemetri, kullanım istatistiği, çökme raporu: hiçbiri yok (ADR-0008)",
	}
	return sees, never
}

func settingFindings(st settingsView) []Finding {
	var out []Finding
	if !st.Found {
		return []Finding{{SeverityInfo, "settings_unread", "servis ayarları okunamadı; ayar denetimi yapılmadı (servis klasörü yönetici izni ister)"}}
	}
	if st.logLevel() == "debug" {
		out = append(out, Finding{SeverityWarn, "debug_log", "hata ayıklama günlüğü açık: IP adresleri ve uç noktalar günlüğe maskesiz yazılır; işiniz bitince kapatın (openscale set log-level=info)"})
	}
	if st.ExitNode != "" {
		ks := st.KillSwitch == nil || *st.KillSwitch
		if !ks {
			out = append(out, Finding{SeverityWarn, "exit_without_killswitch", "çıkış düğümü kill switch olmadan kullanılıyor: tünel düşerse trafik, DNS ve IPv6 doğrudan yerel ağdan çıkabilir"})
		}
		if st.ExitAllowLAN {
			out = append(out, Finding{SeverityInfo, "exit_allow_lan", "çıkış düğümü açıkken yerel ağ erişimi açık: yerel ağdaki cihazlar bu bilgisayarla konuşabilir"})
		}
	} else {
		out = append(out, Finding{SeverityInfo, "dns_local", "çıkış düğümü kapalı: internet DNS sorguları ve trafiği yerel ağın/İSS'nin çözücüsüne ve yoluna gider"})
	}
	if st.IgnoreNetworkDNS {
		out = append(out, Finding{SeverityInfo, "network_dns_ignored", "ağın DNS ayarları bu bilgisayarda kapalı: sorgular işletim sisteminin çözücüsüne gider"})
	}
	if !st.hideLocal() {
		out = append(out, Finding{SeverityInfo, "local_candidates", "yerel ağ adresleri koordinatöre bildiriliyor"})
	}
	if st.Tunnel != nil && st.Tunnel.MagicDNSAllDevices {
		out = append(out, Finding{SeverityInfo, "magicdns_all", "MagicDNS bütün cihaz adlarını çözüyor (erişim kuralı olmayanlar dahil)"})
	}
	return out
}

func hostnameFindings(host string, docs []*trust.Document) []Finding {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return nil
	}
	if i := strings.IndexByte(h, '.'); i > 0 {
		h = h[:i]
	}
	var out []Finding
	seen := map[string]bool{}
	for _, doc := range docs {
		for _, d := range doc.Devices {
			n := strings.ToLower(d.Name)
			if n == h && !seen[n] {
				seen[n] = true
				out = append(out, Finding{SeverityInfo, "device_name_is_hostname",
					fmt.Sprintf("%q cihaz adı bilgisayarın adıyla aynı: ağ belgesini gören herkes (koordinatör dahil) bilgisayar adını görür; openscale device rename ile değiştirilebilir", d.Name)})
			}
		}
	}
	return out
}

func dumpFindings(h HardeningStatus) []Finding {
	var out []Finding
	if !h.CoreDumpsDisabled {
		out = append(out, Finding{SeverityWarn, "crash_dumps", "çökme dökümü bu süreçte kapatılamadı"})
	}
	for _, w := range h.Warnings {
		out = append(out, Finding{SeverityWarn, "crash_dump_env", w})
	}
	return append(out, crashDumpEnvironment()...)
}

// recentPeers reads the endpoint cache next to a member store. Names come
// from the verified document; unknown ids are shortened.
func recentPeers(dir string, doc *trust.Document, now time.Time) []RecentPeer {
	data, err := securefile.ReadLimited(filepath.Join(dir, "endpoints.json"), maxReadSize)
	if err != nil {
		return nil
	}
	var c struct {
		Coordinator *struct {
			Endpoint string    `json:"endpoint"`
			Seen     time.Time `json:"seen"`
		} `json:"coordinator"`
		Peers map[string]struct {
			Endpoint string    `json:"endpoint"`
			Seen     time.Time `json:"seen"`
		} `json:"peers"`
	}
	if json.Unmarshal(data, &c) != nil {
		return nil
	}
	names := map[string]string{}
	if doc != nil {
		for _, d := range doc.Devices {
			names[d.ID] = d.Name
		}
	}
	var out []RecentPeer
	if c.Coordinator != nil {
		out = append(out, RecentPeer{Name: "(koordinatör)", Endpoint: c.Coordinator.Endpoint, Seen: c.Coordinator.Seen})
	}
	for id, p := range c.Peers {
		name, ok := names[id]
		if !ok {
			name = shortID(id)
		}
		if p.Seen.After(now.Add(time.Minute)) {
			continue
		}
		out = append(out, RecentPeer{Name: name, Endpoint: p.Endpoint, Seen: p.Seen})
	}
	return out
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8] + "…"
	}
	return id
}

// WriteText prints the report for a terminal, in Turkish.
func (r Report) WriteText(w io.Writer) error {
	p := &errWriter{w: w}
	p.printf("OpenScale gizlilik raporu (%s)\n", r.GeneratedAt.Local().Format("02.01.2006 15:04"))
	p.printf("Bu rapor yalnızca bu bilgisayardaki dosyalardan üretildi; hiçbir yere bağlanılmadı.\n")

	p.printf("\n1. Bu bilgisayarda tutulan veriler\n")
	for _, s := range r.Stores {
		switch {
		case s.Error != "" && !s.Exists:
			p.printf("  %s (%s): %s\n", s.Path, s.Kind, s.Error)
			continue
		case !s.Exists:
			p.printf("  %s (%s): yok\n", s.Path, s.Kind)
			continue
		}
		p.printf("  %s (%s)\n", s.Path, s.Kind)
		if s.Error != "" {
			p.printf("    %s\n", s.Error)
		}
		files := slices.Clone(s.Files)
		sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
		for _, f := range files {
			mode := ""
			if f.Mode != "" {
				mode = " " + f.Mode
			}
			p.printf("    [%s] %s (%d bayt%s): %s\n", f.Class, f.Path, f.Size, mode, f.Description)
		}
	}

	p.printf("\n2. Koordinatörün görebildikleri\n")
	for _, s := range r.CoordinatorSees {
		p.printf("  + %s\n", s)
	}
	p.printf("  Koordinatörün göremedikleri:\n")
	for _, s := range r.CoordinatorNever {
		p.printf("  - %s\n", s)
	}

	p.printf("\n3. Son bağlantılar (yerel uç nokta önbelleği)\n")
	if len(r.Recent) == 0 {
		p.printf("  kayıt yok veya okunamadı\n")
	}
	for _, c := range r.Recent {
		p.printf("  %-24s %-28s %s\n", c.Name, c.Endpoint, c.Seen.Local().Format("02.01.2006 15:04"))
	}

	p.printf("\n4. Gizlilik denetimi\n")
	if len(r.Findings) == 0 {
		p.printf("  sorun bulunmadı\n")
	}
	for _, f := range r.Findings {
		p.printf("  [%s] %s\n", f.Severity, f.Text)
	}

	p.printf("\n5. Çökme dökümü\n")
	for _, m := range r.Hardening.Measures {
		p.printf("  %s\n", m)
	}
	p.printf("  OpenScale süreçleri başlarken aynı önlemleri kendileri için alır.\n")
	return p.err
}

// WriteJSON prints the report as indented JSON.
func (r Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) printf(format string, args ...any) {
	if e.err != nil {
		return
	}
	_, e.err = fmt.Fprintf(e.w, format, args...)
}
