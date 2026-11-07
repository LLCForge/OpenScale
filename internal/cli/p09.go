package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/namesuggest"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

// Rule language commands of P09 (ADR-0120): the text policy file
// (F-075, #228), policy tests (F-076, #101), the rule simulator (#102),
// rule scope warnings (#112), named addresses (F-073, #277) and the
// extra flags of "rule add" (#103, #104, #108, #110, #281).

func p09Commands() []command {
	return []command{
		{"policy export", "Kuralları, grupları, adresleri ve testleri yorumlu metin dosyası olarak yazar", cmdPolicyExport},
		{"policy import", "Metin politika dosyasını doğrular, testleri çalıştırır, farkı gösterir ve imzalar", cmdPolicyImport},
		{"policy edit", "Politikayı metin düzenleyicide açar; kaydedince doğrulayıp farkı gösterir ve imzalar", cmdPolicyEdit},
		{"rule edit", "'policy edit' ile aynı: kuralları metin düzenleyicide düzenler", cmdPolicyEdit},
		{"policy test", "Belgedeki (veya --file dosyasındaki) kural testlerini imzalamadan çalıştırır", cmdPolicyTest},
		{"policy check", "Kural simülatörü: bir cihaz diğerine bu portla bağlanabilir mi, hangi kural karar verir", cmdPolicyCheck},
		{"policy lint", "Kural kapsam uyarıları: geniş, gölgede, eşleşmeyen ve süresi dolmuş kurallar", cmdPolicyLint},
		{"host set", "Kurallarda host:<ad> olarak kullanılacak adlandırılmış adres aralığı tanımlar", cmdHostSet},
		{"host rm", "Kullanılmayan adlandırılmış adresi siler", cmdHostRemove},
	}
}

// maxEditorWait bounds how long "policy edit" waits for the editor.
const maxEditorWait = 24 * time.Hour

// --- rule add extensions ---

// ruleExtFlags are the "rule add" flags of ADR-0120.
type ruleExtFlags struct {
	bidirectional *bool
	icmpTypes     *string
	window        *string
	since         *string
	until         *string
	days          *string
	hours         *string
	tz            *string
}

func addRuleExtFlags(fs *flag.FlagSet) ruleExtFlags {
	return ruleExtFlags{
		bidirectional: fs.Bool("bidirectional", false, "kural iki yönde de izin versin (hedef de kaynağa aynı portla bağlanabilir)"),
		icmpTypes:     fs.String("icmp-types", "", "icmp kuralını türlerle sınırla: echo, v4:<n>, v6:<n> (virgülle)"),
		window:        fs.String("for", "", "tek seferlik erişim penceresi: kural şimdiden bu süre sonra kapanır (ör. 30m, 2h; en fazla 720h)"),
		since:         fs.String("since", "", "kural bu andan itibaren geçerli (RFC3339, ör. 2026-11-01T09:00:00+03:00)"),
		until:         fs.String("until", "", "kural bu anda kapanır (RFC3339)"),
		days:          fs.String("days", "", "zaman çizelgesi günleri: mon,tue,wed,thu,fri,sat,sun (boş: her gün)"),
		hours:         fs.String("hours", "", "zaman çizelgesi saatleri: HH:MM-HH:MM (ör. 09:00-18:00; 22:00-06:00 gece yarısını aşar)"),
		tz:            fs.String("tz", "", "çizelge saat dilimi farkı, ör. +03:00 (varsayılan: bu bilgisayarın şu anki farkı)"),
	}
}

const maxAccessWindow = 30 * 24 * time.Hour

// apply sets the extension fields on r and expands port names (#110). It
// prints the clock warning for time-limited rules.
func (f ruleExtFlags) apply(env *Env, r *trust.Rule, now time.Time) error {
	r.Bidirectional = *f.bidirectional
	r.ICMPTypes = splitList(strings.ToLower(*f.icmpTypes))
	if r.Service == "" && (r.Protocol == trust.ProtocolTCP || r.Protocol == trust.ProtocolUDP) {
		ports, err := trust.ExpandPortNames(r.Protocol, r.Ports)
		if err != nil {
			return usageError("%v", err)
		}
		r.Ports = ports
	}
	if *f.window != "" && *f.until != "" {
		return usageError("--for ve --until birlikte kullanılamaz")
	}
	if *f.window != "" {
		d, err := time.ParseDuration(*f.window)
		if err != nil || d < time.Minute || d > maxAccessWindow {
			return usageError("--for 1m ile 720h arasında bir süre olmalı (ör. 30m)")
		}
		r.NotAfter = now.Add(d).UTC().Truncate(time.Second)
	}
	for _, x := range []struct {
		flag string
		val  string
		dst  *time.Time
	}{{"since", *f.since, &r.NotBefore}, {"until", *f.until, &r.NotAfter}} {
		if x.val == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339, x.val)
		if err != nil {
			return usageError("--%s RFC3339 biçiminde olmalı (ör. 2026-11-01T09:00:00+03:00)", x.flag)
		}
		*x.dst = t.UTC().Truncate(time.Second)
	}
	if *f.hours != "" {
		start, end, ok := strings.Cut(*f.hours, "-")
		if !ok {
			return usageError("--hours HH:MM-HH:MM biçiminde olmalı")
		}
		tz := *f.tz
		if tz == "" {
			_, off := now.Zone()
			tz = trust.FormatUTCOffset(off)
		}
		if tz == "+00:00" {
			tz = ""
		}
		r.Schedule = &trust.RuleSchedule{Days: splitList(strings.ToLower(*f.days)), Start: strings.TrimSpace(start), End: strings.TrimSpace(end), UTCOffset: tz}
	} else if *f.days != "" || *f.tz != "" {
		return usageError("--days ve --tz yalnızca --hours ile kullanılır")
	}
	if r.HasTimeConditions() {
		fmt.Fprintln(env.Stderr, "uyarı: zamana bağlı kurallar her cihazın kendi saatine göre uygulanır; saati yanlış cihaz kuralı yanlış zamanda açar veya kapatır.")
	}
	return nil
}

// --- policy file ---

func cmdPolicyExport(env *Env, args []string) error {
	fs := newFlagSet(env, "policy export")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	out := fs.String("out", "", "yazılacak dosya (varsayılan: standart çıktı)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	doc, err := loadPolicyDoc(env, *dir)
	if err != nil {
		return err
	}
	text, err := trust.FormatPolicyText(doc)
	if err != nil {
		return err
	}
	if *out == "" {
		_, err := env.Stdout.Write(text)
		return err
	}
	if err := os.WriteFile(*out, text, 0o600); err != nil {
		return fmt.Errorf("dosya yazılamadı: %w", err)
	}
	fmt.Fprintf(env.Stdout, "Politika %s dosyasına yazıldı.\n", *out)
	return nil
}

func loadPolicyDoc(env *Env, dir string) (*trust.Document, error) {
	if dir == "" {
		return nil, usageError("--dir zorunlu")
	}
	n, err := admin.Load(dir, env.adminOptions())
	if err != nil {
		return nil, err
	}
	return n.Document()
}

func readPolicyFile(path string) (*trust.PolicyFile, error) {
	data, err := securefile.ReadLimited(path, trust.MaxPolicyTextSize)
	if err != nil {
		return nil, fmt.Errorf("politika dosyası okunamadı: %w", err)
	}
	return trust.ParsePolicyText(data)
}

func cmdPolicyImport(env *Env, args []string) error {
	fs := newFlagSet(env, "policy import")
	common := addEditFlags(fs)
	file := fs.String("file", "", "politika dosyası (zorunlu)")
	confirm := fs.String("confirm", "", "yeni geniş (herkesten herkese) kurallar için betiklerde açık onay: "+wideRuleWord)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *file == "" {
		return usageError("--file zorunlu")
	}
	p, err := readPolicyFile(*file)
	if err != nil {
		return err
	}
	return importPolicy(env, common, p, *confirm)
}

// importPolicy replaces the policy sections, shows the difference, the
// warnings and the test results, asks for confirmation of new broad rules
// and signs unless --dry-run.
func importPolicy(env *Env, common editFlags, p *trust.PolicyFile, confirm string) error {
	if *common.dir == "" {
		return usageError("--dir zorunlu")
	}
	validity, err := daysFlag(*common.validityDays, 1, int(trust.MaxValidity.Hours()/24), "validity")
	if err != nil {
		return err
	}
	n, err := admin.Load(*common.dir, env.adminOptions())
	if err != nil {
		return err
	}
	cur, err := n.Document()
	if err != nil {
		return err
	}
	plan, err := n.Prepare(env.Now(), validity, func(doc *trust.Document) error { return doc.ApplyPolicy(p) })
	if err != nil {
		return err
	}
	fmt.Fprintln(env.Stdout, "Değişiklikler:")
	for _, line := range plan.Diff.Lines() {
		fmt.Fprintf(env.Stdout, "  %s\n", line)
	}
	printPolicyReport(env, plan.Next)
	if *common.dryRun {
		fmt.Fprintln(env.Stdout, "Kuru çalıştırma: hiçbir şey imzalanmadı.")
		return nil
	}
	if broad := trust.NewBroadRules(cur, plan.Next); len(broad) > 0 {
		what := fmt.Sprintf("Dosya %d yeni geniş kural ekliyor (bütün cihazlardan bütün cihazlara)", len(broad))
		if err := confirmCritical(env, confirm, wideRuleWord, what); err != nil {
			return err
		}
	}
	passphrase, err := existingPassphrase(env, *common.passFile)
	if err != nil {
		return err
	}
	defer wipe(passphrase)
	if err := n.Commit(plan, passphrase); err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Ağ belgesi sürüm %d olarak imzalandı.\n", plan.Next.Version)
	return nil
}

func printPolicyReport(env *Env, doc *trust.Document) {
	if res := doc.RunPolicyTests(); len(res) > 0 {
		fmt.Fprintf(env.Stdout, "Kural testleri: %d test geçti.\n", len(res))
	}
	for _, w := range doc.PolicyWarnings(env.Now()) {
		fmt.Fprintf(env.Stdout, "  UYARI: %s\n", w.Message)
	}
}

func cmdPolicyEdit(env *Env, args []string) error {
	fs := newFlagSet(env, "policy edit")
	common := addEditFlags(fs)
	confirm := fs.String("confirm", "", "yeni geniş kurallar için açık onay: "+wideRuleWord)
	editor := fs.String("editor", "", "düzenleyici komutu (varsayılan: VISUAL, EDITOR veya notepad/vi)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	doc, err := loadPolicyDoc(env, *common.dir)
	if err != nil {
		return err
	}
	text, err := trust.FormatPolicyText(doc)
	if err != nil {
		return err
	}
	// The draft lives in the network folder (owner-only), not the shared
	// system temp folder (ADR-0008).
	tmp, err := os.CreateTemp(*common.dir, ".openscale-politika-*.jsonc")
	if err != nil {
		return err
	}
	path := tmp.Name()
	_, werr := tmp.Write(text)
	cerr := tmp.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(path)
		return errors.New("geçici politika dosyası yazılamadı")
	}
	if err := runEditor(*editor, path); err != nil {
		_ = os.Remove(path)
		return err
	}
	edited, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("düzenlenen dosya okunamadı: %w", err)
	}
	if string(edited) == string(text) {
		_ = os.Remove(path)
		fmt.Fprintln(env.Stdout, "Değişiklik yok; hiçbir şey imzalanmadı.")
		return nil
	}
	p, err := trust.ParsePolicyText(edited)
	if err == nil {
		err = importPolicy(env, common, p, *confirm)
	}
	if err != nil {
		fmt.Fprintf(env.Stderr, "Düzenlenen dosya saklandı: %s\nDüzeltip şununla uygulayın: openscale policy import --dir %s --file %s\n", path, *common.dir, path)
		return err
	}
	_ = os.Remove(path)
	return nil
}

// runEditor runs the owner's editor on path and waits for it.
func runEditor(cmdline, path string) error {
	if cmdline == "" {
		cmdline = os.Getenv("VISUAL")
	}
	if cmdline == "" {
		cmdline = os.Getenv("EDITOR")
	}
	if cmdline == "" {
		cmdline = "vi"
		if runtime.GOOS == "windows" {
			cmdline = "notepad"
		}
	}
	parts := strings.Fields(cmdline)
	if len(parts) == 0 {
		return errors.New("düzenleyici komutu boş")
	}
	cmd := exec.Command(parts[0], append(parts[1:], filepath.Clean(path))...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("düzenleyici başlatılamadı (%s): %w", parts[0], err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("düzenleyici hatayla çıktı: %w", err)
		}
		return nil
	case <-time.After(maxEditorWait):
		_ = cmd.Process.Kill()
		return errors.New("düzenleyici çok uzun süre açık kaldı")
	}
}

// --- tests, simulator, warnings ---

func cmdPolicyTest(env *Env, args []string) error {
	fs := newFlagSet(env, "policy test")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	file := fs.String("file", "", "testleri bu politika dosyası uygulanmış haliyle çalıştır (imzalamaz)")
	asJSON := fs.Bool("json", false, "sonuçları JSON olarak yaz")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	doc, err := loadPolicyDoc(env, *dir)
	if err != nil {
		return err
	}
	if *file != "" {
		p, err := readPolicyFile(*file)
		if err != nil {
			return err
		}
		if err := doc.ApplyPolicy(p); err != nil {
			return err
		}
	}
	res := doc.RunPolicyTests()
	if *asJSON {
		if err := json.NewEncoder(env.Stdout).Encode(res); err != nil {
			return err
		}
	} else {
		if len(res) == 0 {
			fmt.Fprintln(env.Stdout, "Belgede kural testi yok. Testler politika dosyasının \"tests\" bölümüne yazılır.")
		}
		for _, r := range res {
			mark := "GEÇTİ"
			if !r.Passed {
				mark = "KALDI"
			}
			fmt.Fprintf(env.Stdout, "%s  #%d %s (%s)\n", mark, r.Index+1, r.Test, decisionText(doc, r.Decision))
		}
	}
	for _, r := range res {
		if !r.Passed {
			return fmt.Errorf("%w: en az bir test başarısız", trust.ErrPolicyTestFailed)
		}
	}
	return nil
}

// decisionText explains a decision in Turkish.
func decisionText(doc *trust.Document, d trust.Decision) string {
	rule := func(i int) string {
		if i < 0 || i >= len(doc.Rules) {
			return ""
		}
		return fmt.Sprintf("kural %d: %s", i+1, trust.RuleSummary(doc.Rules[i]))
	}
	switch d.Reason {
	case trust.ReasonSelf:
		return "cihaz kendisiyle eşleşmez"
	case trust.ReasonDeny:
		return "reddedildi, " + rule(d.Rule)
	case trust.ReasonAllow:
		return "izin verildi, " + rule(d.Rule)
	}
	if d.Allowed {
		return "izin verildi"
	}
	return "reddedildi: hiçbir kural izin vermiyor (varsayılan reddet)"
}

func cmdPolicyCheck(env *Env, args []string) error {
	fs := newFlagSet(env, "policy check")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	from := fs.String("from", "", "kaynak cihaz (zorunlu)")
	to := fs.String("to", "", "hedef cihaz (zorunlu)")
	proto := fs.String("proto", "tcp", "tcp, udp, icmp veya IANA numarası")
	port := fs.String("port", "", "hedef port veya adı (ör. 22, rdp); tcp/udp için zorunlu")
	icmpType := fs.Int("icmp-type", 8, "icmp türü (8: echo)")
	at := fs.String("at", "now", "değerlendirme anı: now, RFC3339 bir an veya 'any' (zaman koşullarını yok say)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *from == "" || *to == "" {
		return usageError("--from ve --to zorunlu")
	}
	doc, err := loadPolicyDoc(env, *dir)
	if err != nil {
		return err
	}
	for _, name := range []string{*from, *to} {
		if _, ok := doc.DeviceByName(name); !ok {
			return namesuggest.Wrap(fmt.Errorf("cihaz bulunamadı: %s", name), namesuggest.KindDevice, name, knownDeviceNames(doc)) // #798
		}
	}
	q, err := checkQuery(*proto, *port, *icmpType)
	if err != nil {
		return err
	}
	switch *at {
	case "any":
	case "", "now":
		q.At = env.Now()
	default:
		t, err := time.Parse(time.RFC3339, *at)
		if err != nil {
			return usageError("--at now, any veya RFC3339 olmalı")
		}
		q.At = t
	}
	d := doc.Explain(*from, *to, q)
	verdict := "İZİN"
	if !d.Allowed {
		verdict = "RET"
	}
	fmt.Fprintf(env.Stdout, "%s: %s -> %s %s\n", verdict, *from, *to, decisionText(doc, d))
	if d.Reason == trust.ReasonDeny && len(d.Allows) > 0 {
		fmt.Fprintf(env.Stdout, "Not: kural %d izin verirdi; reddet kuralı her zaman önce gelir.\n", d.Allows[0]+1)
	}
	return nil
}

func checkQuery(proto, port string, icmpType int) (trust.PacketQuery, error) {
	q := trust.PacketQuery{ICMPType: -1}
	p := trust.Protocol(strings.ToLower(strings.TrimSpace(proto)))
	switch p {
	case trust.ProtocolTCP, trust.ProtocolUDP:
		ports, err := trust.ExpandPortNames(p, []string{port})
		if err != nil || port == "" {
			return q, usageError("--port gerekli: 1-65535 veya bilinen bir ad")
		}
		n, err := strconv.Atoi(ports[0])
		if err != nil || n < 1 || n > 65535 {
			return q, usageError("--port 1-65535 olmalı")
		}
		q.Port = uint16(n)
		q.Proto = 6
		if p == trust.ProtocolUDP {
			q.Proto = 17
		}
	case trust.ProtocolICMP, "ping":
		if icmpType < 0 || icmpType > 255 {
			return q, usageError("--icmp-type 0-255 olmalı")
		}
		q.Proto, q.ICMPType = 1, icmpType
	default:
		n, ok := trust.ProtocolNumber(p)
		if !ok {
			return q, usageError("--proto tcp, udp, icmp veya 0-255 olmalı")
		}
		q.Proto = int(n)
	}
	return q, nil
}

func cmdPolicyLint(env *Env, args []string) error {
	fs := newFlagSet(env, "policy lint")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	doc, err := loadPolicyDoc(env, *dir)
	if err != nil {
		return err
	}
	ws := doc.PolicyWarnings(env.Now())
	if len(ws) == 0 {
		fmt.Fprintln(env.Stdout, "Uyarı yok.")
		return nil
	}
	for _, w := range ws {
		fmt.Fprintf(env.Stdout, "UYARI [%s]: %s\n", w.Code, w.Message)
	}
	return nil
}

// --- named addresses ---

func cmdHostSet(env *Env, args []string) error {
	fs := newFlagSet(env, "host set")
	common := addEditFlags(fs)
	name := fs.String("name", "", "ad: küçük harf, rakam ve tire (zorunlu)")
	prefix := fs.String("prefix", "", "ağın kendi aralığında CIDR, ör. 100.80.1.0/24 (zorunlu)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *name == "" || *prefix == "" {
		return usageError("--name ve --prefix zorunlu")
	}
	p, err := netip.ParsePrefix(strings.TrimSpace(*prefix))
	if err != nil {
		return usageError("--prefix CIDR olmalı (ör. 100.80.1.0/24)")
	}
	return runEdit(env, common, func(doc *trust.Document) error { return doc.SetHost(*name, p) })
}

func cmdHostRemove(env *Env, args []string) error {
	fs := newFlagSet(env, "host rm")
	common := addEditFlags(fs)
	name := fs.String("name", "", "silinecek adres adı (zorunlu)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *name == "" {
		return usageError("--name zorunlu")
	}
	return runEdit(env, common, func(doc *trust.Document) error { return doc.RemoveHost(*name) })
}
