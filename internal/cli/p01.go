package cli

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

// Commands of package P01 (ADR-0151): signature ledger (#342), change
// draft (#344), limits (#345), revocation compaction (#346), key age
// policy (#347), visual fingerprints (#351), emergency lock (#361) and
// bulk membership (#362).

func p01Commands() []command {
	return []command{
		{"network ledger", "İmza defterini doğrular; --check dosya ile bir belgenin bu klasörde imzalanıp imzalanmadığını söyler", cmdNetworkLedger},
		{"network draft show", "Değişiklik taslağını ve tek imzada uygulanacak farkı gösterir", cmdDraftShow},
		{"network draft sign", "Değişiklik taslağını tek fark, tek parola ve tek sürümle imzalar", cmdDraftSign},
		{"network draft discard", "Değişiklik taslağını siler", cmdDraftDiscard},
		{"network limits", "Belge sınırlarının ne kadarının kullanıldığını gösterir (%80'de uyarır)", cmdNetworkLimits},
		{"network revoked-compact", "Eski iptal kayıtlarını anahtar özetlerine sıkıştırır: --keep N --yes", cmdRevokedCompact},
		{"network key-age", "Cihaz anahtarı yaşı politikası: --days N (0 kaldırır) [--yes]", cmdNetworkKeyAge},
		{"network fingerprint-art", "Kök, koordinatör ve cihaz parmak izlerini görsel desenle yan yana gösterir", cmdFingerprintArt},
		{"network lockdown", "Ağ geneli acil kilit: --state on|off [--reason metin] [--yes]; kilitliyken yalnızca yönetici cihaz erişir", cmdNetworkLockdown},
		{"device key-age", "Cihaz anahtarlarının yaşını ve politikayı aşanları listeler", cmdDeviceKeyAge},
		{"device bulk", "Birden çok cihazın üyeliğini tek imzayla uzatır/bitirir/etiketler: --names a,b [--extend-days N|--expire] [--add-tags x] [--remove-tags y]", cmdDeviceBulk},
	}
}

const newFieldWarning = `UYARI: Bu değişiklik belgeye yeni bir alan ekler (ADR-0151). Bu özelliği
bilmeyen eski OpenScale sürümlerindeki cihazlar ve koordinatör bu sürümden
itibaren ağ belgesini REDDEDER ve son kabul ettikleri belgede kalır.
Önce bütün cihazları ve koordinatörü güncelleyin; "openscale network
min-version" ile eski istemcilerin bağlanmasını da kesebilirsiniz.`

const lockdownWarning = `ACİL KİLİT: Bütün erişim kuralları askıya alınır; yalnızca "admin" rolündeki
cihazlar diğer cihazlara bağlanabilir, çıkış düğümü kullanılamaz. Belge
yayılımı sürer; kilit kaldırılınca kurallar aynen geri döner.
DİKKAT: ADR-0151 öncesi sürümdeki cihazlar ve koordinatör kilitli belgeyi
reddeder ve ÖNCEKİ KURALLARLA çalışmayı sürdürür; kilit onlara ulaşmaz.
Eski bir koordinatör belgeyi hiç dağıtmaz. Şüpheli bir cihazı kesin olarak
ayırmak için ayrıca "openscale device revoke" kullanın.`

// --- ledger (#342) ---

func cmdNetworkLedger(env *Env, args []string) error {
	fs := newFlagSet(env, "network ledger")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	check := fs.String("check", "", "denetlenecek imzalı belge dosyası (ör. bir cihazın veya koordinatörün network.json'u)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *dir == "" {
		return usageError("--dir zorunlu")
	}
	n, err := admin.Load(*dir, env.adminOptions())
	if err != nil {
		return err
	}
	w := env.Stdout
	if *check != "" {
		data, err := securefile.ReadLimited(*check, trust.MaxEnvelopeSize)
		if err != nil {
			return fmt.Errorf("dosya okunamadı: %w", err)
		}
		e, err := trust.UnmarshalEnvelope(data)
		if err != nil {
			return err
		}
		c, err := n.CheckSigned(e)
		if err != nil {
			return fmt.Errorf("belge bu ağın güncel kök anahtarıyla doğrulanamadı: %w", err)
		}
		fmt.Fprintf(w, "Sürüm %d (kök dönemi %d), özet %s\n", c.Version, c.RootEpoch, c.Digest)
		switch c.Verdict {
		case admin.LedgerKnown:
			fmt.Fprintln(w, "Bu sürüm bu klasörde imzalandı.")
		case admin.LedgerUntracked:
			fmt.Fprintln(w, "Bu sürüm imza defterinden eski; denetlenemez.")
		case admin.LedgerEmpty:
			fmt.Fprintln(w, "İmza defteri henüz boş; denetlenemez.")
		case admin.LedgerForeign:
			fmt.Fprintln(w, "KRİTİK: geçerli kök imzalı ama bu klasörde imzalanmamış bir sürüm. Kök anahtar başka bir yerde kullanılmış olabilir:")
			fmt.Fprintln(w, "  kökü kurtarma anahtarıyla değiştirin ('openscale network root-recover').")
			return errors.New("yabancı imza bulundu")
		}
		return nil
	}
	st, err := n.LedgerStatus()
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "İmza defteri: %d kayıt", st.Entries)
	if st.Entries > 0 {
		fmt.Fprintf(w, " (sürüm %d - %d, son imza %s)", st.First, st.Last, formatTime(*st.LastSigned))
	}
	fmt.Fprintln(w)
	for _, p := range st.Problems {
		fmt.Fprintln(w, "  "+p)
	}
	if len(st.Problems) > 0 {
		return errors.New("imza defteri sorun bildirdi")
	}
	return nil
}

// --- draft (#344) ---

func stageDraft(env *Env, n *admin.Network, change admin.Change) error {
	lines, err := n.StageDraft(env.Now(), change)
	if err != nil {
		return err
	}
	fmt.Fprintln(env.Stdout, "Taslağa eklendi (imzalanmadı):")
	for _, l := range lines {
		fmt.Fprintf(env.Stdout, "  %s\n", l)
	}
	fmt.Fprintln(env.Stdout, "İmzalamak için: openscale network draft sign --dir ...")
	return nil
}

func loadDir(env *Env, name string, args []string) (*admin.Network, editFlags, error) {
	fs := newFlagSet(env, name)
	f := addEditFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return nil, f, err
	}
	if *f.dir == "" {
		return nil, f, usageError("--dir zorunlu")
	}
	n, err := admin.Load(*f.dir, env.adminOptions())
	return n, f, err
}

func cmdDraftShow(env *Env, args []string) error {
	n, _, err := loadDir(env, "network draft show", args)
	if err != nil {
		return err
	}
	d, err := n.Draft()
	if errors.Is(err, admin.ErrNoDraft) {
		fmt.Fprintln(env.Stdout, "Bekleyen değişiklik taslağı yok.")
		return nil
	}
	if err != nil {
		return err
	}
	w := env.Stdout
	fmt.Fprintf(w, "Taslak: sürüm %d üzerine, %d düzenleme (başlangıç %s)\n", d.Base, len(d.Entries), formatTime(d.Created))
	for _, l := range d.Lines {
		fmt.Fprintf(w, "  %s\n", l)
	}
	if d.Problem != "" {
		fmt.Fprintf(w, "İmzalanamaz: %s\n", d.Problem)
	}
	return nil
}

func cmdDraftSign(env *Env, args []string) error {
	n, f, err := loadDir(env, "network draft sign", args)
	if err != nil {
		return err
	}
	validity, err := daysFlag(*f.validityDays, 1, int(trust.MaxValidity.Hours()/24), "validity")
	if err != nil {
		return err
	}
	plan, err := n.PrepareDraft(env.Now(), validity)
	if err != nil {
		return err
	}
	fmt.Fprintln(env.Stdout, "Değişiklikler:")
	for _, line := range plan.Diff.Lines() {
		fmt.Fprintf(env.Stdout, "  %s\n", line)
	}
	if *f.dryRun {
		fmt.Fprintln(env.Stdout, "Kuru çalıştırma: hiçbir şey imzalanmadı.")
		return nil
	}
	passphrase, err := existingPassphrase(env, *f.passFile)
	if err != nil {
		return err
	}
	defer wipe(passphrase)
	if err := n.CommitDraft(plan, passphrase); err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Taslak ağ belgesi sürüm %d olarak tek imzayla imzalandı.\n", plan.Next.Version)
	return nil
}

func cmdDraftDiscard(env *Env, args []string) error {
	n, _, err := loadDir(env, "network draft discard", args)
	if err != nil {
		return err
	}
	if err := n.DiscardDraft(); err != nil {
		return err
	}
	fmt.Fprintln(env.Stdout, "Değişiklik taslağı silindi.")
	return nil
}

// --- limits (#345) and the network show additions ---

func cmdNetworkLimits(env *Env, args []string) error {
	n, _, err := loadDir(env, "network limits", args)
	if err != nil {
		return err
	}
	doc, err := n.Document()
	if err != nil {
		return err
	}
	for _, u := range doc.LimitUsages() {
		mark := ""
		if u.Percent() >= trust.LimitWarnPercent {
			mark = "  UYARI"
		}
		fmt.Fprintf(env.Stdout, "  %-24s %8d / %-8d %%%d%s\n", u.Name, u.Used, u.Max, u.Percent(), mark)
	}
	return nil
}

// showP01 adds the P01 warnings to "network show".
func showP01(env *Env, n *admin.Network, doc *trust.Document) {
	w := env.Stdout
	for _, u := range doc.NearLimits() {
		fmt.Fprintln(w, "  UYARI: "+trust.LimitWarning(u))
	}
	if l := doc.Lockdown; l != nil {
		fmt.Fprintf(w, "  ACİL KİLİT AÇIK (%s'den beri): bütün kurallar askıda. %s\n", formatTime(l.Since), l.Reason)
	}
	if doc.MaxKeyAgeDays > 0 {
		for _, s := range doc.KeyAges(env.Now()) {
			if s.Overdue {
				fmt.Fprintf(w, "  UYARI: %s cihazının anahtarı %d günlük (politika %d gün); cihazda 'openscale device rotate-key' çalıştırın.\n", s.Name, s.AgeDays, doc.MaxKeyAgeDays)
			}
		}
	}
	if st, err := n.LedgerStatus(); err == nil {
		for _, p := range st.Problems {
			fmt.Fprintln(w, "  "+p)
		}
	}
	if d, err := n.Draft(); err == nil {
		fmt.Fprintf(w, "  Bekleyen değişiklik taslağı: %d düzenleme ('openscale network draft show').\n", len(d.Entries))
	}
}

// --- revocation compaction (#346) ---

func cmdRevokedCompact(env *Env, args []string) error {
	fs := newFlagSet(env, "network revoked-compact")
	f := addEditFlags(fs)
	keep := fs.Int("keep", trust.MaxRevoked/2, "tam kayıt olarak tutulacak en yeni iptal sayısı")
	yes := fs.Bool("yes", false, "eski cihazların yeni belgeyi reddedeceğini ve sıkıştırmanın geri alınamayacağını kabul eder")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *keep < 0 || *keep > trust.MaxRevoked {
		return usageError("--keep 0 ile %d arasında olmalı", trust.MaxRevoked)
	}
	fmt.Fprintln(env.Stderr, newFieldWarning)
	fmt.Fprintln(env.Stderr, "Sıkıştırılan iptallerin cihaz adı ve zamanı unutulur; anahtarları yine asla yeniden eklenemez. Geri alınamaz.")
	if !*yes && !*f.dryRun && !*f.draft {
		return usageError("sıkıştırmak için --yes verin (veya önce --dry-run ile bakın)")
	}
	return runEdit(env, f, admin.CompactRevocations(*keep))
}

// --- key age (#347) ---

func cmdNetworkKeyAge(env *Env, args []string) error {
	fs := newFlagSet(env, "network key-age")
	f := addEditFlags(fs)
	days := fs.Int("days", -1, "cihaz anahtarının en çok yaşı (gün); 0 politikayı kaldırır")
	yes := fs.Bool("yes", false, "eski cihazların yeni belgeyi reddedeceğini kabul eder")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *days < 0 || *days > trust.MaxKeyAgeDays {
		return usageError("--days 0 ile %d arasında olmalı", trust.MaxKeyAgeDays)
	}
	if *days > 0 {
		fmt.Fprintln(env.Stderr, newFieldWarning)
		if !*yes && !*f.dryRun && !*f.draft {
			return usageError("politikayı koymak için --yes verin (veya önce --dry-run ile bakın)")
		}
	}
	return runEdit(env, f, admin.SetMaxKeyAge(*days))
}

func cmdDeviceKeyAge(env *Env, args []string) error {
	n, _, err := loadDir(env, "device key-age", args)
	if err != nil {
		return err
	}
	doc, err := n.Document()
	if err != nil {
		return err
	}
	w := env.Stdout
	if doc.MaxKeyAgeDays > 0 {
		fmt.Fprintf(w, "Politika: en çok %d gün\n", doc.MaxKeyAgeDays)
	} else {
		fmt.Fprintln(w, "Politika yok ('openscale network key-age --days N').")
	}
	for _, s := range doc.KeyAges(env.Now()) {
		mark := ""
		if s.Overdue {
			mark = "  SÜRESİ GEÇTİ: cihazda 'openscale device rotate-key'"
		}
		fmt.Fprintf(w, "  %-24s %5d gün (anahtar %s)%s\n", s.Name, s.AgeDays, formatTime(s.IssuedAt), mark)
	}
	return nil
}

// --- visual fingerprints (#351) ---

func cmdFingerprintArt(env *Env, args []string) error {
	n, _, err := loadDir(env, "network fingerprint-art", args)
	if err != nil {
		return err
	}
	doc, err := n.Document()
	if err != nil {
		return err
	}
	w := env.Stdout
	entries := fingerprintEntries(n.RootFingerprint(), doc)
	for _, e := range entries {
		fmt.Fprintf(w, "%s: %s\n", e.Label, e.Fingerprint)
	}
	var arts [][]string
	for i, e := range entries {
		arts = append(arts, trust.RandomArt(e.Title, e.Fingerprint))
		if len(arts) == 3 || i == len(entries)-1 {
			fmt.Fprintln(w)
			for _, line := range trust.SideBySide(arts...) {
				fmt.Fprintln(w, strings.TrimRight(line, " "))
			}
			arts = nil
		}
	}
	return nil
}

type fingerprintEntry struct {
	Label, Title, Fingerprint string
}

func fingerprintEntries(root string, doc *trust.Document) []fingerprintEntry {
	out := []fingerprintEntry{{Label: "Kök", Title: "KÖK", Fingerprint: root}}
	if c := doc.Coordinator; c != nil {
		out = append(out, fingerprintEntry{Label: "Koordinatör", Title: "KOORDİNATÖR", Fingerprint: trust.CoordinatorFingerprint(c.WireGuardKey)})
	}
	for _, d := range doc.Devices {
		out = append(out, fingerprintEntry{Label: "Cihaz " + d.Name, Title: d.Name, Fingerprint: trust.DeviceFingerprint(d)})
	}
	return out
}

// --- emergency lock (#361) ---

func cmdNetworkLockdown(env *Env, args []string) error {
	fs := newFlagSet(env, "network lockdown")
	f := addEditFlags(fs)
	state := fs.String("state", "", "on (acil kilit) veya off (kaldır)")
	reason := fs.String("reason", "", "kısa açıklama (belgeye yazılır, herkes görür)")
	yes := fs.Bool("yes", false, "kilidin etkisini ve eski cihaz sınırını okuduğunu onaylar (açarken zorunlu)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *state != "on" && *state != "off" {
		return usageError("--state on|off zorunlu")
	}
	on := *state == "on"
	if on {
		fmt.Fprintln(env.Stderr, lockdownWarning)
		if !*yes && !*f.dryRun && !*f.draft {
			return usageError("kilidi açmak için --yes verin (veya önce --dry-run ile bakın)")
		}
	}
	return runEdit(env, f, admin.SetLockdown(on, *reason, env.Now()))
}

// --- bulk membership (#362) ---

func cmdDeviceBulk(env *Env, args []string) error {
	fs := newFlagSet(env, "device bulk")
	f := addEditFlags(fs)
	names := fs.String("names", "", "virgülle ayrılmış cihaz adları (zorunlu)")
	extend := fs.Int("extend-days", 0, "üyelikleri bugünden itibaren bu kadar gün uzatır")
	expire := fs.Bool("expire", false, "üyelikleri şimdi bitirir (anahtarlar iptal edilmez)")
	add := fs.String("add-tags", "", "eklenecek etiketler (virgülle)")
	remove := fs.String("remove-tags", "", "kaldırılacak etiketler (virgülle)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	list := splitList(*names)
	if len(list) == 0 {
		return usageError("--names zorunlu")
	}
	maxDays := int(trust.MaxDeviceLife.Hours() / 24)
	if *extend < 0 || *extend > maxDays {
		return usageError("--extend-days 0 ile %d arasında olmalı", maxDays)
	}
	op := admin.BulkOp{Extend: time.Duration(*extend) * 24 * time.Hour, Expire: *expire, AddTags: splitList(*add), RemoveTags: splitList(*remove)}
	change, err := admin.BulkMembership(list, op, env.Now())
	if err != nil {
		return usageError("%s", err.Error())
	}
	return runEdit(env, f, change)
}
