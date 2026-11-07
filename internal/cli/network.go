package cli

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

const maxPassphraseFile = 1024

func (env *Env) adminOptions() admin.Options {
	return admin.Options{Argon2: env.Argon2, Random: env.Random}
}

func cmdNetworkInit(env *Env, args []string) error {
	fs := newFlagSet(env, "network init")
	dir := fs.String("dir", "", "ağ dosyalarının tutulacağı klasör (zorunlu)")
	domain := fs.String("domain", trust.DefaultDNSDomain, "cihaz isimleri için DNS alanı")
	ipv4 := fs.String("ipv4", trust.DefaultIPv4Prefix.String(), "özel ağ IPv4 aralığı")
	validityDays := fs.Int("validity", int(trust.DefaultValidity.Hours()/24), "belge geçerlilik süresi (gün)")
	passFile := fs.String("passphrase-file", "", "parolayı terminal yerine bu dosyadan oku")
	// The backup step (#195, p14.go): setup is complete only with a backup.
	backupOut := fs.String("backup-out", "", "kurulumun parçası olarak kök anahtar yedeğinin yazılacağı dosya (ör. USB bellekte)")
	backupPassFile := fs.String("backup-passphrase-file", "", "yedeğin parolasını bu dosyadan oku")
	skipBackup := fs.Bool("skip-backup", false, "yedek adımını atla (kurulum tamamlanmamış sayılır)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *dir == "" {
		return usageError("--dir zorunlu")
	}
	validity, err := daysFlag(*validityDays, 1, int(trust.MaxValidity.Hours()/24), "validity")
	if err != nil {
		return err
	}
	prefix4, err := netip.ParsePrefix(*ipv4)
	if err != nil {
		return usageError("--ipv4 geçerli bir IPv4 aralığı değil")
	}
	passphrase, err := newPassphrase(env, *passFile, "Kök anahtar")
	if err != nil {
		return err
	}
	defer wipe(passphrase)

	n, err := admin.Init(*dir, admin.InitOptions{DNSDomain: *domain, IPv4Prefix: prefix4, Validity: validity}, passphrase, env.adminOptions(), env.Now())
	if err != nil {
		return err
	}
	doc, err := n.Document()
	if err != nil {
		return err
	}
	w := env.Stdout
	fmt.Fprintln(w, "Ağ oluşturuldu.")
	fmt.Fprintf(w, "  Ağ kimliği:              %s\n", doc.NetworkID)
	fmt.Fprintf(w, "  Kök anahtar parmak izi:  %s\n", n.RootFingerprint())
	fmt.Fprintf(w, "  IPv4 / IPv6:             %s / %s\n", doc.IPv4Prefix, doc.IPv6Prefix)
	fmt.Fprintf(w, "  Geçerlilik sonu:         %s\n", formatTime(doc.ExpiresAt))
	return finishInitBackup(env, n, passphrase, *dir, *backupOut, *backupPassFile, *skipBackup)
}

func cmdNetworkShow(env *Env, args []string) error {
	fs := newFlagSet(env, "network show")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
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
	doc, err := n.Document()
	if err != nil {
		return err
	}
	w := env.Stdout
	fmt.Fprintf(w, "Ağ %s (sürüm %d)\n", doc.NetworkID, doc.Version)
	if doc.DisplayName != "" {
		fmt.Fprintf(w, "  Ağ adı:                  %s\n", doc.DisplayName)
	}
	fmt.Fprintf(w, "  Kök anahtar parmak izi:  %s\n", n.RootFingerprint())
	fmt.Fprintf(w, "  DNS alanı:               %s\n", doc.DNSDomain)
	fmt.Fprintf(w, "  IPv4 / IPv6:             %s / %s\n", doc.IPv4Prefix, doc.IPv6Prefix)
	fmt.Fprintf(w, "  Geçerlilik:              %s - %s\n", formatTime(doc.IssuedAt), formatTime(doc.ExpiresAt))
	switch remaining := doc.ExpiresAt.Sub(env.Now()); {
	case remaining <= 0:
		fmt.Fprintln(w, "  UYARI: belgenin süresi dolmuş, cihazlar yeni bağlantı kurmaz. 'openscale network renew' çalıştır.")
	case remaining < 14*24*time.Hour:
		fmt.Fprintf(w, "  UYARI: belgenin süresi %d gün içinde doluyor.\n", int(remaining.Hours()/24)+1)
	}
	if doc.Coordinator != nil {
		fmt.Fprintf(w, "  Koordinatör:             %s\n", doc.Coordinator.Endpoint)
	}
	backups, err := n.Backups()
	if err != nil {
		return err
	}
	if len(backups) == 0 {
		fmt.Fprintln(w, "  UYARI: kök anahtarın hiç yedeği yok. 'openscale network backup' çalıştır.")
	} else {
		fmt.Fprintf(w, "  Yedek sayısı:            %d (son: %s)\n", len(backups), formatTime(backups[len(backups)-1].CreatedAt))
	}
	showP01(env, n, doc) // limits, lock, key age, ledger, draft (p01.go)

	fmt.Fprintf(w, "\nCihazlar (%d):\n", len(doc.Devices))
	for _, d := range doc.Devices {
		roles := ""
		if d.HasRole(trust.RoleExitNode) {
			roles = "  [çıkış düğümü]"
		}
		if len(d.Tags) > 0 {
			roles += "  etiketler: " + strings.Join(d.Tags, ",")
		}
		fmt.Fprintf(w, "  %-20s %-15s %s  bitiş %s%s\n", d.Name+"."+doc.DNSDomain, d.IPv4, d.IPv6, formatTime(d.ExpiresAt), roles)
	}
	if len(doc.Groups) > 0 {
		fmt.Fprintf(w, "\nGruplar (%d):\n", len(doc.Groups))
		for _, g := range doc.Groups {
			fmt.Fprintf(w, "  group:%s  %s\n", g.Name, strings.Join(g.Members, ", "))
		}
	}
	fmt.Fprintf(w, "\nKurallar (%d):\n", len(doc.Rules))
	for i, r := range doc.Rules {
		fmt.Fprintf(w, "  %d. %s", i+1, admin.RuleString(r))
		if r.Description != "" {
			fmt.Fprintf(w, "  (%s)", r.Description)
		}
		fmt.Fprintln(w)
	}
	if len(doc.Rules) == 0 {
		fmt.Fprintln(w, "  Kural yok: cihazlar arası tüm trafik reddedilir.")
	}
	printTagWarnings(env, doc)
	fmt.Fprintf(w, "\nÇıkış düğümü kullanıcıları: %s\n", exitUsersText(doc))
	fmt.Fprintln(w)
	printDNS(env, doc)
	fmt.Fprintf(w, "\nİptal edilmiş cihaz sayısı: %d\n", len(doc.Revoked))
	return nil
}

func cmdNetworkRenew(env *Env, args []string) error {
	fs := newFlagSet(env, "network renew")
	common := addEditFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	return runEdit(env, common, func(*trust.Document) error { return nil })
}

func cmdNetworkBackup(env *Env, args []string) error {
	fs := newFlagSet(env, "network backup")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	out := fs.String("out", "", "yedeğin yazılacağı dosya, ör. bir USB bellekte (zorunlu)")
	label := fs.String("label", "", "yedek için kısa not, ör. usb-1")
	passFile := fs.String("passphrase-file", "", "mevcut parolayı bu dosyadan oku")
	backupPassFile := fs.String("backup-passphrase-file", "", "yedeğin parolasını bu dosyadan oku")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *dir == "" || *out == "" {
		return usageError("--dir ve --out zorunlu")
	}
	n, err := admin.Load(*dir, env.adminOptions())
	if err != nil {
		return err
	}
	current, err := existingPassphrase(env, *passFile)
	if err != nil {
		return err
	}
	defer wipe(current)
	backupPass, err := newPassphrase(env, *backupPassFile, "Yedek")
	if err != nil {
		return err
	}
	defer wipe(backupPass)
	data, err := n.CreateBackup(current, backupPass, *label, env.Now())
	if err != nil {
		return err
	}
	if err := securefile.WriteNew(*out, data); err != nil {
		return fmt.Errorf("yedek yazılamadı: %w", err)
	}
	// Read back and open (#195, p14.go).
	if err := verifyWrittenBackup(n, *out, data, backupPass); err != nil {
		return fmt.Errorf("yedek yazıldı ama doğrulanamadı (%s): %w", *out, err)
	}
	fmt.Fprintf(env.Stdout, "Yedek yazıldı ve geri açılarak doğrulandı: %s\n", *out)
	fmt.Fprintln(env.Stdout, "Yedeği ve parolasını ayrı yerlerde sakla. Geri yüklemek için: openscale network restore")
	return nil
}

func cmdNetworkRestore(env *Env, args []string) error {
	fs := newFlagSet(env, "network restore")
	dir := fs.String("dir", "", "ağ klasörü; network.json burada olmalı (zorunlu)")
	from := fs.String("from", "", "yedek dosyası (zorunlu)")
	passFile := fs.String("passphrase-file", "", "yedeğin parolasını bu dosyadan oku")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *dir == "" || *from == "" {
		return usageError("--dir ve --from zorunlu")
	}
	data, err := securefile.ReadPrivate(*from, trust.MaxSealedKeySize)
	if err != nil {
		return fmt.Errorf("yedek okunamadı: %w", err)
	}
	pass, err := existingPassphrase(env, *passFile)
	if err != nil {
		return err
	}
	defer wipe(pass)
	if err := admin.Restore(*dir, data, pass, env.adminOptions()); err != nil {
		return err
	}
	fmt.Fprintln(env.Stdout, "Kök anahtar yedekten geri yüklendi. Artık yedeğin parolası kullanılır; istersen 'openscale network passphrase' ile değiştir.")
	return nil
}

func cmdNetworkPassphrase(env *Env, args []string) error {
	fs := newFlagSet(env, "network passphrase")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	passFile := fs.String("passphrase-file", "", "mevcut parolayı bu dosyadan oku")
	newPassFile := fs.String("new-passphrase-file", "", "yeni parolayı bu dosyadan oku")
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
	current, err := existingPassphrase(env, *passFile)
	if err != nil {
		return err
	}
	defer wipe(current)
	next, err := newPassphrase(env, *newPassFile, "Yeni kök anahtar")
	if err != nil {
		return err
	}
	defer wipe(next)
	if err := n.ChangePassphrase(current, next); err != nil {
		return err
	}
	fmt.Fprintln(env.Stdout, "Kök anahtar parolası değiştirildi. Mevcut yedekler kendi parolalarıyla geçerli kalır.")
	return nil
}

func cmdNetworkVerify(env *Env, args []string) error {
	fs := newFlagSet(env, "network verify")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
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
	report, err := n.VerifyHistory()
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "%d sürüm incelendi.\n", len(report.Entries))
	if report.OK() {
		fmt.Fprintln(env.Stdout, "Geçmiş doğrulandı: tüm sürümler kök anahtarla imzalı, sıralı ve eksiksiz.")
		return nil
	}
	for _, p := range report.Problems {
		fmt.Fprintf(env.Stdout, "  SORUN: %s\n", p)
	}
	return errors.New("geçmiş doğrulanamadı")
}

// editFlags are shared by every command that signs a new document version.
type editFlags struct {
	dir          *string
	validityDays *int
	passFile     *string
	dryRun       *bool
	// draft collects the change in the change draft instead of signing
	// (#344, p01.go).
	draft *bool
}

func addEditFlags(fs *flag.FlagSet) editFlags {
	return editFlags{
		dir:          fs.String("dir", "", "ağ klasörü (zorunlu)"),
		validityDays: fs.Int("validity", int(trust.DefaultValidity.Hours()/24), "yeni belgenin geçerlilik süresi (gün)"),
		passFile:     fs.String("passphrase-file", "", "parolayı bu dosyadan oku"),
		dryRun:       fs.Bool("dry-run", false, "değişikliği göster ama imzalama"),
		draft:        fs.Bool("draft", false, "imzalamadan değişiklik taslağına ekle ('openscale network draft sign' ile tek imzada imzalanır)"),
	}
}

// runEdit prepares the change, prints the diff, and signs it unless
// --dry-run was given.
func runEdit(env *Env, f editFlags, change admin.Change) error {
	if *f.dir == "" {
		return usageError("--dir zorunlu")
	}
	validity, err := daysFlag(*f.validityDays, 1, int(trust.MaxValidity.Hours()/24), "validity")
	if err != nil {
		return err
	}
	n, err := admin.Load(*f.dir, env.adminOptions())
	if err != nil {
		return err
	}
	if f.draft != nil && *f.draft { // #344, p01.go
		return stageDraft(env, n, change)
	}
	plan, err := n.Prepare(env.Now(), validity, change)
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
	if err := n.Commit(plan, passphrase); err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Ağ belgesi sürüm %d olarak imzalandı.\n", plan.Next.Version)
	return nil
}

func newPassphrase(env *Env, passFile, what string) ([]byte, error) {
	if passFile != "" {
		p, err := readPassphraseFile(passFile)
		if err != nil {
			return nil, err
		}
		if err := trust.CheckPassphrase(p); err != nil {
			wipe(p)
			return nil, err
		}
		return p, nil
	}
	if !env.IsTerminal() {
		return nil, usageError("terminal yok; parola dosyası seçeneğini kullan")
	}
	fmt.Fprintf(env.Stderr, "%s için en az %d karakterlik bir parola seç.\n", what, trust.MinPassphraseLength)
	first, err := env.ReadSecret("Parola: ")
	if err != nil {
		return nil, err
	}
	if err := trust.CheckPassphrase(first); err != nil {
		wipe(first)
		return nil, err
	}
	second, err := env.ReadSecret("Parola (tekrar): ")
	if err != nil {
		wipe(first)
		return nil, err
	}
	defer wipe(second)
	if subtle.ConstantTimeCompare(first, second) != 1 {
		wipe(first)
		return nil, errors.New("parolalar eşleşmiyor")
	}
	return first, nil
}

func existingPassphrase(env *Env, passFile string) ([]byte, error) {
	if passFile != "" {
		return readPassphraseFile(passFile)
	}
	if !env.IsTerminal() {
		return nil, usageError("terminal yok; --passphrase-file kullan")
	}
	return env.ReadSecret("Kök anahtar parolası: ")
}

func readPassphraseFile(path string) ([]byte, error) {
	data, err := securefile.ReadPrivate(path, maxPassphraseFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("parola dosyası bulunamadı: %s", path)
		}
		return nil, fmt.Errorf("parola dosyası okunamadı: %w", err)
	}
	trimmed := bytes.TrimRight(data, "\r\n")
	p := append([]byte(nil), trimmed...)
	wipe(data)
	return p, nil
}

func formatTime(t time.Time) string {
	return t.UTC().Format("2006-01-02 15:04 UTC")
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
