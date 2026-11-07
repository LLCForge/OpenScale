package cli

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/logcrypt"
	"github.com/openscale/openscale/internal/qr"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/service"
	"github.com/openscale/openscale/internal/trust"
)

// Key and crypto hardening commands (P13: #8, #9, #11, #12, #17, #18, #19,
// #20, #44; ADR-0060, ADR-0062, ADR-0063).

type keySubcommand struct {
	name    string
	summary string
	run     func(*Env, []string) error
}

func keySubcommands() []keySubcommand {
	return []keySubcommand{
		{"status", "Anahtar dosyalarının korumasını, bellek kilidini ve rastgelelik denetimini gösterir", cmdKeyStatus},
		{"protect", "Cihaz/koordinatör anahtar dosyalarını işletim sistemi anahtar deposuyla şifreler (Windows DPAPI)", cmdKeyProtect},
		{"unprotect", "Korumayı kaldırır ve klasörde otomatik korumayı kapatır (eski sürüme dönmeden önce)", cmdKeyUnprotect},
		{"kdf-upgrade", "Kök anahtarı aynı parolayla daha güçlü Argon2id ayarlarıyla yeniden şifreler", cmdKeyKDFUpgrade},
		{"strength", "Bir parolanın tahmin edilebilirliğini yerel olarak ölçer", cmdKeyStrength},
		{"paper-backup", "Kök anahtarın parolalı kâğıt yedeğini QR ve satırlar olarak üretir", cmdKeyPaperBackup},
		{"paper-restore", "Kök anahtarı kâğıt yedekten (QR metni veya satırlar) geri yükler", cmdKeyPaperRestore},
		{"request", "Kayıt isteğini QR kod, parmak izi ve kısa doğrulama koduyla gösterir", cmdKeyRequest},
		{"sas", "Kısa doğrulama kodunu gösterir: bu cihaz, bir kayıt isteği veya kök anahtar", cmdKeySAS},
		{"log-decrypt", "Şifreli hata ayıklama günlüğünü cihaz anahtarıyla çözer", cmdKeyLogDecrypt},
		{"selftest", "Rastgelelik sağlık denetimini ve bellek kilidini dener", cmdKeySelftest},
	}
}

func cmdKey(env *Env, args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprintln(env.Stdout, "Kullanım: openscale key <alt komut> [seçenekler]\n\nAlt komutlar:")
		for _, c := range keySubcommands() {
			fmt.Fprintf(env.Stdout, "  %-14s %s\n", c.name, c.summary)
		}
		if len(args) == 0 {
			return usageError("alt komut gerekli")
		}
		return nil
	}
	for _, c := range keySubcommands() {
		if c.name == args[0] {
			return c.run(env, args[1:])
		}
	}
	return usageError("bilinmeyen alt komut %q", args[0])
}

// keyDirs resolves the key directories from --state-dir and --data-dir.
func keyDirs(env *Env, stateDir, dataDir string) ([]string, error) {
	var dirs []string
	if stateDir != "" {
		dirs = append(dirs, stateDir)
	}
	if dataDir != "" {
		dirs = append(dirs, filepath.Join(dataDir, service.DeviceDir), filepath.Join(dataDir, service.CoordinatorDir), dataDir)
	}
	if len(dirs) == 0 {
		d, err := env.DefaultStateDir()
		if err != nil {
			return nil, fmt.Errorf("varsayılan klasör bulunamadı, --state-dir kullan: %w", err)
		}
		dirs = append(dirs, d)
	}
	return dirs, nil
}

// keyFiles lists the protectable key files in dirs.
func keyFiles(dirs []string) []string {
	var files []string
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.Type().IsRegular() && securefile.IsKeyFileName(e.Name()) {
				files = append(files, filepath.Join(dir, e.Name()))
			}
		}
	}
	sort.Strings(files)
	return files
}

func keyDirFlags(fs *flag.FlagSet) (*string, *string) {
	return fs.String("state-dir", "", "anahtar klasörü (varsayılan: kullanıcı yapılandırma klasörü)"),
		fs.String("data-dir", "", "servisin veri klasörü, ör. %ProgramData%\\OpenScale (device ve coordinator alt klasörleriyle)")
}

func schemeText(s securefile.Scheme) string {
	switch s {
	case securefile.SchemeDPAPIMachine:
		return "Windows DPAPI (makine kapsamı)"
	case securefile.SchemeDPAPIUser:
		return "Windows DPAPI (kullanıcı kapsamı)"
	}
	return "düz dosya (yalnızca dosya izinleri)"
}

func cmdKeyStatus(env *Env, args []string) error {
	fs := newFlagSet(env, "key status")
	stateDir, dataDir := keyDirFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	dirs, err := keyDirs(env, *stateDir, *dataDir)
	if err != nil {
		return err
	}
	w := env.Stdout
	files := keyFiles(dirs)
	if len(files) == 0 {
		fmt.Fprintf(w, "Anahtar dosyası bulunamadı: %s\n", strings.Join(dirs, ", "))
	}
	for _, f := range files {
		s, err := securefile.FileScheme(f)
		if err != nil {
			fmt.Fprintf(w, "  %s: okunamadı (%s)\n", f, describe(err))
			continue
		}
		fmt.Fprintf(w, "  %s: %s\n", f, schemeText(s))
	}
	for _, d := range dirs {
		if _, err := os.Stat(filepath.Join(d, securefile.OptOutFile)); err == nil {
			fmt.Fprintf(w, "  %s: otomatik koruma kapalı (%s var)\n", d, securefile.OptOutFile)
		}
	}
	switch {
	case securefile.ProtectionAvailable():
		fmt.Fprintln(w, "İşletim sistemi anahtar deposu: Windows DPAPI kullanılabilir; anahtarlar ilk açılışta korunur.")
	default:
		fmt.Fprintln(w, "İşletim sistemi anahtar deposu: bu platformda yok; anahtarlar 0600 izinli dosyada (ADR-0060).")
	}
	printSelftest(w)
	return nil
}

func printSelftest(w io.Writer) {
	if err := trust.CheckSystemRandom(); err != nil {
		fmt.Fprintf(w, "Rastgelelik sağlık denetimi: BAŞARISIZ (%v). Anahtar üretilmez.\n", err)
	} else {
		fmt.Fprintln(w, "Rastgelelik sağlık denetimi: geçti.")
	}
	probe := make([]byte, 32)
	switch {
	case !trust.MemoryLockSupported():
		fmt.Fprintln(w, "Bellek kilitleme: bu platformda yok (anahtarlar takas alanına yazılabilir).")
	case trust.LockKey(probe):
		fmt.Fprintln(w, "Bellek kilitleme: çalışıyor (kısmi koruma; ADR-0060).")
	default:
		fmt.Fprintln(w, "Bellek kilitleme: sınıra ulaşıldı veya izin yok; anahtarlar kilitlenmeden kullanılır.")
	}
	trust.WipeKey(probe)
}

func cmdKeySelftest(env *Env, args []string) error {
	fs := newFlagSet(env, "key selftest")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	// Cryptographic known answer tests (#531, kat.go).
	passed, err := trust.KnownAnswerTests()
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Bilinen yanıt testleri geçti: %s\n", strings.Join(passed, ", "))
	printSelftest(env.Stdout)
	return trust.CheckSystemRandom()
}

func cmdKeyProtect(env *Env, args []string) error {
	fs := newFlagSet(env, "key protect")
	stateDir, dataDir := keyDirFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if !securefile.ProtectionAvailable() {
		return errors.New("bu platformda işletim sistemi anahtar deposu yok; anahtarlar 0600 izinli dosyada kalır (ADR-0060)")
	}
	dirs, err := keyDirs(env, *stateDir, *dataDir)
	if err != nil {
		return err
	}
	files := keyFiles(dirs)
	if len(files) == 0 {
		return fmt.Errorf("anahtar dosyası bulunamadı: %s", strings.Join(dirs, ", "))
	}
	for _, f := range files {
		changed, err := securefile.ProtectFile(f)
		switch {
		case err != nil:
			return fmt.Errorf("%s korunamadı: %s", f, describe(err))
		case changed:
			fmt.Fprintf(env.Stdout, "Korundu: %s\n", f)
		default:
			fmt.Fprintf(env.Stdout, "Zaten korunuyor: %s\n", f)
		}
	}
	fmt.Fprintln(env.Stdout, "Korunan dosyalar yalnızca bu bilgisayarda açılır; başka bir bilgisayara kopyalanırsa kullanılamaz.")
	return nil
}

func cmdKeyUnprotect(env *Env, args []string) error {
	fs := newFlagSet(env, "key unprotect")
	stateDir, dataDir := keyDirFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	dirs, err := keyDirs(env, *stateDir, *dataDir)
	if err != nil {
		return err
	}
	files := keyFiles(dirs)
	if len(files) == 0 {
		return fmt.Errorf("anahtar dosyası bulunamadı: %s", strings.Join(dirs, ", "))
	}
	for _, f := range files {
		changed, err := securefile.UnprotectFile(f)
		switch {
		case err != nil:
			return fmt.Errorf("%s çözülemedi: %s", f, describe(err))
		case changed:
			fmt.Fprintf(env.Stdout, "Koruma kaldırıldı: %s\n", f)
		default:
			fmt.Fprintf(env.Stdout, "Zaten düz dosya: %s\n", f)
		}
	}
	fmt.Fprintf(env.Stdout, "Bu klasörlerde otomatik koruma kapatıldı (%s). Yeniden açmak için: openscale key protect\n", securefile.OptOutFile)
	return nil
}

func cmdKeyKDFUpgrade(env *Env, args []string) error {
	fs := newFlagSet(env, "key kdf-upgrade")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	passFile := fs.String("passphrase-file", "", "parolayı bu dosyadan oku")
	target := fs.Duration("target", trust.DefaultKDFTarget, "bu bilgisayarda hedeflenen açma süresi")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *dir == "" {
		return usageError("--dir zorunlu")
	}
	if *target < 100*time.Millisecond || *target > 10*time.Second {
		return usageError("--target 100ms ile 10s arasında olmalı")
	}
	n, err := admin.Load(*dir, env.adminOptions())
	if err != nil {
		return err
	}
	pass, err := existingPassphrase(env, *passFile)
	if err != nil {
		return err
	}
	defer wipe(pass)
	before := n.KDFParams()
	fmt.Fprintln(env.Stderr, "Bu bilgisayar ölçülüyor...")
	params, err := n.UpgradeKDF(pass, trust.CalibrateArgon2(*target))
	if errors.Is(err, admin.ErrKDFCurrent) {
		fmt.Fprintf(env.Stdout, "Kök anahtar zaten güçlü ayarlarla şifreli: t=%d, bellek=%d MiB, iş parçacığı=%d\n", before.Time, before.MemoryKiB/1024, before.Threads)
		return nil
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Kök anahtar yeniden şifrelendi: t=%d→%d, bellek=%d→%d MiB, iş parçacığı=%d\n",
		before.Time, params.Time, before.MemoryKiB/1024, params.MemoryKiB/1024, params.Threads)
	fmt.Fprintln(env.Stdout, "Mevcut yedekler kendi ayarlarıyla geçerli kalır; güçlendirmek için yeni yedek al.")
	return nil
}

func cmdKeyStrength(env *Env, args []string) error {
	fs := newFlagSet(env, "key strength")
	passFile := fs.String("passphrase-file", "", "parolayı bu dosyadan oku")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	var pass []byte
	var err error
	if *passFile != "" {
		pass, err = readPassphraseFile(*passFile)
	} else {
		if !env.IsTerminal() {
			return usageError("terminal yok; --passphrase-file kullan")
		}
		pass, err = env.ReadSecret("Denenecek parola: ")
	}
	if err != nil {
		return err
	}
	defer wipe(pass)
	bits := trust.EstimatePassphraseBits(pass)
	fmt.Fprintf(env.Stdout, "Tahmini güç: %.0f bit (en az %d gerekir)\n", bits, trust.MinPassphraseBits)
	if err := trust.CheckPassphrase(pass); err != nil {
		fmt.Fprintf(env.Stdout, "Kabul edilmez: %s\n", describe(err))
		return nil
	}
	fmt.Fprintln(env.Stdout, "Kabul edilir. Tahmin yerel kelime listesiyle yapılır; ağ isteği gönderilmez.")
	return nil
}

func qrFlags(fs *flag.FlagSet) (*string, *bool, *bool) {
	return fs.String("png", "", "QR kodunu bu PNG dosyasına da yaz"),
		fs.Bool("light-terminal", false, "terminal arka planı açık renkliyse"),
		fs.Bool("no-qr", false, "QR kodunu terminale çizme")
}

// showQR draws text as a QR code in the terminal and optionally as PNG.
func showQR(env *Env, text string, level qr.Level, pngPath string, light, noTerminal bool) error {
	code, err := qr.EncodeText(text, level)
	if err != nil {
		return err
	}
	if !noTerminal {
		if err := code.Terminal(env.Stdout, light); err != nil {
			return err
		}
	}
	if pngPath != "" {
		var buf bytes.Buffer
		if err := code.PNG(&buf, 8); err != nil {
			return err
		}
		if err := securefile.WriteNew(pngPath, buf.Bytes()); err != nil {
			return fmt.Errorf("PNG yazılamadı: %w", err)
		}
		fmt.Fprintf(env.Stdout, "QR kodu yazıldı: %s\n", pngPath)
	}
	return nil
}

func cmdKeyPaperBackup(env *Env, args []string) error {
	fs := newFlagSet(env, "key paper-backup")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	label := fs.String("label", "kagit", "yedek için kısa not")
	passFile := fs.String("passphrase-file", "", "mevcut parolayı bu dosyadan oku")
	backupPassFile := fs.String("backup-passphrase-file", "", "yedeğin parolasını bu dosyadan oku")
	pngPath, light, noQR := qrFlags(fs)
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
	backupPass, err := newPassphrase(env, *backupPassFile, "Kâğıt yedek")
	if err != nil {
		return err
	}
	defer wipe(backupPass)
	packed, err := n.CreatePaperBackup(current, backupPass, *label, env.Now())
	if err != nil {
		return err
	}
	w := env.Stdout
	fmt.Fprintf(w, "OpenScale kök anahtar kâğıt yedeği (kök parmak izi %s)\n", n.RootFingerprint())
	if err := showQR(env, trust.PaperQRText(packed), qr.Q, *pngPath, *light, *noQR); err != nil {
		return err
	}
	fmt.Fprintln(w, "\nElle yazılacak satırlar (her satırın sonundaki iki harf o satırı denetler):")
	for _, line := range trust.PaperLines(packed) {
		fmt.Fprintln(w, "  "+line)
	}
	fmt.Fprintln(w, "\nYazdır veya elle yaz; ekran görüntüsü alma. Yedek yalnızca yedek parolasıyla açılır;")
	fmt.Fprintln(w, "parolayı kâğıtla aynı yerde saklama. Geri yükleme: openscale key paper-restore --dir <klasör> --from <dosya>")
	return nil
}

func cmdKeyPaperRestore(env *Env, args []string) error {
	fs := newFlagSet(env, "key paper-restore")
	dir := fs.String("dir", "", "ağ klasörü; network.json burada olmalı (zorunlu)")
	from := fs.String("from", "", "QR metnini veya satırları içeren dosya (zorunlu)")
	passFile := fs.String("passphrase-file", "", "yedeğin parolasını bu dosyadan oku")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *dir == "" || *from == "" {
		return usageError("--dir ve --from zorunlu")
	}
	text, err := securefile.ReadPrivate(*from, 8192)
	if err != nil {
		return fmt.Errorf("kâğıt yedek dosyası okunamadı: %w", err)
	}
	pass, err := existingPassphrase(env, *passFile)
	if err != nil {
		return err
	}
	defer wipe(pass)
	if err := admin.RestorePaper(*dir, string(text), pass, env.adminOptions()); err != nil {
		if errors.Is(err, trust.ErrPaperChecksum) {
			return fmt.Errorf("kâğıt yedekte yazım hatası: %v", err)
		}
		return err
	}
	fmt.Fprintln(env.Stdout, "Kök anahtar kâğıt yedekten geri yüklendi. Artık yedeğin parolası kullanılır; istersen 'openscale network passphrase' ile değiştir.")
	return nil
}

func cmdKeyRequest(env *Env, args []string) error {
	fs := newFlagSet(env, "key request")
	stateDir := fs.String("state-dir", "", "cihaz anahtarlarının klasörü (varsayılan: kullanıcı yapılandırma klasörü)")
	hostname := fs.String("hostname", "", "önerilen cihaz adı (varsayılan: bilgisayar adı)")
	pngPath, light, noQR := qrFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	dirs, err := keyDirs(env, *stateDir, "")
	if err != nil {
		return err
	}
	name := *hostname
	if name == "" {
		if h, err := env.Hostname(); err == nil {
			name = h
		}
	}
	secrets, _, err := loadOrCreateDeviceSecrets(env, filepath.Join(dirs[0], deviceKeyFile))
	if err != nil {
		return err
	}
	defer secrets.Wipe()
	envl, req, err := secrets.NewEnrollmentRequest(name, env.Now())
	if err != nil {
		return err
	}
	line, err := trust.EncodeEnrollment(envl)
	if err != nil {
		return err
	}
	w := env.Stdout
	fmt.Fprintln(w, "Kayıt isteği (yönetici cihazda kamerayla okut veya metni yapıştır):")
	if err := showQR(env, line, qr.L, *pngPath, *light, *noQR); err != nil {
		return err
	}
	fmt.Fprintln(w, line)
	fmt.Fprintf(w, "\nParmak izi:             %s\n", req.Fingerprint())
	fmt.Fprintf(w, "Kısa doğrulama kodu:    %s\n", req.SAS())
	fmt.Fprintln(w, "Yönetici ekranındaki kodla rakam rakam karşılaştır; eşleşmezse cihazı ekletme.")
	fmt.Fprintf(w, "İstek %d saat geçerlidir. Özel anahtarlar bu cihazdan hiç çıkmaz.\n", int(trust.EnrollmentMaxAge.Hours()))
	return nil
}

func cmdKeySAS(env *Env, args []string) error {
	fs := newFlagSet(env, "key sas")
	stateDir := fs.String("state-dir", "", "bu cihazın anahtar klasörü")
	request := fs.String("request", "", "kayıt isteği metni (osreq1....)")
	requestFile := fs.String("request-file", "", "kayıt isteğini içeren dosya")
	netDir := fs.String("dir", "", "ağ klasörü: kök anahtarın kodunu gösterir")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	w := env.Stdout
	switch {
	case *netDir != "":
		n, err := admin.Load(*netDir, env.adminOptions())
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "Kök anahtar kısa doğrulama kodu: %s\n", n.RootSAS())
		return nil
	case *request != "" || *requestFile != "":
		line := *request
		if *requestFile != "" {
			data, err := securefile.ReadLimited(*requestFile, 16<<10)
			if err != nil {
				return err
			}
			line = strings.TrimSpace(string(data))
		}
		envl, err := trust.DecodeEnrollment(line)
		if err != nil {
			return err
		}
		req, err := trust.OpenEnrollmentRequest(envl, env.Now())
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "Kısa doğrulama kodu: %s\nParmak izi:          %s\n", req.SAS(), req.Fingerprint())
		return nil
	}
	dirs, err := keyDirs(env, *stateDir, "")
	if err != nil {
		return err
	}
	secrets, err := readSecrets(filepath.Join(dirs[0], deviceKeyFile))
	if errors.Is(err, os.ErrNotExist) {
		return errors.New("bu cihazda anahtar yok; önce 'openscale keygen' veya 'openscale key request' çalıştır")
	}
	if err != nil {
		return err
	}
	defer secrets.Wipe()
	code, err := secrets.SAS()
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "Bu cihazın kısa doğrulama kodu: %s\n", code)
	return nil
}

func cmdKeyLogDecrypt(env *Env, args []string) error {
	fs := newFlagSet(env, "key log-decrypt")
	in := fs.String("in", "", "şifreli günlük dosyası (zorunlu)")
	stateDir, dataDir := keyDirFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *in == "" {
		return usageError("--in zorunlu")
	}
	dirs, err := keyDirs(env, *stateDir, *dataDir)
	if err != nil {
		return err
	}
	data, err := securefile.ReadPrivate(*in, 256<<20)
	if err != nil {
		return fmt.Errorf("günlük okunamadı: %w", err)
	}
	// The log may predate a key rotation: try the current key, then the
	// kept old keys.
	var lastErr error = errors.New("anahtar dosyası bulunamadı")
	for _, f := range keyFiles(dirs) {
		secrets, err := readSecrets(f)
		if err != nil {
			continue
		}
		var out bytes.Buffer
		n, err := logcrypt.Decrypt(&out, bytes.NewReader(data), secrets.SigningSeed)
		secrets.Wipe()
		if err == nil || (n > 0 && errors.Is(err, logcrypt.ErrCorrupt)) {
			if _, werr := env.Stdout.Write(out.Bytes()); werr != nil {
				return werr
			}
			if err != nil {
				return fmt.Errorf("günlüğün %d kaydı çözüldü, sonrası bozuk: %w", n, err)
			}
			return nil
		}
		if errors.Is(err, logcrypt.ErrNotEncryptedLog) {
			return errors.New("bu dosya şifreli bir OpenScale günlüğü değil")
		}
		lastErr = err
	}
	return fmt.Errorf("günlük bu cihazın anahtarlarıyla çözülemedi: %w", lastErr)
}
