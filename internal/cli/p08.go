package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

// Commands of the membership package (ADR-0027, ADR-0028): root key
// rotation and recovery, recovery keys, preauthorized enrollment keys,
// ephemeral and inactive devices, leave requests, invite notes and
// rejections, the minimum client version and machine rebinding.

const (
	maxP08File      = 64 << 10
	maxPreauthFile  = 4 << 20
	maxRecoveryFile = 8 << 10
)

func p08Commands() []command {
	return append(p01Commands(), []command{ // P01 commands first (p01.go)
		{"network recovery-key add", "Çevrimdışı saklanacak kurtarma anahtarı oluşturur (kök ele geçirilirse ağı kurtarır)", cmdRecoveryKeyAdd},
		{"network rotate-root", "Kök anahtarı yeniler; cihazlar yeniden katılmadan yeni köke geçer", cmdRotateRoot},
		{"network root-recover", "Ele geçirilmiş kökü kurtarma anahtarıyla iptal edip son güvenilir sürümden yeni kökle devam eder", cmdRootRecover},
		{"network transitions", "Kök anahtar geçişlerini listeler", cmdNetworkTransitions},
		{"network min-version", "Koordinatörün kabul edeceği asgari istemci sürümünü belirler: --version 1.2.3 | --clear", cmdNetworkMinVersion},
		{"network chain", "Sürüm zincirini açar/kapatır (her sürüm öncekinin özetini taşır; eski cihazlar reddeder): --state on|off [--yes]", cmdNetworkChain},
		{"root apply", "Kök geçişlerini ve yeni belgeyi bu cihaza elle uygular (eski koordinatörler için)", cmdRootApply},
		{"device preauth", "Sunucu/konteyner için ön onaylı, etkileşimsiz kayıt anahtarı üretir", cmdDevicePreauth},
		{"preauth-join", "Ön onaylı kayıt anahtarıyla bu sunucuyu etkileşimsiz ağa katar", cmdPreauthJoin},
		{"device ephemeral", "Cihazı geçici (üyeliği dolunca kendiliğinden düşer) veya kalıcı yapar: --state on|off", cmdDeviceEphemeral},
		{"device inactive", "Uzun süredir görülmeyen cihazları listeler", cmdDeviceInactive},
		{"device remove", "Birden çok cihazı tek imzayla ağdan çıkarır: --names a,b", cmdDeviceRemove},
		{"device leave-apply", "Cihazın imzalı ayrılma isteğini uygular (cihazı ağdan çıkarır)", cmdDeviceLeaveApply},
		{"device rebind", "Bu bilgisayara taşınan cihaz kimliğini bilerek kabul eder", cmdDeviceRebind},
		{"leave", "Bu cihaz için imzalı ayrılma isteği üretir ve yerel anahtarı siler", cmdLeave},
		{"invite list", "Etkin davetleri açıklama ve kullanım sayısıyla listeler", cmdInviteList},
		{"invite note", "Davete yalnızca yönetici bilgisayarında tutulan açıklama yazar", cmdInviteNote},
		{"invite reject", "Bekleyen bir katılım isteğini daveti iptal etmeden reddeder", cmdInviteReject},
	}...)
}

// readArg reads a flag value given inline or as @file.
func readArg(value string, limit int64) (string, error) {
	if !strings.HasPrefix(value, "@") {
		return value, nil
	}
	data, err := securefile.ReadLimited(strings.TrimPrefix(value, "@"), limit)
	if err != nil {
		return "", fmt.Errorf("dosya okunamadı: %w", err)
	}
	return string(data), nil
}

func loadNetwork(env *Env, dir string) (*admin.Network, error) {
	if dir == "" {
		return nil, usageError("--dir zorunlu")
	}
	return admin.Load(dir, env.adminOptions())
}

// --- Root key (ADR-0027) ---

func cmdRecoveryKeyAdd(env *Env, args []string) error {
	fs := newFlagSet(env, "network recovery-key add")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	out := fs.String("out", "", "kurtarma anahtarı dosyası (zorunlu; bu bilgisayardan çıkarıp çevrimdışı saklayın)")
	passFile := fs.String("passphrase-file", "", "kök anahtar parolasını bu dosyadan oku")
	recFile := fs.String("recovery-passphrase-file", "", "kurtarma anahtarı parolasını bu dosyadan oku")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *out == "" {
		return usageError("--out zorunlu")
	}
	n, err := loadNetwork(env, *dir)
	if err != nil {
		return err
	}
	passphrase, err := existingPassphrase(env, *passFile)
	if err != nil {
		return err
	}
	defer wipe(passphrase)
	recPass, err := newPassphrase(env, *recFile, "Kurtarma anahtarı (kök paroladan farklı)")
	if err != nil {
		return err
	}
	defer wipe(recPass)
	file, fp, err := n.AddRecoveryKey(passphrase, recPass, env.Now())
	if err != nil {
		return err
	}
	if err := securefile.WriteNew(*out, file); err != nil {
		return fmt.Errorf("kurtarma anahtarı yazılamadı (anahtar belgeye eklendi; yeniden oluşturun): %w", err)
	}
	w := env.Stdout
	fmt.Fprintf(w, "Kurtarma anahtarı oluşturuldu ve ağ belgesine eklendi. Parmak izi: %s\n", fp)
	fmt.Fprintf(w, "Dosya: %s\n", *out)
	fmt.Fprintln(w, "Bu dosyayı bu bilgisayardan çıkarıp çevrimdışı (USB bellek, kasa) saklayın; günlük kullanımda hiçbir cihazda durmamalı.")
	fmt.Fprintln(w, "Cihazlar kurtarma anahtarını ilk gördükleri belgede sabitler; önce bütün cihazları bu sürüme güncelleyin.")
	return nil
}

func cmdRotateRoot(env *Env, args []string) error {
	fs := newFlagSet(env, "network rotate-root")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	passFile := fs.String("passphrase-file", "", "mevcut kök anahtar parolasını bu dosyadan oku")
	newFile := fs.String("new-passphrase-file", "", "yeni kök anahtar parolası (verilmezse mevcut parola kalır)")
	confirm := fs.String("confirm", "", "onay metni (betikler için): YENIKOK")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	n, err := loadNetwork(env, *dir)
	if err != nil {
		return err
	}
	if err := confirmCritical(env, *confirm, "YENIKOK", "Kök anahtar yenilenecek; eski yedekler geçersiz olur"); err != nil {
		return err
	}
	passphrase, err := existingPassphrase(env, *passFile)
	if err != nil {
		return err
	}
	defer wipe(passphrase)
	var next []byte
	if *newFile != "" {
		if next, err = newPassphrase(env, *newFile, "Yeni kök anahtar"); err != nil {
			return err
		}
		defer wipe(next)
	}
	change, err := n.RotateRoot(passphrase, next, env.Now())
	if err != nil {
		return err
	}
	printRootChange(env, change)
	fmt.Fprintln(env.Stdout, "Eski kök anahtarın yedekleri artık işe yaramaz: 'openscale network backup' ile yeni yedek alın.")
	return nil
}

func cmdRootRecover(env *Env, args []string) error {
	fs := newFlagSet(env, "network root-recover")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	recKey := fs.String("recovery-key", "", "kurtarma anahtarı dosyası (zorunlu)")
	lastGood := fs.Uint64("last-good", 0, "güvendiğiniz son belge sürümü (zorunlu; 'openscale network verify' listeler)")
	bad := fs.String("bad-document", "", "ele geçirilmiş kökle imzalanmış belgeler (cihazın network.json dosyası), virgülle ayrılmış")
	minEpoch := fs.Uint64("min-epoch", 0, "saldırganın kullandığı en yüksek kök dönemi (varsa)")
	minVersion := fs.Uint64("min-version", 0, "saldırganın kullandığı en yüksek belge sürümü (varsa)")
	recFile := fs.String("recovery-passphrase-file", "", "kurtarma anahtarı parolasını bu dosyadan oku")
	newFile := fs.String("new-passphrase-file", "", "yeni kök anahtar parolasını bu dosyadan oku")
	confirm := fs.String("confirm", "", "onay metni (betikler için): KURTAR")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *dir == "" || *recKey == "" || *lastGood == 0 {
		return usageError("--dir, --recovery-key ve --last-good zorunlu")
	}
	keyData, err := securefile.ReadLimited(*recKey, maxRecoveryFile)
	if err != nil {
		return fmt.Errorf("kurtarma anahtarı okunamadı: %w", err)
	}
	var badDocs [][]byte
	for _, p := range splitList(*bad) {
		data, err := securefile.ReadLimited(p, trust.MaxEnvelopeSize)
		if err != nil {
			return fmt.Errorf("belge okunamadı: %w", err)
		}
		badDocs = append(badDocs, data)
	}
	if err := confirmCritical(env, *confirm, "KURTAR", "Kök anahtar iptal edilip ağ sürüm "+fmt.Sprint(*lastGood)+" içeriğiyle yeni köke taşınacak"); err != nil {
		return err
	}
	var recPass []byte
	if *recFile != "" {
		recPass, err = readPassphraseFile(*recFile)
	} else if env.IsTerminal() {
		recPass, err = env.ReadSecret("Kurtarma anahtarı parolası: ")
	} else {
		err = usageError("terminal yok; --recovery-passphrase-file kullan")
	}
	if err != nil {
		return err
	}
	defer wipe(recPass)
	next, err := newPassphrase(env, *newFile, "Yeni kök anahtar")
	if err != nil {
		return err
	}
	defer wipe(next)
	change, err := admin.RecoverRoot(*dir, admin.RecoverOptions{
		RecoveryKey: keyData, RecoveryPassphrase: recPass, NewPassphrase: next,
		LastGoodVersion: *lastGood, BadDocuments: badDocs, MinEpoch: *minEpoch, MinVersion: *minVersion,
	}, env.adminOptions(), env.Now())
	if err != nil {
		return err
	}
	printRootChange(env, change)
	if len(change.Revoked) > 0 {
		fmt.Fprintf(env.Stdout, "Saldırganın eklediği veya anahtarını değiştirdiği cihazlar iptal edildi: %s\n", strings.Join(change.Revoked, ", "))
	}
	fmt.Fprintln(env.Stdout, "Ele geçirilmiş süre içinde açılmış bağlantılar geri alınamaz; parolaları ve sırları yenileyin. Yeni kök için yedek alın.")
	return nil
}

func printRootChange(env *Env, c *admin.RootChange) {
	w := env.Stdout
	fmt.Fprintf(w, "Kök anahtar değişti (%s): dönem %d, belge sürümü %d.\n", c.Kind, c.Epoch, c.Version)
	fmt.Fprintf(w, "Eski kök parmak izi: %s\nYeni kök parmak izi: %s\n", c.OldFingerprint, c.NewFingerprint)
	fmt.Fprintln(w, "Ağ klasörünü izleyen yönetici cihaz geçişi koordinatöre yayımlar; cihazlar yeniden katılmadan yeni köke geçer.")
	fmt.Fprintln(w, "Koordinatör eskiyse geçiş satırını cihazlarda 'openscale root apply' ile elle uygulayın:")
	fmt.Fprintln(w, c.Line)
}

func cmdNetworkTransitions(env *Env, args []string) error {
	fs := newFlagSet(env, "network transitions")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	n, err := loadNetwork(env, *dir)
	if err != nil {
		return err
	}
	list, err := n.RootTransitions()
	if err != nil {
		return err
	}
	if len(list) == 0 {
		fmt.Fprintln(env.Stdout, "Kök anahtar hiç değişmedi.")
		return nil
	}
	for _, st := range list {
		t, err := trust.ParseRootTransition(st)
		if err != nil {
			continue
		}
		fmt.Fprintf(env.Stdout, "dönem %d  %-9s  %s  son güvenilir sürüm %d  yeni kök %s\n", t.Epoch, t.Kind, formatTime(t.IssuedAt),
			t.LastGoodVersion, trust.RootFingerprint(t.NewRoot[:]))
	}
	return nil
}

func cmdNetworkMinVersion(env *Env, args []string) error {
	fs := newFlagSet(env, "network min-version")
	f := addEditFlags(fs)
	v := fs.String("version", "", "asgari istemci sürümü, ör. 1.4.0")
	clear := fs.Bool("clear", false, "asgari sürümü kaldırır")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if (*v == "") == !*clear {
		return usageError("--version veya --clear verin")
	}
	value := *v
	if *clear {
		value = ""
	}
	return runEdit(env, f, func(doc *trust.Document) error { return doc.SetMinClientVersion(value) })
}

func cmdRootApply(env *Env, args []string) error {
	fs := newFlagSet(env, "root apply")
	stateDir := fs.String("state-dir", "", "cihazın durum klasörü (varsayılan: kullanıcı yapılandırma klasörü)")
	transitions := fs.String("transitions", "", "geçiş satırları (osroot1.), virgülle ayrılmış, veya @dosya (zorunlu)")
	document := fs.String("document", "", "yeni kökün imzaladığı network.json dosyası (zorunlu)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *transitions == "" || *document == "" {
		return usageError("--transitions ve --document zorunlu")
	}
	dir, err := resolveStateDir(env, *stateDir)
	if err != nil {
		return err
	}
	text, err := readArg(*transitions, maxP08File)
	if err != nil {
		return err
	}
	var ts []trust.SignedRootTransition
	for _, line := range strings.FieldsFunc(text, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' || r == ' ' || r == '"' }) {
		if !strings.HasPrefix(line, "osroot1.") {
			continue
		}
		st, err := trust.DecodeRootTransition(line)
		if err != nil {
			return err
		}
		ts = append(ts, st)
	}
	data, err := securefile.ReadLimited(*document, trust.MaxEnvelopeSize)
	if err != nil {
		return fmt.Errorf("belge okunamadı: %w", err)
	}
	store, err := member.Open(dir)
	if err != nil {
		return err
	}
	if _, err := store.AcceptTransitions(ts, data, env.Now()); err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Kök geçişi uygulandı: dönem %d, belge sürümü %d.\n", store.Epoch(), store.Document().Version)
	return nil
}

// --- Preauthorized keys and device lifecycle (ADR-0028) ---

func cmdDevicePreauth(env *Env, args []string) error {
	fs := newFlagSet(env, "device preauth")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	name := fs.String("name", "", "cihaz adı (zorunlu)")
	tags := fs.String("tags", "", "etiketler, virgülle ayrılmış (ör. ci)")
	hours := fs.Int("hours", 0, "üyelik süresi (saat; varsayılan geçici cihazda 24, değilse 365 gün)")
	ephemeral := fs.Bool("ephemeral", false, "geçici cihaz: üyeliği dolunca bir sonraki imzalı sürümde kendiliğinden düşer")
	exitNode := fs.Bool("exit-node", false, "cihaz çıkış düğümü olabilir")
	out := fs.String("out", "", "kayıt anahtarının yazılacağı dosya (zorunlu; '-' ekrana yazar)")
	passFile := fs.String("passphrase-file", "", "parolayı bu dosyadan oku")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *name == "" || *out == "" {
		return usageError("--name ve --out zorunlu")
	}
	maxHours := int(trust.MaxDeviceLife.Hours())
	if *ephemeral {
		maxHours = int(trust.MaxEphemeralLife.Hours())
	}
	if *hours < 0 || *hours > maxHours {
		return usageError("--hours 1 ile %d arasında olmalı", maxHours)
	}
	n, err := loadNetwork(env, *dir)
	if err != nil {
		return err
	}
	passphrase, err := existingPassphrase(env, *passFile)
	if err != nil {
		return err
	}
	defer wipe(passphrase)
	line, dev, err := n.CreatePreauthKey(passphrase, trust.PreauthOptions{
		Name: *name, Tags: splitList(*tags), Lifetime: time.Duration(*hours) * time.Hour, Ephemeral: *ephemeral, ExitNode: *exitNode,
	}, env.Now())
	if err != nil {
		return err
	}
	w := env.Stdout
	if *out == "-" {
		fmt.Fprintln(w, line)
	} else if err := securefile.WriteNew(*out, []byte(line+"\n")); err != nil {
		return fmt.Errorf("kayıt anahtarı yazılamadı (cihaz belgeye eklendi; 'openscale device revoke' ile çıkarın): %w", err)
	} else {
		fmt.Fprintf(w, "Kayıt anahtarı yazıldı: %s\n", *out)
	}
	fmt.Fprintf(w, "Cihaz %s (%s) ön onaylı olarak eklendi; üyelik sonu %s.\n", dev.Name, dev.IPv4, formatTime(dev.ExpiresAt))
	fmt.Fprintln(w, "Anahtar cihazın özel anahtarlarını içerir: parola gibi saklayın, tek bir sunucuda kullanın ve kullandıktan sonra silin.")
	fmt.Fprintln(w, "Sunucuda: openscale preauth-join --key @dosya && openscale up")
	return nil
}

func cmdPreauthJoin(env *Env, args []string) error {
	fs := newFlagSet(env, "preauth-join")
	stateDir := fs.String("state-dir", "", "durum klasörü (varsayılan: kullanıcı yapılandırma klasörü)")
	key := fs.String("key", "", "kayıt anahtarı (osauth1.) veya @dosya; boşsa OPENSCALE_AUTH_KEY")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	value := *key
	if value == "" {
		value = os.Getenv("OPENSCALE_AUTH_KEY")
	}
	if value == "" {
		return usageError("--key veya OPENSCALE_AUTH_KEY gerekli")
	}
	line, err := readArg(value, maxPreauthFile)
	if err != nil {
		return err
	}
	k, anchor, _, err := trust.OpenPreauthKey(line, env.Now())
	if err != nil {
		return err
	}
	dir, err := resolveStateDir(env, *stateDir)
	if err != nil {
		return err
	}
	keyPath := filepath.Join(dir, deviceKeyFile)
	if existing, err := readSecrets(keyPath); err == nil {
		if existing.DeviceID != k.Device.DeviceID {
			return errors.New("bu klasörde başka bir cihaz anahtarı var; başka bir --state-dir seçin")
		}
	} else if errors.Is(err, os.ErrNotExist) {
		encoded, err := trust.MarshalDeviceSecrets(&k.Device)
		if err != nil {
			return err
		}
		defer wipe(encoded)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		if err := securefile.WriteNew(keyPath, encoded); err != nil {
			return fmt.Errorf("cihaz anahtarı yazılamadı: %w", err)
		}
	} else {
		return err
	}
	envData, err := trust.MarshalEnvelope(k.Document)
	if err != nil {
		return err
	}
	store, err := member.JoinAnchor(dir, anchor, envData, env.Now())
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Ağa ön onaylı kayıtla katılındı: belge sürümü %d, durum klasörü %s\n", store.Document().Version, dir)
	fmt.Fprintln(env.Stdout, "Tüneli açmak için: openscale up --state-dir "+dir)
	return nil
}

func cmdDeviceEphemeral(env *Env, args []string) error {
	fs := newFlagSet(env, "device ephemeral")
	f := addEditFlags(fs)
	name := fs.String("name", "", "cihaz adı (zorunlu)")
	state := fs.String("state", "", "on (geçici) veya off (kalıcı)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *name == "" || (*state != "on" && *state != "off") {
		return usageError("--name ve --state on|off zorunlu")
	}
	now := env.Now()
	return runEdit(env, f, func(doc *trust.Document) error { return doc.SetDeviceEphemeral(*name, *state == "on", now) })
}

func cmdDeviceInactive(env *Env, args []string) error {
	fs := newFlagSet(env, "device inactive")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	days := fs.Int("days", int(admin.DefaultInactiveAfter.Hours()/24), "en az bu kadar gündür görülmeyenler")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	after, err := daysFlag(*days, 1, 3650, "days")
	if err != nil {
		return err
	}
	n, err := loadNetwork(env, *dir)
	if err != nil {
		return err
	}
	list := n.InactiveDevices(nil, after, env.Now())
	if len(list) == 0 {
		fmt.Fprintf(env.Stdout, "%d gündür görülmeyen cihaz yok.\n", *days)
		return nil
	}
	fmt.Fprintln(env.Stdout, "Son görülme bilgisi panelin kaydettiği zamanlardır; panel hiç açılmadıysa eklenme tarihi esas alınır.")
	var names []string
	for _, d := range list {
		seen := "hiç görülmedi"
		if !d.LastSeen.IsZero() {
			seen = "son görülme " + formatTime(d.LastSeen)
		}
		note := ""
		if d.Admin {
			note = " (yönetici)"
		}
		fmt.Fprintf(env.Stdout, "  %-24s %4d gün  %s%s\n", d.Name, d.Days, seen, note)
		if !d.Admin {
			names = append(names, d.Name)
		}
	}
	if len(names) > 0 {
		fmt.Fprintf(env.Stdout, "\nTek imzayla çıkarmak için: openscale device remove --dir %s --names %s\n", *dir, strings.Join(names, ","))
	}
	return nil
}

func cmdDeviceRemove(env *Env, args []string) error {
	fs := newFlagSet(env, "device remove")
	f := addEditFlags(fs)
	names := fs.String("names", "", "çıkarılacak cihazlar, virgülle ayrılmış (zorunlu)")
	confirm := fs.String("confirm", "", "onay metni (betikler için): çıkarılacak cihaz sayısı")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	list := splitList(*names)
	if len(list) == 0 {
		return usageError("--names zorunlu")
	}
	slices.Sort(list)
	list = slices.Compact(list)
	if !*f.dryRun {
		if err := confirmCritical(env, *confirm, fmt.Sprint(len(list)), fmt.Sprintf("%d cihaz kalıcı olarak çıkarılacak (%s)", len(list), strings.Join(list, ", "))); err != nil {
			return err
		}
	}
	now := env.Now()
	return runEdit(env, f, func(doc *trust.Document) error {
		_, err := doc.RevokeDevices(list, now)
		return err
	})
}

func cmdDeviceLeaveApply(env *Env, args []string) error {
	fs := newFlagSet(env, "device leave-apply")
	f := addEditFlags(fs)
	request := fs.String("request", "", "ayrılma isteği (osleave1.) veya @dosya (zorunlu)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *request == "" {
		return usageError("--request zorunlu")
	}
	line, err := readArg(*request, maxP08File)
	if err != nil {
		return err
	}
	sl, err := trust.DecodeLeave(line)
	if err != nil {
		return err
	}
	now := env.Now()
	return runEdit(env, f, func(doc *trust.Document) error {
		dev, _, err := doc.ApplyLeave(sl, now)
		if err == nil {
			fmt.Fprintf(env.Stdout, "%s ayrılmak istedi; ağdan çıkarılıyor.\n", dev.Name)
		}
		return err
	})
}

func cmdDeviceRebind(env *Env, args []string) error {
	fs := newFlagSet(env, "device rebind")
	stateDir := fs.String("state-dir", "", "cihazın durum klasörü (varsayılan: kullanıcı yapılandırma klasörü)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	dir, err := resolveStateDir(env, *stateDir)
	if err != nil {
		return err
	}
	secrets, err := readSecrets(filepath.Join(dir, deviceKeyFile))
	if err != nil {
		return fmt.Errorf("cihaz anahtarı okunamadı: %w", err)
	}
	if err := node.RebindMachine(dir, secrets.DeviceID); err != nil {
		return err
	}
	fmt.Fprintln(env.Stdout, "Cihaz kimliği bu bilgisayara bağlandı. Kimliğin eski bilgisayarda çalışmadığından emin olun; aynı kimlik iki yerde çakışır.")
	return nil
}

// leaveFiles are removed from the state directory after a leave request.
var leaveFiles = []string{deviceKeyFile, "anchor.json", "state.json", "network.json", "network.json.bak", "root.json", "machine.json", "endpoints.json"}

func cmdLeave(env *Env, args []string) error {
	fs := newFlagSet(env, "leave")
	stateDir := fs.String("state-dir", "", "cihazın durum klasörü (varsayılan: kullanıcı yapılandırma klasörü)")
	out := fs.String("out", "", "ayrılma isteğini bu dosyaya da yaz")
	confirm := fs.String("confirm", "", "onay metni (betikler için): AYRIL")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	dir, err := resolveStateDir(env, *stateDir)
	if err != nil {
		return err
	}
	secrets, err := readSecrets(filepath.Join(dir, deviceKeyFile))
	if err != nil {
		return fmt.Errorf("cihaz anahtarı okunamadı: %w", err)
	}
	store, err := member.Open(dir)
	if err != nil {
		return err
	}
	if err := confirmCritical(env, *confirm, "AYRIL", "Bu cihazın anahtarı silinecek ve ağa bir daha bu kimlikle bağlanamayacak"); err != nil {
		return err
	}
	sl, err := secrets.NewLeaveRequest(env.Random, store.Document().NetworkID, env.Now())
	if err != nil {
		return err
	}
	line, err := trust.EncodeLeave(sl)
	if err != nil {
		return err
	}
	if *out != "" {
		if err := securefile.WriteNew(*out, []byte(line+"\n")); err != nil {
			return fmt.Errorf("istek yazılamadı; anahtar silinmedi: %w", err)
		}
	}
	w := env.Stdout
	fmt.Fprintln(w, "Ayrılma isteği (yöneticiye verin: 'openscale device leave-apply --request ...' veya panel):")
	fmt.Fprintln(w, line)
	var failed []string
	for _, name := range leaveFiles {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			failed = append(failed, name)
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("şu dosyalar silinemedi, elle silin: %s", strings.Join(failed, ", "))
	}
	fmt.Fprintln(w, "Bu cihazın anahtarı ve ağ durumu silindi. Masaüstü uygulamasında panelden 'Ağdan ayrıl' isteği koordinatöre de iletir.")
	return nil
}

// --- Invites (F-132, F-107) ---

func cmdInviteList(env *Env, args []string) error {
	fs := newFlagSet(env, "invite list")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	n, err := loadNetwork(env, *dir)
	if err != nil {
		return err
	}
	doc, err := n.Document()
	if err != nil {
		return err
	}
	notes := n.InviteNotes()
	now := env.Now()
	shown := 0
	for _, inv := range doc.Invites {
		if !inv.ActiveAt(now) {
			continue
		}
		shown++
		uses := "kullanılmadı"
		switch {
		case inv.MultiUse():
			uses = fmt.Sprintf("%d/%d kullanıldı", len(inv.Uses), inv.MaxUses)
		case inv.UsedBy != "":
			uses = "kullanıldı"
		}
		fmt.Fprintf(env.Stdout, "%s  bitiş %s  %s  %s\n", inv.ID[:8], formatTime(inv.ExpiresAt), uses, notes[inv.ID])
	}
	if shown == 0 {
		fmt.Fprintln(env.Stdout, "Etkin davet yok.")
	}
	return nil
}

// inviteByPrefix finds an active invite by its id or id prefix.
func inviteByPrefix(doc *trust.Document, prefix string) (trust.Invite, error) {
	var found []trust.Invite
	for _, inv := range doc.Invites {
		if strings.HasPrefix(inv.ID, prefix) && prefix != "" {
			found = append(found, inv)
		}
	}
	if len(found) != 1 {
		return trust.Invite{}, errors.New("davet bulunamadı veya kimlik belirsiz; 'openscale invite list' ile bakın")
	}
	return found[0], nil
}

func cmdInviteNote(env *Env, args []string) error {
	fs := newFlagSet(env, "invite note")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	id := fs.String("invite", "", "davet kimliği veya başı (zorunlu)")
	note := fs.String("note", "", "açıklama (boş: kaldırır)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	n, err := loadNetwork(env, *dir)
	if err != nil {
		return err
	}
	doc, err := n.Document()
	if err != nil {
		return err
	}
	inv, err := inviteByPrefix(doc, *id)
	if err != nil {
		return err
	}
	if err := n.SetInviteNote(inv.ID, *note); err != nil {
		return err
	}
	fmt.Fprintln(env.Stdout, "Açıklama kaydedildi (yalnızca bu bilgisayarda; imzalı belgeye girmez).")
	return nil
}

func cmdInviteReject(env *Env, args []string) error {
	fs := newFlagSet(env, "invite reject")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	id := fs.String("invite", "", "davet kimliği veya başı (zorunlu)")
	device := fs.String("device", "", "reddedilecek isteğin cihaz kimliği (32 karakter, zorunlu)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	n, err := loadNetwork(env, *dir)
	if err != nil {
		return err
	}
	doc, err := n.Document()
	if err != nil {
		return err
	}
	inv, err := inviteByPrefix(doc, *id)
	if err != nil {
		return err
	}
	if err := n.RejectPending(inv.ID, *device, env.Now()); err != nil {
		return err
	}
	fmt.Fprintln(env.Stdout, "İstek reddedildi; panelde bir daha gösterilmez ve onaylanamaz. Davet geçerli kalır.")
	return nil
}
