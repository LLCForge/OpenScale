package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/release"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/service"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/updater"
)

// Recovery and update commands (P14, ADR-0095): signed updates with
// rollback (#203, #204), the backup drill (#196, #208), recovering the
// network on another computer (#196), repairing a member's state (#206),
// the self-check (#172) and the backup step of "network init" (#195).

func p14Commands() []command {
	return []command{
		{"update apply", "İmzalı sürümü kurar, servisi yeniden başlatır, başlamazsa eski sürüme döner: <manifesto|klasör|https-adresi>", cmdUpdateApply},
		{"update rollback", "Önceki programa döner (yarım kalan güncellemeyi de temizler)", cmdUpdateRollback},
		{"update status", "Kurulu sürümü, önceki programı ve yarım kalan güncellemeyi gösterir", cmdUpdateStatus},
		{"backup drill", "Yedekleri geçici klasörde açıp kurtarma adımlarını dener; gerçek veriye dokunmaz", cmdBackupDrill},
		{"drill", "Felaket kurtarma tatbikatı (backup drill ile aynı)", cmdBackupDrill},
		{"network recover", "Yönetici cihaz kaybında ağı yedekten başka bir bilgisayarda kurar, eski cihazı iptal eder", cmdNetworkRecover},
		{"state repair", "Bozuk üye durumunu başka bir cihazın network.json dosyasıyla onarır", cmdStateRepair},
		{"selfcheck", "Öz denetim: program bütünlüğü, izinler, saat, belge, disk ve yarım güncelleme", cmdSelfCheck},
	}
}

// multiFlag collects a repeatable flag.
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }

func (m *multiFlag) Set(v string) error {
	if strings.TrimSpace(v) == "" {
		return errors.New("boş değer")
	}
	*m = append(*m, v)
	return nil
}

func envContext14(env *Env) context.Context {
	if env.Ctx != nil {
		return env.Ctx
	}
	return context.Background()
}

// --- network init backup step (#195) ---------------------------------------

// finishInitBackup is the last step of "network init": the setup counts as
// complete only once a verified backup of the root key exists (ADR-0011).
// The guided "openscale setup" (p16.go) asks for the backup as its next
// step; scripts pass --backup-out.
func finishInitBackup(env *Env, n *admin.Network, passphrase []byte, dir, out, backupPassFile string, skip bool) error {
	w := env.Stdout
	if out != "" && !skip {
		if err := writeVerifiedBackup(env, n, passphrase, out, backupPassFile); err != nil {
			fmt.Fprintf(w, "\nKURULUM TAMAMLANMADI: yedek alınamadı: %s\n", describe(err))
			printBackupHint(w, dir)
			return err
		}
		fmt.Fprintln(w, "\nKurulum tamamlandı: kök anahtarın yedeği alındı ve geri açılarak doğrulandı.")
		return nil
	}
	fmt.Fprintln(w, "\nKURULUM TAMAMLANMADI: kök anahtarın yedeği yok. Yedek olmadan bu cihaz bozulursa ağ kaybolur.")
	printBackupHint(w, dir)
	return nil
}

func printBackupHint(w interface{ Write([]byte) (int, error) }, dir string) {
	fmt.Fprintf(w, "  openscale network backup --dir %s --out <USB veya başka bir konum>%sopenscale-yedek.key\n", dir, string(filepath.Separator))
	fmt.Fprintln(w, "  Sonra yedeği deneyin: openscale backup drill --dir "+dir+" --from <yedek dosyası>")
}

// writeVerifiedBackup creates a backup, writes it without overwriting and
// opens the written file again with the backup passphrase.
func writeVerifiedBackup(env *Env, n *admin.Network, current []byte, out, backupPassFile string) error {
	backupPass, err := newPassphrase(env, backupPassFile, "Yedek")
	if err != nil {
		return err
	}
	defer wipe(backupPass)
	data, err := n.CreateBackup(current, backupPass, "kurulum", env.Now())
	if err != nil {
		return err
	}
	if err := securefile.WriteNew(out, data); err != nil {
		return fmt.Errorf("yedek yazılamadı: %w", err)
	}
	if err := verifyWrittenBackup(n, out, data, backupPass); err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Yedek yazıldı ve doğrulandı: %s\n", out)
	return nil
}

// verifyWrittenBackup reads a written backup back, compares it with what
// was written and opens it with its passphrase (a backup on a failing USB
// stick is noticed now, not on the day it is needed).
func verifyWrittenBackup(n *admin.Network, out string, data, backupPass []byte) error {
	back, err := securefile.ReadLimited(out, trust.MaxSealedKeySize)
	if err != nil {
		return fmt.Errorf("yazılan yedek okunamadı: %w", err)
	}
	if !bytes.Equal(back, data) {
		return errors.New("yazılan yedek bozuk (okunan içerik farklı)")
	}
	sealed, err := trust.UnmarshalSealedRootKey(back)
	if err != nil {
		return err
	}
	priv, err := sealed.Open(backupPass)
	if err != nil {
		return fmt.Errorf("yazılan yedek açılamadı: %w", err)
	}
	wipe(priv)
	if sealed.Fingerprint() != n.RootFingerprint() {
		return errors.New("yazılan yedek bu ağın kök anahtarı değil")
	}
	return nil
}

// --- backup drill (#196, #208) ----------------------------------------------

func cmdBackupDrill(env *Env, args []string) error {
	fs := newFlagSet(env, "backup drill")
	var from, passFiles, stateDirs multiFlag
	fs.Var(&from, "from", "denenecek yedek dosyası (birden çok kez verilebilir; zorunlu)")
	fs.Var(&passFiles, "passphrase-file", "yedeğin parolası bu dosyadan (--from sırasıyla; verilmezse sorulur)")
	dir := fs.String("dir", "", "ağ klasörü (network.json buradan okunur)")
	document := fs.String("document", "", "ağ klasörü yoksa: bir cihazın network.json dosyası")
	fs.Var(&stateDirs, "state-dir", "ayrıca denenecek üye durum klasörü (birden çok kez verilebilir)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if len(from) == 0 {
		return usageError("--from zorunlu")
	}
	docPath := *document
	if *dir != "" {
		docPath = filepath.Join(*dir, "network.json")
	}
	if docPath == "" {
		return usageError("--dir veya --document zorunlu")
	}
	docData, err := securefile.ReadLimited(docPath, trust.MaxEnvelopeSize)
	if err != nil {
		return fmt.Errorf("ağ belgesi okunamadı: %w", err)
	}
	// The drill works on copies in a private temporary folder next to the
	// network document (never the shared system temp folder, ADR-0008) that
	// is removed afterwards; nothing in --dir, --state-dir or the backups
	// changes.
	tmp, err := os.MkdirTemp(filepath.Dir(docPath), ".openscale-tatbikat-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	w := env.Stdout
	failed := 0
	var rootFP string
	for i, path := range from {
		pf := ""
		if i < len(passFiles) {
			pf = passFiles[i]
		}
		fp, ver, err := drillBackup(env, tmp, i, path, pf, docData)
		if err != nil {
			failed++
			fmt.Fprintf(w, "HATA   yedek %s: %s\n", path, describe(err))
			continue
		}
		rootFP = fp
		fmt.Fprintf(w, "TAMAM  yedek %s: parola doğru, kök anahtar %s, ağ belgesi sürüm %d ile geri yüklendi\n", path, fp, ver)
	}
	for i, sd := range stateDirs {
		ver, err := drillState(tmp, i, sd)
		if err != nil {
			failed++
			fmt.Fprintf(w, "HATA   durum klasörü %s: %s\n", sd, describe(err))
			continue
		}
		fmt.Fprintf(w, "TAMAM  durum klasörü %s: çapa ve belge (sürüm %d) açılıyor\n", sd, ver)
	}
	if failed > 0 {
		return fmt.Errorf("tatbikat başarısız: %d adım geçmedi", failed)
	}
	fmt.Fprintf(w, "\nTatbikat başarılı: %d yedek açıldı ve ağ geçici bir klasörde yedekten kuruldu", len(from))
	if rootFP != "" {
		fmt.Fprintf(w, " (kök %s)", rootFP)
	}
	fmt.Fprintln(w, ". Gerçek veri değiştirilmedi.")
	fmt.Fprintln(w, "Gerçek kurtarmada: openscale network recover --dir <yeni klasör> --from <yedek> --document <network.json> [--revoke <kayıp cihaz>]")
	return nil
}

func drillBackup(env *Env, tmp string, i int, path, passFile string, docData []byte) (string, uint64, error) {
	data, err := securefile.ReadLimited(path, trust.MaxSealedKeySize)
	if err != nil {
		return "", 0, err
	}
	sealed, err := trust.UnmarshalSealedRootKey(data)
	if err != nil {
		return "", 0, err
	}
	var pass []byte
	if passFile != "" {
		pass, err = readPassphraseFile(passFile)
	} else {
		pass, err = askSecret(env, fmt.Sprintf("Yedek parolası (%s): ", filepath.Base(path)))
	}
	if err != nil {
		return "", 0, err
	}
	defer wipe(pass)
	sub := filepath.Join(tmp, fmt.Sprintf("ag-%d", i))
	if err := os.Mkdir(sub, 0o700); err != nil {
		return "", 0, err
	}
	if err := securefile.WriteNew(filepath.Join(sub, "network.json"), docData); err != nil {
		return "", 0, err
	}
	// The same steps as a real restore: the backup must have signed the
	// document and open with its passphrase.
	if err := admin.Restore(sub, data, pass, env.adminOptions()); err != nil {
		return "", 0, err
	}
	n, err := admin.Load(sub, env.adminOptions())
	if err != nil {
		return "", 0, err
	}
	if err := n.CheckPassphrase(pass); err != nil {
		return "", 0, err
	}
	doc, err := n.Document()
	if err != nil {
		return "", 0, err
	}
	return sealed.Fingerprint(), doc.Version, nil
}

// drillState opens a copy of a member state directory.
func drillState(tmp string, i int, dir string) (uint64, error) {
	sub := filepath.Join(tmp, fmt.Sprintf("uye-%d", i))
	if err := os.Mkdir(sub, 0o700); err != nil {
		return 0, err
	}
	for _, name := range []string{"anchor.json", "state.json", "network.json", "network.json.bak", "root.json"} {
		data, err := securefile.ReadPrivate(filepath.Join(dir, name), trust.MaxEnvelopeSize)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return 0, err
		}
		if err := securefile.WriteNew(filepath.Join(sub, name), data); err != nil {
			return 0, err
		}
	}
	store, err := member.Open(sub)
	if err != nil {
		return 0, err
	}
	return store.Document().Version, nil
}

func askSecret(env *Env, prompt string) ([]byte, error) {
	if env.IsTerminal == nil || !env.IsTerminal() || env.ReadSecret == nil {
		return nil, usageError("terminal yok; parolayı --passphrase-file ile verin")
	}
	return env.ReadSecret(prompt)
}

// --- network recover (#196) -------------------------------------------------

func cmdNetworkRecover(env *Env, args []string) error {
	fs := newFlagSet(env, "network recover")
	dir := fs.String("dir", "", "bu bilgisayarda kurulacak yeni ağ klasörü (zorunlu; içinde root.key olmamalı)")
	from := fs.String("from", "", "kök anahtar yedeği (zorunlu)")
	var documents multiFlag
	fs.Var(&documents, "document", "bir cihazın veya koordinatörün network.json dosyası (birden çok kez; en yeni geçerli olan seçilir)")
	passFile := fs.String("passphrase-file", "", "yedeğin parolasını bu dosyadan oku")
	revoke := fs.String("revoke", "", "kaybolan eski yönetici cihazın adı: ağdan kalıcı olarak çıkarılır")
	confirm := fs.String("confirm", "", "betikler için --revoke onayı: cihazın adı")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *dir == "" || *from == "" || len(documents) == 0 {
		return usageError("--dir, --from ve en az bir --document zorunlu")
	}
	if _, err := os.Stat(filepath.Join(*dir, "root.key")); err == nil {
		return fmt.Errorf("%s içinde zaten bir ağ var; aynı bilgisayarda anahtarı değiştirmek için 'openscale network restore'", *dir)
	}
	backup, err := securefile.ReadLimited(*from, trust.MaxSealedKeySize)
	if err != nil {
		return fmt.Errorf("yedek okunamadı: %w", err)
	}
	sealed, err := trust.UnmarshalSealedRootKey(backup)
	if err != nil {
		return err
	}
	var best []byte
	var bestDoc *trust.Document
	for _, p := range documents {
		data, err := securefile.ReadLimited(p, trust.MaxEnvelopeSize)
		if err != nil {
			fmt.Fprintf(env.Stdout, "Atlandı: %s (%v)\n", p, err)
			continue
		}
		e, err := trust.UnmarshalEnvelope(data)
		if err != nil {
			fmt.Fprintf(env.Stdout, "Atlandı: %s (%v)\n", p, err)
			continue
		}
		doc, err := trust.VerifyDocumentSignature(e, sealed.RootPublicKey())
		if err != nil {
			fmt.Fprintf(env.Stdout, "Atlandı: %s bu yedeğin anahtarıyla imzalanmamış (%v)\n", p, err)
			continue
		}
		fmt.Fprintf(env.Stdout, "Belge: %s sürüm %d\n", p, doc.Version)
		if bestDoc == nil || doc.Version > bestDoc.Version {
			best, bestDoc = data, doc
		}
	}
	if bestDoc == nil {
		return errors.New("bu yedeğin imzaladığı geçerli bir ağ belgesi yok")
	}
	if *revoke != "" {
		if err := confirmCritical(env, *confirm, *revoke, *revoke+" ağdan kalıcı olarak çıkarılacak"); err != nil {
			return err
		}
		if _, ok := bestDoc.DeviceByName(*revoke); !ok {
			return fmt.Errorf("%q belgede yok", *revoke)
		}
	}
	pass, err := existingPassphrase(env, *passFile)
	if err != nil {
		return err
	}
	defer wipe(pass)
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return err
	}
	if err := securefile.WriteNew(filepath.Join(*dir, "network.json"), best); err != nil {
		return fmt.Errorf("ağ belgesi yazılamadı: %w", err)
	}
	// History starts at the recovered version.
	if err := securefile.WriteNew(filepath.Join(*dir, "history", fmt.Sprintf("v%010d.json", bestDoc.Version)), best); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("geçmiş yazılamadı: %w", err)
	}
	if err := admin.Restore(*dir, backup, pass, env.adminOptions()); err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Ağ bu bilgisayarda yedekten kuruldu (belge sürüm %d, kök %s).\n", bestDoc.Version, sealed.Fingerprint())
	if *revoke != "" {
		n, err := admin.Load(*dir, env.adminOptions())
		if err != nil {
			return err
		}
		now := env.Now()
		plan, err := n.Apply(pass, now, func(doc *trust.Document) error {
			_, err := doc.RevokeDevice(*revoke, now)
			return err
		})
		if err != nil {
			return fmt.Errorf("eski cihaz iptal edilemedi: %w", err)
		}
		fmt.Fprintf(env.Stdout, "%s iptal edildi; belge sürüm %d imzalandı.\n", *revoke, plan.Next.Version)
	}
	fmt.Fprintln(env.Stdout, "\nSonraki adımlar:")
	fmt.Fprintln(env.Stdout, "  1. Yeni belgeyi yayın: bu klasörü kullanan servis veya 'openscale up' belgeyi koordinatöre yükler.")
	fmt.Fprintln(env.Stdout, "  2. Hemen yeni bir yedek alın: openscale network backup --dir "+*dir+" --out <USB>")
	fmt.Fprintln(env.Stdout, "  3. Parolayı değiştirin (yedeğin parolası kullanılıyor): openscale network passphrase --dir "+*dir)
	fmt.Fprintln(env.Stdout, "  4. Kaybolan cihazda root.key vardıysa kök anahtar geçişini düşünün (ADR-0027); iptal kök anahtarı geri almaz.")
	return nil
}

// --- state repair (#206) ----------------------------------------------------

func cmdStateRepair(env *Env, args []string) error {
	fs := newFlagSet(env, "state repair")
	stateDir := fs.String("state-dir", "", "onarılacak üye durum klasörü (zorunlu; servis için %ProgramData%\\OpenScale\\device)")
	document := fs.String("document", "", "başka bir cihazın veya koordinatörün network.json dosyası (zorunlu)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *stateDir == "" || *document == "" {
		return usageError("--state-dir ve --document zorunlu")
	}
	if store, err := member.Open(*stateDir); err == nil {
		for _, n := range store.Recovered() {
			fmt.Fprintf(env.Stdout, "Onarıldı: %s\n", n)
		}
		fmt.Fprintf(env.Stdout, "Durum klasörü sağlam (belge sürüm %d); dışarıdan belge gerekmedi.\n", store.Document().Version)
		return nil
	} else if !errors.Is(err, member.ErrNeedsDocument) {
		return err
	}
	data, err := securefile.ReadLimited(*document, trust.MaxEnvelopeSize)
	if err != nil {
		return fmt.Errorf("belge okunamadı: %w", err)
	}
	store, err := member.Repair(*stateDir, data, env.Now())
	if err != nil {
		return fmt.Errorf("onarılamadı: %w", err)
	}
	for _, n := range store.Recovered() {
		fmt.Fprintf(env.Stdout, "Onarıldı: %s\n", n)
	}
	fmt.Fprintln(env.Stdout, "Servisi veya tüneli yeniden başlatın; daha yeni belgeler koordinatörden gelir.")
	return nil
}

// --- self-check (#172) ------------------------------------------------------

func cmdSelfCheck(env *Env, args []string) error {
	fs := newFlagSet(env, "selfcheck")
	dataDir := fs.String("data-dir", "", "servis veri klasörü (Windows varsayılanı: %ProgramData%\\OpenScale)")
	stateDir := fs.String("state-dir", "", "'openscale up' veya koordinatör durum klasörü (Linux servisleri)")
	last := fs.Bool("last", false, "servisin son açılışta yaptığı öz denetimi göster")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	now := env.Now()
	if *dataDir == "" && *stateDir == "" {
		if p, err := updater.DefaultPlatform(); err == nil && p.DataDir != "" {
			*dataDir = p.DataDir
		}
	}
	var findings []service.Finding
	switch {
	case *last:
		if *dataDir == "" {
			return usageError("--last için --data-dir gerekli")
		}
		r, err := service.LastSelfCheck(*dataDir)
		if err != nil {
			return fmt.Errorf("kayıtlı öz denetim yok: %w", err)
		}
		fmt.Fprintf(env.Stdout, "Son öz denetim: %s (sürüm %s)\n", r.At.Local().Format("02.01.2006 15:04"), r.Version)
		findings = r.Findings
	case *stateDir != "":
		findings = append(findings, service.CheckStateDir(*stateDir, now)...)
		findings = append(findings, service.SelfCheckExtras(filepath.Join(filepath.Dir(*stateDir), service.UpdateDir), *stateDir, now, executable())...)
	default:
		findings = service.RepairMemberStores(*dataDir)
		findings = append(findings, service.SelfCheck(*dataDir, now, executable(), true, service.DefaultPanelPort)...)
	}
	labels := map[string]string{service.FindingOK: "TAMAM", service.FindingInfo: "BİLGİ", service.FindingWarn: "UYARI", service.FindingError: "HATA"}
	problems := 0
	for _, f := range findings {
		if f.Level == service.FindingError {
			problems++
		}
		fmt.Fprintf(env.Stdout, "%-6s %-14s %s\n", labels[f.Level], f.Area, f.Message)
	}
	if problems > 0 {
		return fmt.Errorf("%d sorun bulundu", problems)
	}
	return nil
}

func executable() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return exe
}

// --- update (#203, #204) ----------------------------------------------------

type updateFlags struct {
	rootKey, rootFP, revocations *string
	exe, artifact                *string
}

func addUpdateFlags(fs *flag.FlagSet) updateFlags {
	return updateFlags{
		rootKey:     fs.String("root-key", "", "sürüm kök açık anahtarı (dosya veya "+release.PublicKeyPrefix+"...); varsayılan: gömülü anahtar, sonra "+updater.DefaultRootKeyFile()),
		rootFP:      fs.String("root-fingerprint", "", "kök anahtarın beklenen parmak izi (ayrı kanaldan)"),
		revocations: fs.String("revocations", "", "kök imzalı iptal listesi; bu cihazdaki, programa gömülü ve manifestonun yanındaki liste her durumda uygulanır"),
		exe:         fs.String("exe", "", "değiştirilecek kurulu program (varsayılan: platformun kurulum yolu)"),
		artifact:    fs.String("artifact", "", "manifestodaki program adı (varsayılan: bu platformunki)"),
	}
}

// updateOptions builds the updater options for this computer.
func updateOptions(env *Env, f updateFlags, needRoot bool) (updater.Options, updater.Platform, error) {
	p, err := updater.DefaultPlatform()
	if err != nil {
		return updater.Options{}, p, err
	}
	if *f.exe != "" {
		p.Exe = *f.exe
	}
	art := *f.artifact
	if art == "" {
		if art, err = updater.CurrentArtifact(); err != nil {
			return updater.Options{}, p, err
		}
	}
	o := updater.Options{
		Exe: p.Exe, Artifact: art, StateDir: p.StateDir, Services: p.Services, ReadMarker: p.ReadMarker,
		Now:  env.Now,
		Logf: func(format string, args ...any) { fmt.Fprintf(env.Stdout, format+"\n", args...) },
		KeyFiles: func() []string {
			return keyFiles([]string{filepath.Join(p.DataDir, service.DeviceDir), filepath.Join(p.DataDir, service.CoordinatorDir), p.DataDir})
		},
	}
	if needRoot {
		root, where, err := updater.LoadRootKey(*f.rootKey)
		if err != nil {
			return o, p, err
		}
		o.Root, o.RootFingerprint = root, *f.rootFP
		fmt.Fprintf(env.Stdout, "Sürüm kök anahtarı (%s): %s\n", where, root.Fingerprint())
		if *f.revocations != "" {
			data, err := securefile.ReadLimited(*f.revocations, release.MaxRevocationsSize)
			if err != nil {
				return o, p, err
			}
			if o.Revocations, err = release.VerifyRevocations(root, data); err != nil {
				return o, p, err
			}
		}
	}
	return o, p, nil
}

func cmdUpdateApply(env *Env, args []string) error {
	fs := newFlagSet(env, "update apply")
	f := addUpdateFlags(fs)
	program := fs.String("file", "", "program dosyası veya https adresi (varsayılan: manifestonun yanındaki)")
	allowDowngrade := fs.Bool("allow-downgrade", false, "eski bir sürüme bilerek geç")
	reinstall := fs.Bool("reinstall", false, "aynı sürümü yeniden kur")
	installed := fs.String("installed-version", "", "kurulu sürüm okunamıyorsa elle ver")
	verifyOnly := fs.Bool("verify-only", false, "yalnızca doğrula; hiçbir şeyi değiştirme")
	health := fs.Duration("health-timeout", 90*time.Second, "yeni sürümün sağlıklı başlaması için beklenecek süre")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return usageError("%v", err)
	}
	if fs.NArg() != 1 {
		return usageError("tek argüman gerekli: imzalı manifesto, klasör veya https:// adresi")
	}
	if *health < 10*time.Second || *health > 10*time.Minute {
		return usageError("--health-timeout 10s ile 10m arasında olmalı")
	}
	o, _, err := updateOptions(env, f, true)
	if err != nil {
		return err
	}
	o.AllowDowngrade, o.Reinstall, o.Installed, o.HealthTimeout = *allowDowngrade, *reinstall, *installed, *health
	ctx := envContext14(env)
	src, err := updater.LoadSource(ctx, fs.Arg(0), *program, o.Artifact, nil)
	if err != nil {
		return err
	}
	if *verifyOnly {
		v, err := updater.VerifySource(o, src)
		if err != nil {
			return err
		}
		fmt.Fprintf(env.Stdout, "İmzalı sürüm geçerli: %s %s; program: %s. Hiçbir şey değiştirilmedi.\n", v.Manifest.Product, v.Manifest.Version, o.Artifact)
		return nil
	}
	if err := updater.RequirePrivileges(); err != nil {
		return err
	}
	res, err := updater.Apply(ctx, o, src)
	if res != nil {
		for _, w := range res.Warnings {
			fmt.Fprintf(env.Stdout, "UYARI: %s\n", w)
		}
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Güncellendi: %s -> %s", res.From, res.To)
	if res.Restarted {
		fmt.Fprintf(env.Stdout, " (servis %s kesintiyle yeniden başladı; kill switch bu sırada açık kaldı)", res.Downtime.Round(100*time.Millisecond))
	}
	fmt.Fprintln(env.Stdout, ".")
	fmt.Fprintln(env.Stdout, "Önceki programa dönmek için: openscale update rollback. Açık tepsi uygulaması eski sürümle çalışır; yeniden açın.")
	return nil
}

func cmdUpdateRollback(env *Env, args []string) error {
	fs := newFlagSet(env, "update rollback")
	f := addUpdateFlags(fs)
	unprotect := fs.Bool("unprotect-keys", false, "dönmeden önce DPAPI korumalı anahtarları düz dosyaya çevir (korumayı tanımayan eski sürüm için, ADR-0060)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	o, p, err := updateOptions(env, f, false)
	if err != nil {
		return err
	}
	if err := updater.RequirePrivileges(); err != nil {
		return err
	}
	if protected := updater.ProtectedKeys(o.KeyFiles()); len(protected) > 0 {
		if !*unprotect {
			fmt.Fprintf(env.Stdout, "UYARI: DPAPI korumalı anahtarlar var (%s). Önceki sürüm korumayı tanımıyorsa servis anahtarı okuyamaz; o durumda --unprotect-keys ile yeniden çalıştırın.\n", strings.Join(protected, ", "))
		} else {
			ctx := envContext14(env)
			for _, s := range p.Services {
				if err := s.Stop(ctx); err != nil {
					return fmt.Errorf("%s durdurulamadı: %w", s.Name(), err)
				}
			}
			for _, k := range protected {
				if _, err := securefile.UnprotectFile(k); err != nil {
					return fmt.Errorf("%s çözülemedi: %s", k, describe(err))
				}
				fmt.Fprintf(env.Stdout, "Koruma kaldırıldı: %s\n", k)
			}
			for _, s := range p.Services {
				_ = s.Start(ctx)
			}
		}
	}
	res, err := updater.Rollback(envContext14(env), o)
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Önceki program geri kondu: %s -> %s.\n", res.From, res.To)
	return nil
}

func cmdUpdateStatus(env *Env, args []string) error {
	fs := newFlagSet(env, "update status")
	f := addUpdateFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	o, _, err := updateOptions(env, f, false)
	if err != nil {
		return err
	}
	ctx := envContext14(env)
	w := env.Stdout
	if v, err := updater.RunVersion(ctx, o.Exe); err == nil {
		fmt.Fprintf(w, "Kurulu program: %s (sürüm %s)\n", o.Exe, v)
	} else {
		fmt.Fprintf(w, "Kurulu program: %s (sürüm okunamadı: %v)\n", o.Exe, err)
	}
	if v, err := updater.RunVersion(ctx, o.Exe+updater.PrevSuffix); err == nil {
		fmt.Fprintf(w, "Önceki program: %s (sürüm %s; 'openscale update rollback' ile dönülür)\n", o.Exe+updater.PrevSuffix, v)
	} else {
		fmt.Fprintln(w, "Önceki program: yok")
	}
	if root, _, err := updater.LoadRootKey(*f.rootKey); err == nil {
		switch v, ok, err := updater.CheckInstalled(o.StateDir, o.Exe, root, env.Now()); {
		case err != nil:
			fmt.Fprintf(w, "Bütünlük: SORUN (%v)\n", err)
		case ok:
			fmt.Fprintf(w, "Bütünlük: program imzalı %s sürümüyle aynı\n", v)
		default:
			fmt.Fprintln(w, "Bütünlük: kayıtlı imzalı manifesto yok")
		}
	}
	j, err := updater.ReadJournal(o.StateDir)
	if err != nil {
		return err
	}
	if j == nil {
		fmt.Fprintln(w, "Yarım kalan güncelleme: yok")
		return nil
	}
	fmt.Fprintf(w, "Yarım kalan güncelleme: %s -> %s, durum %s, başlangıç %s\n", j.From, j.To, j.State, j.Started.Local().Format("02.01.2006 15:04"))
	fmt.Fprintln(w, "Temizlemek ve önceki programa dönmek için: openscale update rollback")
	return nil
}
