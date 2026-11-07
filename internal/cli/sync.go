package cli

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/syncdir"
)

// --- sync (ADR-0104: #134, #135, #136, #137) ---

type syncSub struct {
	name    string
	summary string
	run     func(*Env, []string) error
}

func syncSubcommands() []syncSub {
	return []syncSub{
		{"serve", "Klasörleri salt okunur paylaşır ve/veya şifreli yedek hedefi olur (ön planda)", cmdSyncServe},
		{"pull", "Bir cihazın paylaştığı klasördeki değişiklikleri buraya çeker", cmdSyncPull},
		{"versions", "Eşitlemenin sakladığı eski dosya sürümlerini listeler", cmdSyncVersions},
		{"backup", "Klasörü kaynakta şifreleyip bir cihaza yedekler", cmdSyncBackup},
		{"snapshots", "Hedefteki yedekleri listeler", cmdSyncSnapshots},
		{"restore", "Bir yedeği boş bir klasöre geri yükler", cmdSyncRestore},
		{"prune", "Son N yedek dışındakileri hedeften siler (hedef izin vermeli)", cmdSyncPrune},
		{"key", "Yedek anahtarı: init | show | export | import", cmdSyncKey},
	}
}

func cmdSync(env *Env, args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprintln(env.Stdout, "Kullanım: openscale sync <alt komut> [seçenekler]\n\nAlt komutlar:")
		for _, c := range syncSubcommands() {
			fmt.Fprintf(env.Stdout, "  %-10s %s\n", c.name, c.summary)
		}
		if len(args) == 0 {
			return usageError("alt komut gerekli")
		}
		return nil
	}
	for _, c := range syncSubcommands() {
		if c.name == args[0] {
			return c.run(env, args[1:])
		}
	}
	return usageError("bilinmeyen alt komut %q", args[0])
}

type syncList []string

func (l *syncList) String() string { return strings.Join(*l, ",") }
func (l *syncList) Set(v string) error {
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			*l = append(*l, s)
		}
	}
	return nil
}

func parseSyncSize(s string) (int64, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	mult := int64(1)
	for _, u := range []struct {
		suffix string
		m      int64
	}{{"TIB", 1 << 40}, {"GIB", 1 << 30}, {"MIB", 1 << 20}, {"TB", 1 << 40}, {"GB", 1 << 30}, {"MB", 1 << 20}} {
		if strings.HasSuffix(s, u.suffix) {
			s, mult = strings.TrimSuffix(s, u.suffix), u.m
			break
		}
	}
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || n <= 0 || n > (1<<62)/mult {
		return 0, usageError("geçersiz boyut %q (ör. 50GiB)", s)
	}
	return n * mult, nil
}

// syncTarget resolves a device to its sync service address.
func syncTarget(env *Env, rf remoteFlags, target string) (string, netip.AddrPort, error) {
	rc := loadRemoteContext(env, rf)
	name, addr, err := rc.resolveTarget(envContext(env), target)
	if err != nil {
		return "", netip.AddrPort{}, err
	}
	if name == "" {
		name = addr.String()
	}
	return name, netip.AddrPortFrom(addr, syncdir.DefaultPort), nil
}

func cmdSyncServe(env *Env, args []string) error {
	fs := newFlagSet(env, "sync serve")
	rf := addRemoteFlags(fs)
	var folders, allow, backupAllow syncList
	fs.Var(&folders, "folder", "paylaşılacak klasör: kimlik=yol (birden çok kez verilebilir)")
	fs.Var(&allow, "allow", "klasörleri okuyabilecek cihazlar (virgülle)")
	backupDir := fs.String("backup-dir", "", "diğer cihazların şifreli yedeklerinin tutulacağı klasör (boş: yedek hedefi kapalı)")
	fs.Var(&backupAllow, "backup-allow", "buraya yedek gönderebilecek cihazlar (virgülle)")
	quota := fs.String("quota", "50GiB", "yedek gönderen cihaz başına kota")
	allowPrune := fs.Bool("allow-prune", false, "kaynakların eski yedeklerini silmesine izin ver (varsayılan: yalnızca ekleme)")
	fs.Usage = func() {
		fmt.Fprintln(env.Stderr, "Kullanım: openscale sync serve --folder kimlik=yol --allow cihaz [--backup-dir klasör --backup-allow cihaz]")
		fmt.Fprintln(env.Stderr, "Yalnızca bu cihazın tünel adresinde, ön planda dinler; Ctrl+C ile durur. Paylaşılan klasörler salt okunurdur.")
		fs.PrintDefaults()
	}
	if err := parseFlagsWithArgs(fs, args, 0); err != nil {
		return err
	}
	if len(folders) == 0 && *backupDir == "" {
		return usageError("en az bir --folder veya --backup-dir gerekli")
	}
	q, err := parseSyncSize(*quota)
	if err != nil {
		return err
	}
	rc := loadRemoteContext(env, rf)
	if rc.doc == nil || rc.self == "" {
		return errors.New("ağ belgesi veya bu cihazın tünel adresi bulunamadı; tünel açıkken ve gerekirse yönetici olarak çalıştırın")
	}
	self, ok := rc.doc.DeviceByName(rc.self)
	if !ok || !self.IPv4.IsValid() {
		return errors.New("bu cihazın tünel adresi belgede yok")
	}
	for _, n := range append(slices.Clone(allow), backupAllow...) {
		if _, ok := rc.doc.DeviceByName(strings.ToLower(n)); !ok {
			return usageError("%s", withSuggestionText(deviceNotFound(rc.doc, n))) // #798
		}
	}
	shared := map[string]*syncdir.Folder{}
	var ids []string
	for _, spec := range folders {
		id, dir, ok := strings.Cut(spec, "=")
		if !ok || dir == "" {
			return usageError("--folder kimlik=yol biçiminde olmalı")
		}
		f, err := syncdir.OpenFolder(syncdir.FolderConfig{ID: id, Path: dir, Mode: syncdir.SendOnly})
		if err != nil {
			return err
		}
		defer f.Close()
		shared[id] = f
		ids = append(ids, id)
	}
	cfg := syncdir.ServerConfig{
		ListenAddr: netip.AddrPortFrom(self.IPv4, syncdir.DefaultPort),
		Folder:     func(id string) *syncdir.Folder { return shared[id] },
		BackupDir:  *backupDir,
		Authorize: func(remote netip.Addr) syncdir.Access {
			d, ok := rc.doc.DeviceByAddr(remote)
			if !ok {
				return syncdir.Access{}
			}
			acc := syncdir.Access{Peer: d.Name}
			if slices.ContainsFunc(allow, func(s string) bool { return strings.EqualFold(s, d.Name) }) {
				acc.Folders = ids
			}
			if slices.ContainsFunc(backupAllow, func(s string) bool { return strings.EqualFold(s, d.Name) }) {
				acc.Backup, acc.Quota, acc.AllowPrune = true, q, *allowPrune
			}
			return acc
		},
	}
	srv, err := syncdir.NewServer(cfg)
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Eşitleme servisi %s adresinde dinliyor (yalnızca tünel). Durdurmak için Ctrl+C.\n", cfg.ListenAddr)
	return srv.ListenAndServe(envContext(env))
}

func addFolderFlags(fs interface {
	String(string, string, string) *string
	Bool(string, bool, string) *bool
	Int(string, int, string) *int
}) (id, mode *string, del *bool, versions *int) {
	id = fs.String("id", "", "klasörün cihazlar arasındaki kimliği (küçük harf, rakam, tire)")
	mode = fs.String("mode", string(syncdir.SendReceive), "sendreceive (iki yönlü) veya receiveonly (yalnızca alır)")
	del = fs.Bool("delete", false, "karşı tarafta silinen dosyaları burada da sil (sürüm deposuna taşınır)")
	versions = fs.Int("versions", syncdir.DefaultVersions, "değişen/silinen her dosyanın saklanacak eski sürüm sayısı")
	return
}

func cmdSyncPull(env *Env, args []string) error {
	fs := newFlagSet(env, "sync pull")
	rf := addRemoteFlags(fs)
	id, mode, del, versions := addFolderFlags(fs)
	fs.Usage = func() {
		fmt.Fprintln(env.Stderr, "Kullanım: openscale sync pull <yerel-klasör> <cihaz> --id kimlik [--mode receiveonly] [--delete]")
		fs.PrintDefaults()
	}
	if err := parseFlagsWithArgs(fs, args, 2); err != nil {
		return err
	}
	m := syncdir.FolderMode(*mode)
	if m != syncdir.SendReceive && m != syncdir.ReceiveOnly {
		return usageError("--mode sendreceive veya receiveonly olmalı")
	}
	if *versions < 0 {
		*versions = -1
	}
	f, err := syncdir.OpenFolder(syncdir.FolderConfig{ID: *id, Path: fs.Arg(0), Mode: m, PropagateDeletes: *del, Versions: *versions})
	if err != nil {
		return err
	}
	defer f.Close()
	name, addr, err := syncTarget(env, rf, fs.Arg(1))
	if err != nil {
		return err
	}
	ctx := envContext(env)
	c, err := syncdir.Dial(ctx, addr)
	if err != nil {
		return err
	}
	defer c.Close()
	res, err := f.Pull(ctx, name, c.Folder(*id))
	if err != nil {
		if errors.Is(err, syncdir.ErrDenied) {
			return fmt.Errorf("%s bu klasörü bu cihazla paylaşmıyor", name)
		}
		return err
	}
	fmt.Fprintf(env.Stdout, "%s: %d dosya alındı, %d silindi, %d çakışma (iki sürüm de saklandı).\n", name, res.Fetched, res.Deleted, res.Conflicts)
	for _, s := range res.Skipped {
		fmt.Fprintf(env.Stdout, "  atlandı: %s (%s)\n", s.Path, s.Reason)
	}
	for _, s := range res.Failed {
		fmt.Fprintf(env.Stdout, "  yapılamadı: %s (%s)\n", s.Path, s.Reason)
	}
	return nil
}

func cmdSyncVersions(env *Env, args []string) error {
	fs := newFlagSet(env, "sync versions")
	id := fs.String("id", "", "klasör kimliği")
	if err := parseFlagsWithArgs(fs, args, 1); err != nil {
		return err
	}
	f, err := syncdir.OpenFolder(syncdir.FolderConfig{ID: *id, Path: fs.Arg(0)})
	if err != nil {
		return err
	}
	defer f.Close()
	vs, err := f.Versions()
	if err != nil {
		return err
	}
	if len(vs) == 0 {
		fmt.Fprintln(env.Stdout, "Saklanan eski sürüm yok.")
	}
	for _, v := range vs {
		fmt.Fprintf(env.Stdout, "%s  %s  %s\n", v.Time.Local().Format("2006-01-02 15:04:05"), formatBytes(v.Size), v.Path)
	}
	return nil
}

type backupFlags struct {
	store   *string
	keyPath *string
}

func addBackupFlags(env *Env, fs interface {
	String(string, string, string) *string
}) backupFlags {
	def := ""
	if env.DefaultStateDir != nil {
		if d, err := env.DefaultStateDir(); err == nil {
			def = filepath.Join(d, "backup.key")
		}
	}
	return backupFlags{
		store:   fs.String("store", "", "hedefteki yedek deposunun adı (küçük harf, rakam, tire)"),
		keyPath: fs.String("key", def, "yedek anahtarı dosyası (yalnızca bu cihazda)"),
	}
}

func (b backupFlags) open(env *Env, target string, rf remoteFlags) (*syncdir.Client, *syncdir.RemoteStore, string, error) {
	if !syncdir.ValidID(*b.store) {
		return nil, nil, "", usageError("--store küçük harf, rakam ve tireden oluşmalı")
	}
	name, addr, err := syncTarget(env, rf, target)
	if err != nil {
		return nil, nil, "", err
	}
	c, err := syncdir.Dial(envContext(env), addr)
	if err != nil {
		return nil, nil, "", err
	}
	return c, c.Store(*b.store), name, nil
}

func (b backupFlags) key() (*syncdir.BackupKey, error) {
	if *b.keyPath == "" {
		return nil, usageError("--key gerekli")
	}
	k, err := syncdir.LoadBackupKey(*b.keyPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("yedek anahtarı yok: önce 'openscale sync key init --key %s'", *b.keyPath)
	}
	return k, err
}

func cmdSyncBackup(env *Env, args []string) error {
	fs := newFlagSet(env, "sync backup")
	rf := addRemoteFlags(fs)
	bf := addBackupFlags(env, fs)
	label := fs.String("label", "", "yedeğe eklenecek kısa açıklama (şifreli saklanır)")
	if err := parseFlagsWithArgs(fs, args, 2); err != nil {
		return err
	}
	if !syncdir.ValidID(*bf.store) {
		return usageError("--store küçük harf, rakam ve tireden oluşmalı")
	}
	k, err := bf.key()
	if err != nil {
		return err
	}
	f, err := syncdir.OpenFolder(syncdir.FolderConfig{ID: *bf.store, Path: fs.Arg(0), Mode: syncdir.SendOnly})
	if err != nil {
		return err
	}
	defer f.Close()
	c, store, name, err := bf.open(env, fs.Arg(1), rf)
	if err != nil {
		return err
	}
	defer c.Close()
	start := time.Now()
	res, err := syncdir.Snapshot(envContext(env), f, k, store, *label)
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "%s cihazına yedeklendi (%s): %d dosya, %d yeni (%s), %d değişmedi; %s.\n",
		name, res.Name, res.Files, res.Uploaded, formatBytes(res.UploadedBytes), res.Reused, time.Since(start).Round(time.Second))
	return nil
}

func cmdSyncSnapshots(env *Env, args []string) error {
	fs := newFlagSet(env, "sync snapshots")
	rf := addRemoteFlags(fs)
	bf := addBackupFlags(env, fs)
	if err := parseFlagsWithArgs(fs, args, 1); err != nil {
		return err
	}
	c, store, _, err := bf.open(env, fs.Arg(0), rf)
	if err != nil {
		return err
	}
	defer c.Close()
	names, err := syncdir.Snapshots(envContext(env), store)
	if err != nil {
		return err
	}
	if len(names) == 0 {
		fmt.Fprintln(env.Stdout, "Bu depoda yedek yok.")
	}
	for _, n := range names {
		t, _ := syncdir.SnapshotTime(n)
		fmt.Fprintf(env.Stdout, "%s  %s\n", t.Local().Format("2006-01-02 15:04:05"), n)
	}
	return nil
}

func cmdSyncRestore(env *Env, args []string) error {
	fs := newFlagSet(env, "sync restore")
	rf := addRemoteFlags(fs)
	bf := addBackupFlags(env, fs)
	snap := fs.String("snapshot", "", "geri yüklenecek yedek (varsayılan: en yenisi)")
	if err := parseFlagsWithArgs(fs, args, 2); err != nil {
		return err
	}
	k, err := bf.key()
	if err != nil {
		return err
	}
	c, store, _, err := bf.open(env, fs.Arg(0), rf)
	if err != nil {
		return err
	}
	defer c.Close()
	ctx := envContext(env)
	name := *snap
	if name == "" {
		names, err := syncdir.Snapshots(ctx, store)
		if err != nil {
			return err
		}
		if len(names) == 0 {
			return syncdir.ErrNoSnapshot
		}
		name = names[len(names)-1]
	}
	n, err := syncdir.Restore(ctx, k, store, name, fs.Arg(1))
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "%d dosya %s klasörüne geri yüklendi ve doğrulandı.\n", n, fs.Arg(1))
	return nil
}

func cmdSyncPrune(env *Env, args []string) error {
	fs := newFlagSet(env, "sync prune")
	rf := addRemoteFlags(fs)
	bf := addBackupFlags(env, fs)
	keep := fs.Int("keep", 10, "tutulacak en yeni yedek sayısı")
	if err := parseFlagsWithArgs(fs, args, 1); err != nil {
		return err
	}
	k, err := bf.key()
	if err != nil {
		return err
	}
	c, store, _, err := bf.open(env, fs.Arg(0), rf)
	if err != nil {
		return err
	}
	defer c.Close()
	m, b, err := syncdir.Prune(envContext(env), k, store, *keep)
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "%d eski yedek ve %d kullanılmayan nesne silindi.\n", m, b)
	return nil
}

func cmdSyncKey(env *Env, args []string) error {
	if len(args) == 0 {
		return usageError("alt komut gerekli: init | show | export | import")
	}
	fs := newFlagSet(env, "sync key "+args[0])
	bf := addBackupFlags(env, fs)
	if err := parseFlagsWithArgs(fs, args[1:], 0); err != nil {
		return err
	}
	if *bf.keyPath == "" {
		return usageError("--key gerekli")
	}
	switch args[0] {
	case "init":
		k, created, err := syncdir.LoadOrCreateBackupKey(*bf.keyPath)
		if err != nil {
			return err
		}
		if created {
			fmt.Fprintf(env.Stdout, "Yeni yedek anahtarı oluşturuldu: %s\nParmak izi: %s\n", *bf.keyPath, k.Fingerprint())
			fmt.Fprintln(env.Stdout, "Bu anahtar kök anahtardan bağımsızdır; kaybolursa yedekler açılamaz. Hemen 'openscale sync key export' ile parolalı bir kopyasını alın.")
		} else {
			fmt.Fprintf(env.Stdout, "Anahtar zaten var; parmak izi: %s\n", k.Fingerprint())
		}
		return nil
	case "show":
		k, err := bf.key()
		if err != nil {
			return err
		}
		fmt.Fprintf(env.Stdout, "Parmak izi: %s\n", k.Fingerprint())
		return nil
	case "export":
		k, err := bf.key()
		if err != nil {
			return err
		}
		pass, err := readNewPassphrase(env)
		if err != nil {
			return err
		}
		text, err := k.Export(pass)
		clear(pass)
		if err != nil {
			return err
		}
		fmt.Fprintln(env.Stdout, text)
		fmt.Fprintf(env.Stderr, "Parmak izi: %s. Bu satırı ve parolayı ayrı yerlerde saklayın.\n", k.Fingerprint())
		return nil
	case "import":
		if env.ReadLine == nil || env.ReadSecret == nil {
			return errors.New("bu komut etkileşimli terminal ister")
		}
		text, err := env.ReadLine("Dışa aktarılmış anahtar: ")
		if err != nil {
			return err
		}
		pass, err := env.ReadSecret("Parola: ")
		if err != nil {
			return err
		}
		k, err := syncdir.ImportBackupKey(text, pass)
		clear(pass)
		if err != nil {
			return err
		}
		if err := k.Save(*bf.keyPath); err != nil {
			return fmt.Errorf("anahtar kaydedilemedi (dosya varsa üzerine yazılmaz): %w", err)
		}
		fmt.Fprintf(env.Stdout, "Anahtar %s dosyasına kaydedildi; parmak izi: %s\n", *bf.keyPath, k.Fingerprint())
		return nil
	}
	return usageError("bilinmeyen alt komut %q", args[0])
}

func readNewPassphrase(env *Env) ([]byte, error) {
	if env.ReadSecret == nil {
		return nil, errors.New("bu komut etkileşimli terminal ister")
	}
	first, err := env.ReadSecret("Dışa aktarma parolası (en az 12 karakter): ")
	if err != nil {
		return nil, err
	}
	second, err := env.ReadSecret("Parola (tekrar): ")
	if err != nil {
		return nil, err
	}
	defer clear(second)
	if !bytes.Equal(first, second) {
		clear(first)
		return nil, errors.New("parolalar eşleşmiyor")
	}
	return first, nil
}
