package cli

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/openscale/openscale/internal/autoupdate"
	"github.com/openscale/openscale/internal/updater"
	"github.com/openscale/openscale/internal/version"
)

// Automatic updates from the coordinator's mirror (ADR-0225).

func init() {
	registerCommands(
		command{"update auto on", "Otomatik güncellemeyi açar (varsayılan açık; yönetici/root)", cmdUpdateAutoOn},
		command{"update auto off", "Otomatik güncellemeyi kapatır (yönetici/root)", cmdUpdateAutoOff},
		command{"update auto status", "Otomatik güncelleme durumu: açık/kapalı, son denetim, kurulu ve en yeni sürüm, bekleme nedeni", cmdUpdateAutoStatus},
		command{"update auto install", "Cihazın indirip doğruladığı sürümü yeniden doğrulayıp kurar (servis/systemd başlatır; yönetici/root)", cmdUpdateAutoInstall},
		command{"update publish", "İmzalı sürümü doğrulayıp koordinatörün aynasına koyar; cihazlar tünel içinden alır: --dir <dist/sürüm>", cmdUpdatePublish},
		command{"update source set", "Koordinatörün sürümleri izleyeceği GitHub deposu: " + autoupdate.SourceFormat() + " (varsayılan kapalı)", cmdUpdateSourceSet},
		command{"update source off", "Yukarı akış kaynağını kapatır", cmdUpdateSourceOff},
		command{"update source status", "Yukarı akış kaynağı, son denetim ve sonucu", cmdUpdateSourceStatus},
		command{"update source sync", "Kaynağı denetler; yeni ve doğrulanan sürümü aynaya koyar (zamanlayıcı çalıştırır)", cmdUpdateSourceSync},
	)
}

func setAutoUpdate(env *Env, args []string, name string, on bool) error {
	fs := newFlagSet(env, name)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	p := autoupdate.DefaultPaths()
	if !p.Supported {
		return errors.New(p.Reason)
	}
	if err := updater.RequirePrivileges(); err != nil {
		return err
	}
	if err := autoupdate.WriteSettings(p.Settings, on); err != nil {
		return err
	}
	if on {
		fmt.Fprintln(env.Stdout, "Otomatik güncelleme açık: cihaz koordinatörün ilan ettiği imzalı sürümü doğrulayıp rastgele bir gecikmeyle kurar.")
	} else {
		fmt.Fprintln(env.Stdout, "Otomatik güncelleme kapalı.")
	}
	return nil
}

func cmdUpdateAutoOn(env *Env, args []string) error {
	return setAutoUpdate(env, args, "update auto on", true)
}

func cmdUpdateAutoOff(env *Env, args []string) error {
	return setAutoUpdate(env, args, "update auto off", false)
}

func cmdUpdateAutoStatus(env *Env, args []string) error {
	fs := newFlagSet(env, "update auto status")
	asJSON := fs.Bool("json", false, "JSON çıktı")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	p := autoupdate.DefaultPaths()
	st := autoupdate.New(autoupdate.Config{Paths: p, Installed: version.Version}).Status()
	// The device process saves what it learnt from the coordinator; this
	// device's switch and key are always read fresh.
	if saved, err := autoupdate.ReadStatus(p.Work); err == nil && st.Enabled && (st.State == autoupdate.StatePending || st.State == autoupdate.StateWaitingKey) {
		saved.Current, saved.Enabled = st.Current, st.Enabled
		st = saved
	}
	if *asJSON {
		return printJSON(env.Stdout, st)
	}
	printAutoStatus(env.Stdout, st)
	return nil
}

func printAutoStatus(w io.Writer, st autoupdate.Status) {
	onOff := "kapalı"
	if st.Enabled {
		onOff = "açık"
	}
	fmt.Fprintf(w, "Otomatik güncelleme: %s\n", onOff)
	fmt.Fprintf(w, "Durum: %s\n", st.Message)
	if st.Action != "" {
		fmt.Fprintf(w, "Yapılacak: %s\n", st.Action)
	}
	fmt.Fprintf(w, "Kurulu sürüm: %s (kanal %s)\n", st.Current, st.Channel)
	if st.Latest != "" {
		v := "doğrulanmadı"
		if st.LatestVerified {
			v = "imzası doğrulandı"
		}
		fmt.Fprintf(w, "Koordinatördeki en yeni sürüm: %s (%s)\n", st.Latest, v)
	}
	if st.Source != "" {
		at := "henüz denetlenmedi"
		if !st.SourceChecked.IsZero() {
			at = "son denetim " + st.SourceChecked.Local().Format("02.01.2006 15:04")
		}
		fmt.Fprintf(w, "Koordinatörün kaynağı: %s (%s)\n", st.Source, at)
	}
	if !st.LastCheck.IsZero() {
		fmt.Fprintf(w, "Son denetim: %s\n", st.LastCheck.Local().Format("02.01.2006 15:04"))
	}
	if !st.ScheduledAt.IsZero() {
		fmt.Fprintf(w, "Planlanan kurulum: %s\n", st.ScheduledAt.Local().Format("02.01.2006 15:04"))
	}
	if a := st.LastAttempt; a != nil {
		res := "başarılı"
		if !a.OK {
			res = "başarısız"
			if a.RolledBack {
				res += ", önceki sürüme dönüldü"
			}
		}
		fmt.Fprintf(w, "Son kurulum: %s %s (%s) %s\n", a.Version, a.At.Local().Format("02.01.2006 15:04"), res, a.Message)
	}
}

func cmdUpdateAutoInstall(env *Env, args []string) error {
	fs := newFlagSet(env, "update auto install")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	res, err := autoupdate.Install(envContext14(env), autoupdate.InstallOptions{
		Paths: autoupdate.DefaultPaths(),
		Logf:  func(format string, a ...any) { fmt.Fprintf(env.Stdout, format+"\n", a...) },
	})
	if errors.Is(err, autoupdate.ErrNoRequest) {
		fmt.Fprintln(env.Stdout, "Bekleyen otomatik güncelleme yok.")
		return nil
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Güncellendi: %s -> %s.\n", res.From, res.To)
	return nil
}

func cmdUpdatePublish(env *Env, args []string) error {
	fs := newFlagSet(env, "update publish")
	dir := fs.String("dir", "", "sürüm betiğinin çıktı klasörü: dist/<sürüm> (zorunlu)")
	stateDir := fs.String("state-dir", autoupdate.DefaultCoordinatorStateDir(), "koordinatörün durum klasörü")
	rootKey := fs.String("root-key", "", "sürüm kök açık anahtarı (varsayılan: gömülü, sonra "+updater.DefaultRootKeyFile()+")")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *dir == "" {
		return usageError("--dir zorunlu")
	}
	root, where, err := updater.LoadRootKey(*rootKey)
	if err != nil {
		return fmt.Errorf("%w; imzasız sürüm yayımlanmaz (docs/otomatik-guncelleme.md)", err)
	}
	fmt.Fprintf(env.Stdout, "Sürüm kök anahtarı (%s): %s\n", where, root.Fingerprint())
	res, err := autoupdate.Publish(autoupdate.PublishOptions{
		Dist: *dir, StateDir: *stateDir, Root: root, Now: env.Now,
		Logf: func(format string, a ...any) { fmt.Fprintf(env.Stdout, format+"\n", a...) },
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Yayımlandı: %s (%d dosya) -> %s\n", res.Version, len(res.Files), res.Mirror)
	fmt.Fprintln(env.Stdout, "Koordinatör bir dakika içinde ilan eder; otomatik güncellemesi açık cihazlar 0-30 dakika arası rastgele bir gecikmeyle kurar.")
	fmt.Fprintf(env.Stdout, "Bu sunucunun kendi programı için: openscale update apply %s\n", *dir)
	return nil
}

func cmdUpdateSourceSet(env *Env, args []string) error {
	fs := newFlagSet(env, "update source set")
	stateDir := fs.String("state-dir", autoupdate.DefaultCoordinatorStateDir(), "koordinatörün durum klasörü")
	every := fs.Duration("every", autoupdate.DefaultSourceEvery, "kontrol aralığı (1h-168h)")
	stable := fs.Bool("stable-only", false, "önsürümleri (beta) aynaya almaz")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usageError("tek argüman: %s", autoupdate.SourceFormat())
	}
	owner, repo, err := autoupdate.ParseSourceURL(fs.Arg(0))
	if err != nil {
		return usageError("%v", err)
	}
	if *every < autoupdate.MinSourceEvery || *every > autoupdate.MaxSourceEvery {
		return usageError("--every %s ile %s arasında olmalı", autoupdate.MinSourceEvery, autoupdate.MaxSourceEvery)
	}
	c := &autoupdate.SourceConfig{Owner: owner, Repo: repo, Every: autoupdate.Duration(*every), Beta: !*stable}
	if err := autoupdate.WriteSource(*stateDir, c); err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Yukarı akış kaynağı: %s (her %s). Yalnızca bu sunucu bağlanır; cihazlar sürümü koordinatörden tünel içinden alır.\n", c.Name(), *every)
	fmt.Fprintln(env.Stdout, "İmzası bu sunucuda doğrulanmayan sürüm aynaya alınmaz.")
	fmt.Fprintln(env.Stdout, "Linux'ta zamanlayıcıyı açın: systemctl enable --now openscale-release-sync.timer  (hemen denemek için: openscale update source sync --force)")
	return nil
}

func cmdUpdateSourceOff(env *Env, args []string) error {
	fs := newFlagSet(env, "update source off")
	stateDir := fs.String("state-dir", autoupdate.DefaultCoordinatorStateDir(), "koordinatörün durum klasörü")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := autoupdate.WriteSource(*stateDir, nil); err != nil {
		return err
	}
	fmt.Fprintln(env.Stdout, "Yukarı akış kaynağı kapalı; aynadaki sürüm yerinde kalır (yeni sürümü elle: openscale update publish).")
	return nil
}

func cmdUpdateSourceStatus(env *Env, args []string) error {
	fs := newFlagSet(env, "update source status")
	stateDir := fs.String("state-dir", autoupdate.DefaultCoordinatorStateDir(), "koordinatörün durum klasörü")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	c, err := autoupdate.ReadSource(*stateDir)
	if err != nil {
		return err
	}
	if c == nil {
		fmt.Fprintln(env.Stdout, "Yukarı akış kaynağı: kapalı (sürümler elle yayımlanır: openscale update publish)")
		return nil
	}
	beta := "önsürümler dahil"
	if !c.Beta {
		beta = "yalnızca kararlı"
	}
	fmt.Fprintf(env.Stdout, "Yukarı akış kaynağı: %s (her %s, %s)\n", c.Name(), time.Duration(c.Every), beta)
	st, err := autoupdate.ReadSourceStatus(*stateDir)
	if err != nil {
		fmt.Fprintln(env.Stdout, "Son denetim: henüz yok")
		return nil
	}
	fmt.Fprintf(env.Stdout, "Son denetim: %s", st.LastCheck.Local().Format("02.01.2006 15:04"))
	if st.Version != "" {
		fmt.Fprintf(env.Stdout, ", en yeni sürüm %s", st.Version)
	}
	fmt.Fprintln(env.Stdout)
	if st.Error != "" {
		fmt.Fprintf(env.Stdout, "Son hata: %s\n", st.Error)
	}
	return nil
}

func cmdUpdateSourceSync(env *Env, args []string) error {
	fs := newFlagSet(env, "update source sync")
	stateDir := fs.String("state-dir", autoupdate.DefaultCoordinatorStateDir(), "koordinatörün durum klasörü")
	force := fs.Bool("force", false, "kontrol aralığını beklemeden denetle")
	rootKey := fs.String("root-key", "", "sürüm kök açık anahtarı (varsayılan: gömülü, sonra "+updater.DefaultRootKeyFile()+")")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	// Without a key the sync records the error and mirrors nothing.
	root, _, _ := updater.LoadRootKey(*rootKey)
	res, err := autoupdate.SyncSource(envContext14(env), autoupdate.SyncOptions{
		StateDir: *stateDir, Root: root, Force: *force, Now: env.Now,
		Logf: func(format string, a ...any) { fmt.Fprintf(env.Stdout, format+"\n", a...) },
	})
	if err != nil {
		return err
	}
	switch {
	case res.Skipped:
		fmt.Fprintln(env.Stdout, "Kontrol aralığı dolmadı; denetlenmedi (--force ile hemen).")
	case res.Published:
		fmt.Fprintf(env.Stdout, "Kaynaktaki %s doğrulandı ve aynaya kondu.\n", res.Version)
	default:
		fmt.Fprintf(env.Stdout, "Ayna güncel (%s).\n", res.Version)
	}
	return nil
}
