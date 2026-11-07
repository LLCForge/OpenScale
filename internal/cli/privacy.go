package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/openscale/openscale/internal/desktop"
	"github.com/openscale/openscale/internal/privacy"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/winapp"
)

// privacyCommands are the privacy commands of ADR-0008 (#50, #52).
func privacyCommands() []command {
	return []command{
		{"privacy report", "Gizlilik raporu: hangi veri nerede, koordinatör neyi görür, son bağlantılar, riskli ayarlar (yalnızca yerel)", cmdPrivacyReport},
		{"privacy-check", "Gizlilik raporunun kısa adı", cmdPrivacyReport},
		{"uninstall", "OpenScale'i kaldırır; --purge anahtarları, ayarları ve günlükleri üzerine yazarak siler", cmdUninstall},
	}
}

// maskedJSONLogger is the JSON logger of the commands: Info and above
// never carry IP addresses and no level carries keys (#42).
func maskedJSONLogger(w io.Writer, level slog.Leveler) *slog.Logger {
	return privacy.NewMaskedLogger(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level}))
}

// linuxDataDirs are the state directories of the systemd units in
// deploy/linux.
var linuxDataDirs = []string{"/var/lib/openscale/device", "/var/lib/openscale/coordinator"}

// knownDataDirs returns the data directories of this computer; tests
// replace it.
var knownDataDirs = func(env *Env) []privacy.DataDir {
	var dirs []privacy.DataDir
	if runtime.GOOS == "windows" {
		dirs = append(dirs, privacy.DataDir{Path: winapp.DataDir(), Kind: "servis"})
	} else {
		for _, d := range linuxDataDirs {
			dirs = append(dirs, privacy.DataDir{Path: d, Kind: "servis"})
		}
	}
	if d, err := env.DefaultStateDir(); err == nil && d != "" {
		dirs = append(dirs, privacy.DataDir{Path: d, Kind: "cli"})
	}
	return dirs
}

// uninstallSystem removes the service, the kill switch and the firewall
// rules (Windows); tests replace it so nothing on the computer changes.
var uninstallSystem = desktop.Uninstall

// processHardening is the crash dump status of this process, filled in by
// main through SetProcessHardening.
var processHardening privacy.HardeningStatus

// SetProcessHardening records what main did against crash dumps, for the
// privacy report.
func SetProcessHardening(st privacy.HardeningStatus) { processHardening = st }

// stringList is a repeatable string flag.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	if strings.TrimSpace(v) == "" {
		return errors.New("boş değer")
	}
	*s = append(*s, v)
	return nil
}

func cmdPrivacyReport(env *Env, args []string) error {
	fs := newFlagSet(env, "privacy report")
	var extra stringList
	fs.Var(&extra, "state-dir", "ayrıca incelenecek durum klasörü (tekrarlanabilir)")
	asJSON := fs.Bool("json", false, "JSON çıktı")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	dirs := knownDataDirs(env)
	for _, d := range extra {
		dirs = append(dirs, privacy.DataDir{Path: d, Kind: "cli"})
	}
	host := ""
	if env.Hostname != nil {
		host, _ = env.Hostname()
	}
	r := privacy.BuildReport(privacy.ReportOptions{
		Dirs:       dedupeDirs(dirs),
		Now:        env.Now(),
		OSHostname: host,
		Hardening:  processHardening,
	})
	if *asJSON {
		return r.WriteJSON(env.Stdout)
	}
	return r.WriteText(env.Stdout)
}

func dedupeDirs(in []privacy.DataDir) []privacy.DataDir {
	seen := map[string]bool{}
	var out []privacy.DataDir
	for _, d := range in {
		abs, err := filepath.Abs(d.Path)
		if err != nil {
			continue
		}
		key := abs
		if runtime.GOOS == "windows" {
			key = strings.ToLower(abs)
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, privacy.DataDir{Path: abs, Kind: d.Kind})
	}
	return out
}

const purgeConfirmWord = "SİL"

func cmdUninstall(env *Env, args []string) error {
	flags := newFlagSet(env, "uninstall")
	purge := flags.Bool("purge", false, "anahtarları, ağ belgesini, ayarları ve günlükleri üzerine yazarak sil")
	var extra stringList
	flags.Var(&extra, "state-dir", "--purge ile ayrıca silinecek durum klasörü (tekrarlanabilir)")
	rootKey := flags.Bool("include-root-key", false, "ağın kök anahtarını da sil (yedeği yoksa ağ kaybolur)")
	yes := flags.Bool("yes", false, "onay sormadan sil (betikler için)")
	dryRun := flags.Bool("dry-run", false, "yalnızca neyin silineceğini göster")
	if err := parseFlags(flags, args); err != nil {
		return err
	}
	if !*purge && len(extra) > 0 {
		return usageError("--state-dir yalnızca --purge ile kullanılır")
	}

	// Every directory is checked before anything changes, so a refusal
	// (root key, foreign folder) never leaves a half-removed installation.
	var targets []string
	if *purge {
		candidates := knownDataDirs(env)
		for _, d := range extra {
			candidates = append(candidates, privacy.DataDir{Path: d, Kind: "cli"})
		}
		for _, d := range dedupeDirs(candidates) {
			if _, err := os.Lstat(d.Path); errors.Is(err, fs.ErrNotExist) {
				continue
			}
			abs, err := privacy.CheckPurgeTarget(d.Path, *rootKey)
			switch {
			case errors.Is(err, privacy.ErrRootKeyPresent):
				return fmt.Errorf("%w; önce \"openscale network backup\" ile yedek alın, sonra --include-root-key ile tekrar deneyin", err)
			case err != nil:
				return err
			}
			targets = append(targets, abs)
		}
	}

	out := env.Stdout
	if *dryRun {
		fmt.Fprintln(out, "Deneme: hiçbir şey değiştirilmedi.")
		printUninstallPlan(out, targets, *purge)
		return nil
	}
	if *purge && len(targets) > 0 && !*yes {
		if !env.IsTerminal() {
			return usageError("onay için terminal yok; --yes verin")
		}
		printUninstallPlan(env.Stderr, targets, *purge)
		answer, err := env.ReadLine(fmt.Sprintf("Bu klasörler geri getirilemez biçimde silinecek. Onaylamak için %s yazın: ", purgeConfirmWord))
		if err != nil {
			return err
		}
		if a := strings.TrimSpace(answer); a != purgeConfirmWord && !strings.EqualFold(a, "SIL") {
			return errors.New("onaylanmadı; hiçbir şey silinmedi")
		}
	}

	if runtime.GOOS == "windows" {
		if err := uninstallSystem(); err != nil {
			return fmt.Errorf("servis kaldırılamadı, veri silinmedi: %w", err)
		}
		fmt.Fprintln(out, "Servis, kill switch filtreleri ve güvenlik duvarı kuralları kaldırıldı.")
	} else {
		// Only OpenScale's own units and nft tables are touched (#52).
		cctx := env.Ctx
		if cctx == nil {
			cctx = context.Background()
		}
		c, err := privacy.RunLinuxCleanup(cctx, privacy.LinuxCleanupOptions{})
		switch {
		case errors.Is(err, privacy.ErrNotRoot):
			fmt.Fprintln(out, "Servisleri ve filtreleri kaldırmak için root gerekir: sudo openscale uninstall")
		case err != nil:
			return fmt.Errorf("servisler ve filtreler kaldırılamadı, veri silinmedi: %w", err)
		default:
			fmt.Fprintf(out, "Kapatılan birimler: %d, silinen nft tabloları: %d\n", len(c.Units), len(c.Tables))
		}
	}
	if !*purge {
		fmt.Fprintln(out, "Anahtarlar ve ağ verisi yerinde duruyor; silmek için: openscale uninstall --purge")
		return nil
	}
	if len(targets) == 0 {
		fmt.Fprintln(out, "Silinecek OpenScale veri klasörü bulunamadı.")
		return nil
	}
	var errs []error
	for _, dir := range targets {
		res, err := privacy.Purge(dir, privacy.PurgeOptions{AllowRootKey: *rootKey, Random: env.Random})
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", dir, err))
		}
		fmt.Fprintf(out, "Silindi: %s (%d dosya, %d üzerine yazıldı, %d bayt)\n", dir, res.Files, res.Overwritten, res.Bytes)
		for _, n := range res.NotOverwritten {
			fmt.Fprintf(out, "  yalnızca silindi (bağlantı veya büyük dosya): %s\n", n)
		}
	}
	fmt.Fprintln(out, "Not: SSD ve flash bellekte, ayrıca kopyala-yaz dosya sistemlerinde eski bloklar fiziksel olarak kalabilir; "+
		"tam koruma için disk şifrelemesi (BitLocker, LUKS, FileVault) kullanın.")
	return errors.Join(errs...)
}

func printUninstallPlan(w io.Writer, targets []string, purge bool) {
	if runtime.GOOS == "windows" {
		fmt.Fprintln(w, "Kaldırılacak: OpenScale servisi, kill switch filtreleri, güvenlik duvarı kuralları")
	}
	if !purge {
		return
	}
	if len(targets) == 0 {
		fmt.Fprintln(w, "Silinecek veri klasörü yok.")
		return
	}
	fmt.Fprintln(w, "Üzerine yazılıp silinecek klasörler:")
	for _, t := range targets {
		fmt.Fprintf(w, "  %s\n", t)
	}
}

// removeStaleTemps deletes temporary files a crash left in a state
// directory before the long-running commands start (#46).
func removeStaleTemps(env *Env, dir string, logger *slog.Logger) {
	n, err := securefile.RemoveStaleTemps(dir, env.Now())
	switch {
	case err != nil:
		logger.Warn("stale temporary files", "error", err.Error())
	case n > 0:
		logger.Info("stale temporary files removed", "count", n)
	}
}
