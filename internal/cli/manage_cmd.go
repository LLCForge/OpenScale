package cli

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"

	"github.com/openscale/openscale/internal/service"
)

// Management commands of P02/P06: shell completion (#227), "config
// validate" (#235) and crash cleanup (#163).

func p06Commands() []command {
	return append(serviceCommands(),
		command{"config validate", "Ayar dosyalarını ve izinleri çalıştırmadan doğrular ('configtest' ile aynı)", cmdConfigtest},
		command{"completion", "Kabuk tamamlama betiği yazar: bash, zsh, fish veya powershell", cmdCompletion},
		command{"cleanup", "Çökme sonrası kalan DNS ve rota değişikliklerini geri alır (tünel kapalıyken)", cmdCleanup},
	)
}

// recoverUpChanges undoes what a crashed "openscale up" left in dir.
func recoverUpChanges(env *Env, j *service.Journal, logger *slog.Logger) {
	done, err := j.Recover(envContext(env), service.SystemUndo, logger)
	if err != nil {
		fmt.Fprintf(env.Stderr, "uyarı: önceki çalışmadan kalan değişiklikler tam geri alınamadı: %v\n", err)
	}
	if len(done) > 0 {
		fmt.Fprintf(env.Stdout, "Önceki çalışmadan kalan değişiklikler geri alındı: %s\n", strings.Join(done, ", "))
	}
}

// journalBegin records a change; a failure is reported but does not stop
// the tunnel.
func journalBegin(env *Env, j *service.Journal, e service.JournalEntry) {
	if err := j.Begin(e); err != nil {
		fmt.Fprintf(env.Stderr, "uyarı: değişiklik günlüğü yazılamadı: %v\n", err)
	}
}

// cmdCleanup runs the crash recovery by hand, for example after the
// program was removed without stopping, or when a tunnel will not start.
func cmdCleanup(env *Env, args []string) error {
	fs := newFlagSet(env, "cleanup")
	stateDir := fs.String("state-dir", "", "ön plan tünelinin durum klasörü (varsayılan: kullanıcı yapılandırma klasörü)")
	dataDir := fs.String("data-dir", "", "servisin veri klasörü (varsayılan: %ProgramData%\\OpenScale, Windows)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if c, err := openLocalClient(env, *stateDir); err == nil && c != nil {
		return errors.New("bir OpenScale tüneli çalışıyor; çalışan tünel kendi değişikliklerini yönetir. Önce durdurun (servis: openscale service stop)")
	}
	var dirs []string
	if d := *dataDir; d != "" {
		dirs = append(dirs, d)
	} else if d := localAPI.dataDir(); d != "" {
		dirs = append(dirs, d)
	}
	if sd, err := resolveStateDir(env, *stateDir); err == nil {
		dirs = append(dirs, sd)
	}
	total := 0
	var errs []error
	for _, d := range slices.Compact(dirs) {
		if _, err := os.Stat(d); err != nil {
			continue
		}
		j := service.OpenJournal(d, env.Now)
		done, err := j.Recover(envContext(env), service.SystemUndo, nil)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", d, describeCleanupErr(err)))
		}
		for _, k := range done {
			fmt.Fprintf(env.Stdout, "Geri alındı: %s (%s)\n", journalKindName(k), d)
		}
		total += len(done)
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	if total == 0 {
		fmt.Fprintln(env.Stdout, "Geri alınacak bir değişiklik yok.")
	}
	return nil
}

func describeCleanupErr(err error) error {
	if errors.Is(err, os.ErrPermission) {
		return errors.New("izin yok; yönetici/root olarak çalıştırın")
	}
	return err
}

func journalKindName(kind string) string {
	switch kind {
	case service.JournalDNS:
		return "MagicDNS ve ağ DNS ayarları"
	case service.JournalExitClient:
		return "çıkış düğümü rotaları ve DNS"
	case service.JournalExitNAT:
		return "çıkış düğümü NAT kuralları"
	}
	return kind
}

// operatorGroup may use the local API of "openscale up" besides root and
// the tunnel's own user (F-097, ADR-0050).
const operatorGroup = "openscale"
