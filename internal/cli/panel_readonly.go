package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/openscale/openscale/internal/service"
	"github.com/openscale/openscale/internal/winapp"
)

// panelReadOnlyOps are the side effects of "panel readonly"; tests replace
// them.
type panelReadOnlyOps struct {
	dataDir  func() string
	elevated func() bool
	set      func(dataDir string, on bool) error
	get      func(dataDir string) bool
}

var panelReadOnly = panelReadOnlyOps{
	dataDir:  winapp.DataDir,
	elevated: winapp.IsElevated,
	set:      service.SetPanelReadOnly,
	get:      service.PanelReadOnly,
}

// cmdPanelReadOnly switches the desktop panel's read-only mode (F-180).
// Turning it off is possible only here, never from the panel itself.
func cmdPanelReadOnly(env *Env, args []string) error {
	flags := newFlagSet(env, "panel readonly")
	dataDir := flags.String("data-dir", "", "servisin veri klasörü (varsayılan: %ProgramData%\\OpenScale)")
	flags.Usage = func() {
		fmt.Fprintln(env.Stderr, "Kullanım: openscale panel readonly on|off|status [--data-dir klasör]")
		flags.PrintDefaults()
	}
	// The choice comes first; flags may follow it.
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		if err := parseFlags(flags, args); err != nil {
			return err
		}
		return usageError("on, off veya status yazın: openscale panel readonly on|off|status")
	}
	mode := args[0]
	if err := parseFlags(flags, args[1:]); err != nil {
		return err
	}
	dir := *dataDir
	if dir == "" {
		dir = panelReadOnly.dataDir()
	}
	if dir == "" {
		return errors.New("salt okunur panel yalnızca masaüstü servisinde var (Windows); --data-dir ile klasörü belirtin")
	}
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		if err == nil || errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("servisin veri klasörü bulunamadı: %s", dir)
		}
		return err
	}
	w := env.Stdout
	switch mode {
	case "status":
		if panelReadOnly.get(dir) {
			fmt.Fprintln(w, "Panel salt okunur: paneldeki değişiklikler reddediliyor.")
		} else {
			fmt.Fprintln(w, "Panel salt okunur değil.")
		}
		return nil
	case "on", "off":
		on := mode == "on"
		if *dataDir == "" && !panelReadOnly.elevated() {
			return errors.New("bu ayar için komutu yönetici olarak çalıştırın (Yönetici: Komut İstemi veya PowerShell)")
		}
		if err := panelReadOnly.set(dir, on); err != nil {
			if errors.Is(err, fs.ErrPermission) {
				return fmt.Errorf("veri klasörüne yazılamadı; komutu yönetici olarak çalıştırın: %w", err)
			}
			return err
		}
		if on {
			fmt.Fprintln(w, "Panel artık salt okunur: değiştiren bütün işlemler reddedilir ve düğmeler gizlenir.")
			fmt.Fprintln(w, "Tepsi menüsü (bağlan/kes, çıkış düğümü) çalışmaya devam eder. Kapatmak için: openscale panel readonly off")
		} else {
			fmt.Fprintln(w, "Panel yeniden değişikliklere açık.")
		}
		return nil
	default:
		return usageError("bilinmeyen seçim %q; on, off veya status yazın", mode)
	}
}
