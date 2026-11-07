package cli

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/openscale/openscale/internal/coordinator"
)

// Coordinator transport disguise wiring (ADR-0186): "coordinator run" and
// the desktop service read obfs-coordinator.json from the coordinator's
// state directory; "coordinator obfs-config" writes it.

func init() { registerCommands(wireCoordObfsCommands()...) }

func wireCoordObfsCommands() []command {
	return []command{
		{"coordinator obfs-config", "Koordinatörde trafik gizlemeyi ayarlar (açılışta okunur): --state-dir KLASÖR --mode off|auto [--tls-listen :443 --name AD] [--tls-off]", cmdCoordinatorObfsConfig},
	}
}

func cmdCoordinatorObfsConfig(env *Env, args []string) error {
	fs := newFlagSet(env, "coordinator obfs-config")
	stateDir := fs.String("state-dir", "", "koordinatörün durum klasörü (zorunlu)")
	mode := fs.String("mode", "", "off veya auto (boş: değiştirme)")
	tlsListen := fs.String("tls-listen", "", "TLS taklidi dinleme adresi, ör. :443 (--tcp-listen de açık olmalı)")
	tlsOff := fs.Bool("tls-off", false, "TLS taklidini kapat")
	var names g3ListFlag
	fs.Var(&names, "name", "yeni sertifikadaki ad (tekrarlanabilir)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *stateDir == "" {
		return usageError("--state-dir zorunlu")
	}
	if *tlsOff && *tlsListen != "" {
		return usageError("--tls-listen ve --tls-off birlikte kullanılamaz")
	}
	f, err := coordinator.LoadObfsFile(*stateDir)
	if err != nil {
		return err
	}
	if m := strings.TrimSpace(*mode); m != "" {
		f.Mode = m
	}
	switch {
	case *tlsOff:
		f.TLSListen, f.Names = "", nil
	case *tlsListen != "":
		f.TLSListen = strings.TrimSpace(*tlsListen)
	}
	if len(names) > 0 {
		f.Names = names
	}
	if err := coordinator.SaveObfsFile(*stateDir, f); err != nil {
		return usageError("%v", err)
	}
	printCoordObfs(env, f)
	fmt.Fprintln(env.Stdout, "Değişiklik koordinatör yeniden başlatılınca geçerli olur.")
	return nil
}

func printCoordObfs(env *Env, f coordinator.ObfsFile) {
	mode := f.Mode
	if mode == "" {
		mode = "off"
	}
	tls := "kapalı"
	if f.TLSListen != "" {
		tls = f.TLSListen
	}
	fmt.Fprintf(env.Stdout, "Koordinatör gizleme kipi: %s, TLS taklidi: %s\n", mode, tls)
}

// startCoordinatorObfs applies the saved disguise to cfg before
// coordinator.New. The returned runtime is nil when it is off.
func startCoordinatorObfs(env *Env, cfg *coordinator.Config, stateDir string) (*coordinator.ObfsRuntime, error) {
	f, err := coordinator.LoadObfsFile(stateDir)
	if err != nil {
		return nil, fmt.Errorf("koordinatör gizleme ayarı: %w", err)
	}
	rt, err := coordinator.ApplyObfs(cfg, stateDir, f, env.Now())
	if err != nil {
		return nil, fmt.Errorf("koordinatör gizleme başlatılamadı: %w", err)
	}
	if rt != nil {
		printCoordObfs(env, f)
		if a := rt.Addr(); a != nil {
			fmt.Fprintf(env.Stdout, "TLS taklidi %s üzerinde; cihazlar için sabitleme: %s\n", a, rt.Pin)
		}
	}
	return rt, nil
}

// obfsServeErr logs a failed TLS listener without stopping the coordinator.
func obfsServeErr(logger *slog.Logger) func(error) {
	return func(err error) { logger.Warn("TLS camouflage listener stopped", "error", err.Error()) }
}
