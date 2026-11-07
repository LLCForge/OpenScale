package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/panel"
)

func cmdPanel(env *Env, args []string) error {
	fs := newFlagSet(env, "panel")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	port := fs.Int("port", 0, "dinlenecek port; 0 boş bir port seçer")
	webDir := fs.String("web-dir", "", "geliştirme: gömülü panel yerine bu klasördeki derlemeyi sun")
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
	cfg := panel.Config{
		Network: n,
		Logger:  maskedJSONLogger(env.Stderr, slog.LevelInfo),
		Now:     env.Now,
		Random:  env.Random,
	}
	if *webDir != "" {
		cfg.Files = os.DirFS(*webDir)
	}
	srv, err := panel.New(cfg)
	if err != nil {
		return err
	}
	ln, err := panel.Listen(*port)
	if err != nil {
		return fmt.Errorf("panel portu açılamadı: %w", err)
	}

	w := env.Stdout
	fmt.Fprintln(w, "OpenScale yönetim paneli çalışıyor. Yalnızca bu bilgisayardan erişilebilir.")
	fmt.Fprintln(w, "\nTarayıcıda aç ve kök anahtar parolanla giriş yap:")
	fmt.Fprintln(w, "  "+srv.URL(ln.Addr()))
	if !srv.Built() {
		fmt.Fprintln(w, "\nUYARI: bu ikiliye panel gömülmemiş; önce 'pnpm --dir panel build' çalıştır.")
	}
	fmt.Fprintln(w, "\nDurdurmak için Ctrl+C.")

	ctx := env.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	// Remote access over the tunnel (ADR-0107) opens only when it is on in
	// the network directory and a panel rule names this device.
	if st, err := panel.LoadRemoteSettings(*dir); err == nil && st.Ready() {
		fmt.Fprintln(w, "Uzaktan erişim açık: panel kuralı olan cihazlar tünel adresinden salt okunur bağlanabilir (openscale panel-remote status).")
	}
	go func() { _ = srv.ServeRemote(ctx, panel.RemoteConfig{}) }()
	return srv.Serve(ctx, ln)
}
