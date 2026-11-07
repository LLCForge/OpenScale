package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/winapp"
)

// Native window commands (ADR-0195):
//
//	openscale window --dir <ağ>   the desktop entry of Linux and macOS (and
//	                              Windows without the service): runs the
//	                              panel and shows it in a native window,
//	                              falling back to the browser.
//	openscale panel-window        started by the Windows tray in a
//	                              non-elevated process; reads the one-time
//	                              link from --url, --link-pipe or standard input.

func init() {
	registerCommands(
		command{"window", "Yönetim panelini yerel uygulama penceresinde açar (pencere yoksa tarayıcıda): --dir <ağ klasörü>", cmdWindow},
		command{"panel-window", "Tepsinin açtığı panel penceresi (elle çalıştırılmaz)", cmdPanelWindow},
	)
}

func cmdWindow(env *Env, args []string) error {
	fs := newFlagSet(env, "window")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	port := fs.Int("port", 0, "dinlenecek port; 0 boş bir port seçer")
	browser := fs.Bool("browser", false, "yerel pencere yerine sistem tarayıcısını kullan")
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
	srv, err := panel.New(panel.Config{
		Network: n,
		Logger:  maskedJSONLogger(env.Stderr, slog.LevelWarn),
		Now:     env.Now,
		Random:  env.Random,
	})
	if err != nil {
		return err
	}
	ln, err := panel.Listen(*port)
	if err != nil {
		return fmt.Errorf("panel portu açılamadı: %w", err)
	}
	ctx := env.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ctx, ln) }()
	link := srv.URL(ln.Addr())

	if !*browser {
		// On macOS this must run on the main goroutine: cli.Run is called
		// from main and commands run on it.
		err := winapp.OpenPanelWindow(ctx, link, "")
		switch {
		case err == nil, errors.Is(err, context.Canceled):
			cancel()
			<-served
			return nil
		case !errors.Is(err, winapp.ErrWindowUnavailable):
			cancel()
			<-served
			return err
		}
		fmt.Fprintf(env.Stderr, "Yerel pencere açılamadı (%v); tarayıcı kullanılıyor.\n", err)
	}
	if err := winapp.OpenSystemBrowser(link); err != nil {
		fmt.Fprintf(env.Stderr, "Tarayıcı açılamadı: %v\n", err)
	}
	fmt.Fprintln(env.Stdout, "Panel tarayıcıda açılıyor. Adres (yalnızca bu bilgisayardan, tek kullanımlık):")
	fmt.Fprintln(env.Stdout, "  "+link)
	fmt.Fprintln(env.Stdout, "Durdurmak için Ctrl+C.")
	return <-served
}

func cmdPanelWindow(env *Env, args []string) error {
	fs := newFlagSet(env, "panel-window")
	link := fs.String("url", "", "tek kullanımlık panel adresi (boşsa standart girişten okunur)")
	linkPipe := fs.String("link-pipe", "", "tepsinin adresi verdiği kanal (yükseltilmiş tepsi kullanır)")
	title := fs.String("title", "", "pencere başlığı (tepsinin gösterdiği ad)")
	if err := parseFlags(fs, args); err != nil {
		return exitCodeError{code: winapp.PanelWindowExitInvalid}
	}
	u := strings.TrimSpace(*link)
	if u == "" && *linkPipe != "" {
		piped, err := winapp.ReadPanelLinkPipe(*linkPipe)
		if err != nil {
			fmt.Fprintf(env.Stderr, "panel penceresi: %v\n", err)
			return exitCodeError{code: winapp.PanelWindowExitInvalid}
		}
		u = strings.TrimSpace(piped)
	}
	if u == "" && env.Stdin != nil {
		line, _ := bufio.NewReader(env.Stdin).ReadString('\n')
		u = strings.TrimSpace(line)
	}
	if u == "" {
		return exitCodeError{code: winapp.PanelWindowExitInvalid}
	}
	ctx := env.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	err := winapp.OpenPanelWindow(ctx, u, *title)
	switch {
	case err == nil, errors.Is(err, context.Canceled):
		return nil
	case errors.Is(err, winapp.ErrWindowUnavailable):
		fmt.Fprintf(env.Stderr, "yerel pencere yok: %v\n", err)
		return exitCodeError{code: winapp.PanelWindowExitUnavailable}
	}
	fmt.Fprintf(env.Stderr, "panel penceresi: %v\n", err)
	return exitCodeError{code: winapp.PanelWindowExitInvalid}
}
