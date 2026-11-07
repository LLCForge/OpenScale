package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	iofs "io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/service"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/webhook"
)

// Automation and management access (P17): remote panel access and API
// keys (ADR-0107), event webhooks and the debug page (ADR-0108).

func p17Commands() []command {
	return []command{
		{"panel-remote", "Panele tünel üzerinden başka cihazdan salt okunur erişim: on|off|password|status (ADR-0107)", cmdPanelRemote},
		{"api-key", "Salt okunur yönetim API'si (/api/v1) anahtarları: create <ad> [--remote] | list | revoke <ad|kimlik>", cmdAPIKey},
		{"webhook", "Olayları yerel/özel ağdaki bir adrese imzalı iletir: init --url | show | test | run | off", cmdWebhook},
		{"debug http", "Durum, yollar, eşler ve kuralları gösteren geçici yerel hata ayıklama sayfası açar (yalnızca 127.0.0.1)", cmdDebugHTTP},
	}
}

// networkDirFlag returns the network directory: --dir, or the Windows
// service's network directory.
func networkDirFlag(dir string) (string, error) {
	if dir != "" {
		return dir, nil
	}
	if d := localAPI.dataDir(); d != "" {
		return filepath.Join(d, service.NetworkDir), nil
	}
	return "", usageError("--dir (ağ klasörü) zorunlu")
}

func cmdPanelRemote(env *Env, args []string) error {
	if len(args) == 0 {
		return usageError("bir alt komut yazın: on | off | password | status")
	}
	sub, rest := args[0], args[1:]
	fs := newFlagSet(env, "panel-remote "+sub)
	dirFlag := fs.String("dir", "", "ağ klasörü (Windows'ta varsayılan: servisin ağ klasörü)")
	asJSON := fs.Bool("json", false, "JSON çıktı (status)")
	if err := parseFlags(fs, rest); err != nil {
		return err
	}
	dir, err := networkDirFlag(*dirFlag)
	if err != nil {
		return err
	}
	n, err := admin.Load(dir, env.adminOptions())
	if err != nil {
		return fmt.Errorf("ağ klasörü açılamadı (uzaktan erişim yalnızca kök anahtarın olduğu bilgisayarda açılır): %w", err)
	}
	w := env.Stdout
	switch sub {
	case "on", "off":
		set, err := panel.LoadRemoteSettings(dir)
		if err != nil {
			return err
		}
		if sub == "on" && set.Password == nil {
			return errors.New("önce uzak erişim parolası belirleyin: openscale panel-remote password")
		}
		set.Enabled = sub == "on"
		set.ChangedAt = env.Now().UTC()
		if err := panel.SaveRemoteSettings(dir, set); err != nil {
			return err
		}
		if sub == "off" {
			fmt.Fprintln(w, "Uzaktan erişim kapatıldı; panel birkaç saniye içinde tünel adresinden dinlemeyi bırakır.")
			return nil
		}
		fmt.Fprintln(w, "Uzaktan erişim açıldı. Yalnızca okuma yapılabilir; imza gerektiren işlemler bu bilgisayarda kalır.")
		fmt.Fprintln(w, "Bir cihaza izin vermek için belgeye panel kuralı ekleyin, örnek:")
		fmt.Fprintln(w, "  openscale rule add --dir <ağ klasörü> --from <cihaz> --to <bu cihaz> --service panel")
		fmt.Fprintln(w, "Uyarı: 'panel' kuralını tanımayan eski istemciler belgeyi reddeder; önce bütün cihazları güncelleyin.")
		return nil
	case "password":
		return setRemotePassword(env, n, dir)
	case "status":
		doc, err := n.Document()
		if err != nil {
			return err
		}
		st, err := panel.DescribeRemote(dir, doc, nil)
		if err != nil {
			return err
		}
		if *asJSON {
			return printJSON(w, st)
		}
		state := "kapalı"
		if st.Enabled {
			state = "açık"
		}
		fmt.Fprintf(w, "Uzaktan erişim: %s\nParola: %v\nPanel kuralı: %v\nAPI anahtarı: %d\n", state, p17YesNo(st.Password), p17YesNo(st.Rule), st.APIKeys)
		if st.Device != "" {
			fmt.Fprintf(w, "Bu cihaz: %s\n", st.Device)
		}
		if st.Address != "" && st.Reason == "" {
			fmt.Fprintf(w, "Adres (yalnızca tünelden): %s\n", st.Address)
		}
		if st.Reason != "" {
			fmt.Fprintf(w, "Dinlemiyor: %s\n", st.Reason)
		}
		return nil
	}
	return usageError("bilinmeyen alt komut %q: on | off | password | status", sub)
}

func p17YesNo(b bool) string {
	if b {
		return "var"
	}
	return "yok"
}

// setRemotePassword asks for the remote password twice. It must differ
// from the root key passphrase: it is typed on other devices.
func setRemotePassword(env *Env, n *admin.Network, dir string) error {
	if env.ReadSecret == nil {
		return errors.New("bu komut etkileşimli terminal ister")
	}
	pw, err := env.ReadSecret("Uzak erişim parolası (kök anahtar parolasından farklı, en az 12 karakter): ")
	if err != nil {
		return err
	}
	defer wipe(pw)
	again, err := env.ReadSecret("Parolayı tekrar yazın: ")
	if err != nil {
		return err
	}
	defer wipe(again)
	if !bytes.Equal(pw, again) {
		return errors.New("parolalar aynı değil")
	}
	if err := panel.CheckRemotePassword(pw); err != nil {
		return err
	}
	switch err := n.CheckPassphrase(pw); {
	case err == nil:
		return errors.New("uzak erişim parolası kök anahtar parolasıyla aynı olamaz; başka cihazlarda yazılacak")
	case !errors.Is(err, trust.ErrWrongPassphrase):
		return err
	}
	hash, err := panel.HashRemotePassword(pw, env.Random)
	if err != nil {
		return err
	}
	set, err := panel.LoadRemoteSettings(dir)
	if err != nil {
		return err
	}
	set.Password = hash
	set.ChangedAt = env.Now().UTC()
	if err := panel.SaveRemoteSettings(dir, set); err != nil {
		return err
	}
	fmt.Fprintln(env.Stdout, "Uzak erişim parolası kaydedildi. Açık uzak oturumlar bir sonraki girişte yeni parolayı ister.")
	if !set.Enabled {
		fmt.Fprintln(env.Stdout, "Uzaktan erişim henüz kapalı: openscale panel-remote on")
	}
	return nil
}

func cmdAPIKey(env *Env, args []string) error {
	if len(args) == 0 {
		return usageError("bir alt komut yazın: create <ad> [--remote] | list | revoke <ad|kimlik>")
	}
	sub := args[0]
	fs := newFlagSet(env, "api-key "+sub)
	dirFlag := fs.String("dir", "", "ağ klasörü (Windows'ta varsayılan: servisin ağ klasörü)")
	remote := fs.Bool("remote", false, "anahtar tünel üzerinden (panel kuralı olan cihazlardan) de geçerli olsun")
	asJSON := fs.Bool("json", false, "JSON çıktı (list)")
	pos, err := parseInterspersed(fs, args[1:])
	if err != nil {
		return err
	}
	dir, err := networkDirFlag(*dirFlag)
	if err != nil {
		return err
	}
	if _, err := admin.Load(dir, env.adminOptions()); err != nil {
		return fmt.Errorf("ağ klasörü açılamadı: %w", err)
	}
	w := env.Stdout
	switch sub {
	case "create":
		if len(pos) != 1 {
			return usageError("anahtar adı yazın: openscale api-key create <ad>")
		}
		secret, k, err := panel.CreateAPIKey(dir, pos[0], *remote, env.Random, env.Now())
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "API anahtarı oluşturuldu: %s (kimlik %s)\n\n  %s\n\n", k.Name, k.ID, secret)
		fmt.Fprintln(w, "Bu anahtar yalnızca şimdi gösterilir; saklanan yalnızca özetidir. Yalnızca okuma yapar.")
		fmt.Fprintln(w, "Kullanım: Authorization: Bearer <anahtar>  →  GET /api/v1/devices (docs/api/openapi.yaml)")
		if k.Remote {
			fmt.Fprintln(w, "Tünel üzerinden de geçerli: istek yapan cihazın belgede panel kuralı olmalı.")
		}
		return nil
	case "list":
		keys, err := panel.LoadAPIKeys(dir)
		if err != nil {
			return err
		}
		if *asJSON {
			type view struct {
				ID        string    `json:"id"`
				Name      string    `json:"name"`
				CreatedAt time.Time `json:"created_at"`
				Remote    bool      `json:"remote"`
			}
			out := []view{}
			for _, k := range keys {
				out = append(out, view{k.ID, k.Name, k.CreatedAt, k.Remote})
			}
			return printJSON(w, map[string]any{"schema": 1, "keys": out})
		}
		if len(keys) == 0 {
			fmt.Fprintln(w, "API anahtarı yok.")
			return nil
		}
		for _, k := range keys {
			scope := "yalnızca bu bilgisayar"
			if k.Remote {
				scope = "bu bilgisayar ve tünel"
			}
			fmt.Fprintf(w, "%s  %-20s  %s  %s\n", k.ID, k.Name, k.CreatedAt.Format("2006-01-02"), scope)
		}
		return nil
	case "revoke":
		if len(pos) != 1 {
			return usageError("anahtar adını veya kimliğini yazın")
		}
		k, err := panel.RevokeAPIKey(dir, pos[0])
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "API anahtarı silindi: %s (%s)\n", k.Name, k.ID)
		return nil
	}
	return usageError("bilinmeyen alt komut %q", sub)
}

// webhookPath is --config or the default location next to the tunnel's
// state.
func webhookPath(env *Env, config string) (string, error) {
	if config != "" {
		return config, nil
	}
	if d := localAPI.dataDir(); d != "" {
		return filepath.Join(d, webhook.ConfigFile), nil
	}
	dir, err := resolveStateDir(env, "")
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, webhook.ConfigFile), nil
}

func cmdWebhook(env *Env, args []string) error {
	if len(args) == 0 {
		return usageError("bir alt komut yazın: init --url <adres> [--events a,b] | show [--secret] | test | run | off")
	}
	sub := args[0]
	fs := newFlagSet(env, "webhook "+sub)
	config := fs.String("config", "", "yapılandırma dosyası")
	rawURL := fs.String("url", "", "hedef (yalnızca loopback veya özel ağ: 10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7)")
	events := fs.String("events", "", "gönderilecek olay türleri veya kategorileri, virgülle (boş: hepsi)")
	showSecret := fs.Bool("secret", false, "sırrı da göster (show)")
	stateDir := fs.String("state-dir", "", "'openscale up' durum klasörü (run)")
	if err := parseFlags(fs, args[1:]); err != nil {
		return err
	}
	path, err := webhookPath(env, *config)
	if err != nil {
		return err
	}
	w := env.Stdout
	switch sub {
	case "init":
		var kinds []string
		for _, k := range strings.Split(*events, ",") {
			if k = strings.TrimSpace(k); k != "" {
				kinds = append(kinds, k)
			}
		}
		c, err := webhook.NewConfig(strings.TrimSpace(*rawURL), kinds, env.Random)
		if err != nil {
			return err
		}
		if err := webhook.Save(path, c); err != nil {
			return err
		}
		fmt.Fprintf(w, "Webhook yapılandırması yazıldı: %s\nHMAC-SHA256 sırrı (alıcıya verin, yalnızca şimdi gösterilir):\n\n  %s\n\n", path, c.Secret)
		fmt.Fprintln(w, "İletmeyi başlatmak için: openscale webhook run   (deneme: openscale webhook test)")
		return nil
	case "show":
		c, err := webhook.Load(path)
		if err != nil {
			return err
		}
		if !*showSecret {
			c.Secret = "(gizli; --secret ile gösterilir)"
		}
		return printJSON(w, c)
	case "off":
		if err := os.Remove(path); err != nil && !errors.Is(err, iofs.ErrNotExist) {
			return err
		}
		fmt.Fprintln(w, "Webhook yapılandırması silindi; çalışan iletici durdurulmalı.")
		return nil
	case "test":
		c, err := webhook.Load(path)
		if err != nil {
			return err
		}
		s, err := webhook.NewSender(c, webhook.Options{Now: env.Now, Random: env.Random})
		if err != nil {
			return err
		}
		ev := webhook.Event{At: env.Now().UTC(), Kind: "webhook_test", Category: "test", Severity: "info", Message: "OpenScale webhook denemesi"}
		if err := s.Deliver(envContext(env), ev); err != nil {
			return fmt.Errorf("deneme iletisi gönderilemedi: %w", err)
		}
		fmt.Fprintln(w, "Deneme iletisi gönderildi.")
		return nil
	case "run":
		return runWebhook(env, path, *stateDir)
	}
	return usageError("bilinmeyen alt komut %q", sub)
}

// webhookPollWait stays below the command line client's call timeout.
const webhookPollWait = 15

// runWebhook reads the local event stream and delivers the chosen events
// until Ctrl+C. It starts at the newest event: nothing old is replayed.
func runWebhook(env *Env, path, stateDir string) error {
	c, err := webhook.Load(path)
	if err != nil {
		return err
	}
	lc, err := openLocalClient(env, stateDir)
	if err != nil {
		return err
	}
	var st panel.DiagStatus
	device := ""
	if lc.get(env, "/status", &st) == nil && st.Self != nil {
		device = st.Self.Name
	}
	logger := maskedJSONLogger(env.Stderr, slog.LevelInfo)
	s, err := webhook.NewSender(c, webhook.Options{Device: device, Logger: logger, Now: env.Now, Random: env.Random})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(envContext(env))
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.Run(ctx)
	}()
	defer func() {
		cancel()
		<-done
	}()
	var rep panel.EventStreamReply
	if err := lc.get(env, "/events/poll?since=0&wait=0", &rep); err != nil {
		return err
	}
	since := rep.Next
	fmt.Fprintf(env.Stdout, "Olaylar %s adresine iletiliyor. Durdurmak için Ctrl+C.\n", c.URL)
	failures := 0
	for ctx.Err() == nil {
		var batch panel.EventStreamReply
		err := lc.call(ctx, "GET", fmt.Sprintf("%s/events/poll?since=%d&wait=%d", panel.LocalAPIPrefix, since, webhookPollWait), nil, &batch)
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			failures++
			logger.Warn("event stream unavailable", "error", err.Error())
			if !sleepCtx(ctx, time.Duration(min(failures, 6))*5*time.Second) {
				break
			}
			continue
		}
		failures = 0
		for _, ev := range batch.Events {
			s.Enqueue(webhook.Event{Seq: ev.Seq, At: ev.At, Kind: ev.Kind, Category: ev.Category, Severity: ev.Severity, Peer: ev.Peer, Message: ev.Message})
		}
		since = batch.Next
	}
	if n := s.Dropped(); n > 0 {
		fmt.Fprintf(env.Stderr, "uyarı: kuyruk dolduğu için %d olay iletilemedi\n", n)
	}
	return nil
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
