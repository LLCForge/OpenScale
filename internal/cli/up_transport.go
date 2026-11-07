package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/openscale/openscale/internal/coordinator"
	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/sdnotify"
	"github.com/openscale/openscale/internal/service"
)

// Faz 4 options of "openscale up" (ADR-0032 TCP transport, ADR-0033
// post-quantum PSK, F-020 lazy peers, F-021 keepalive) and of
// "openscale coordinator run" (TCP listener), plus the systemd readiness
// notification (F-149) and "openscale wait".

// The flags below are also listed in upEnvFlags and coordinatorEnvFlags
// (config.go), so OPENSCALE_* variables and --config files may set them.

type upTransportFlags struct {
	postQuantum *bool
	pskRotation *time.Duration
	tcpFallback *string
	noTCP       *bool
	keepalive   *time.Duration
	adaptive    *bool
	lazy        *bool
	lazyIdle    *time.Duration
	// ADR-0230, ADR-0231, ADR-0233 (up_netsep.go).
	sealed   *string
	birthday *bool
	parser   *string
}

func addUpTransportFlags(fs *flag.FlagSet) upTransportFlags {
	return upTransportFlags{
		postQuantum: fs.Bool("post-quantum", true, "eşlerle kuantum sonrası (ML-KEM-768) ön paylaşımlı anahtar anlaş (ADR-0033); false: klasik WireGuard"),
		pskRotation: fs.Duration("psk-rotation", 0, "kuantum sonrası anahtarın yenilenme aralığı (0: varsayılan 10m; 2m-24h)"),
		tcpFallback: fs.String("tcp-fallback", "", "UDP engelliyken koordinatörün TCP adresi, ana-makine:port (boş: koordinatörün adresi, port 443; ADR-0032)"),
		noTCP:       fs.Bool("disable-tcp-fallback", false, "koordinatöre TCP yedeğini hiç kullanma"),
		keepalive:   fs.Duration("keepalive", 0, "WireGuard keepalive aralığı (0: varsayılan 25s; 10s-120s, tam saniye)"),
		adaptive:    fs.Bool("adaptive-keepalive", false, "bağlantı kopup geri gelince keepalive'ı kısalt, uzun süre sorunsuzsa geri uzat"),
		lazy:        fs.Bool("lazy-peers", false, "eşleri yalnızca trafik olunca WireGuard'a ekle, boşta kalınca çıkar (büyük ağlar için)"),
		lazyIdle:    fs.Duration("lazy-idle", 0, "tembel eşin trafiksiz kalınca çıkarılma süresi (0: varsayılan 10m; 1m-24h)"),
		sealed:      fs.String("sealed-candidates", "auto", "uç nokta adaylarını eşe uçtan uca şifreli gönder (ADR-0230): auto (eski eş çevrimiçiyken açık da), only (yalnızca şifreli), off"),
		birthday:    fs.Bool("birthday-scan", true, "iki taraf da simetrik NAT arkasındaysa sınırlı rastgele port taraması dene (ADR-0231)"),
		parser:      fs.String("parser-sandbox", "auto", "ağdan gelen belgeleri ayrıcalıksız yardımcı süreçte ayrıştır (ADR-0233): auto, required, off"),
	}
}

type upTransportOptions struct {
	postQuantum bool
	pskRotation time.Duration
	tcpFallback string
	noTCP       bool
	keepalive   time.Duration
	adaptive    bool
	lazy        bool
	lazyIdle    time.Duration
	netsep      upNetSepOptions
}

func (f upTransportFlags) resolve() (upTransportOptions, error) {
	o := upTransportOptions{postQuantum: *f.postQuantum, pskRotation: *f.pskRotation, tcpFallback: *f.tcpFallback,
		noTCP: *f.noTCP, keepalive: *f.keepalive, adaptive: *f.adaptive, lazy: *f.lazy, lazyIdle: *f.lazyIdle}
	var err error
	if o.netsep, err = resolveNetSep(f); err != nil {
		return o, err
	}
	if err := service.ValidPSKRotation(o.pskRotation); err != nil {
		return o, usageError("--psk-rotation: %v", err)
	}
	if err := service.ValidTCPFallback(o.tcpFallback); err != nil {
		return o, usageError("--tcp-fallback: %v", err)
	}
	if o.noTCP && o.tcpFallback != "" {
		return o, usageError("--tcp-fallback ile --disable-tcp-fallback birlikte kullanılamaz")
	}
	if err := service.ValidKeepalive(o.keepalive); err != nil {
		return o, usageError("--keepalive: %v", err)
	}
	if err := service.ValidLazyIdle(o.lazyIdle); err != nil {
		return o, usageError("--lazy-idle: %v", err)
	}
	if o.lazyIdle != 0 && !o.lazy {
		return o, usageError("--lazy-idle yalnızca --lazy-peers ile anlamlı")
	}
	return o, nil
}

func (o upTransportOptions) apply(cfg node.Config) node.Config {
	cfg.PostQuantum = node.PostQuantumOn
	if !o.postQuantum {
		cfg.PostQuantum = node.PostQuantumOff
	}
	cfg.PSKRotation = o.pskRotation
	cfg.TCPFallback = o.tcpFallback
	cfg.DisableTCPFallback = o.noTCP
	cfg.Keepalive = o.keepalive
	cfg.AdaptiveKeepalive = o.adaptive
	cfg.LazyPeers = o.lazy
	cfg.LazyIdle = o.lazyIdle
	return o.netsep.apply(cfg)
}

type coordinatorTCPFlags struct {
	listen   *string
	maxConns *int
	perIP    *int
}

func addCoordinatorTCPFlags(fs *flag.FlagSet) coordinatorTCPFlags {
	return coordinatorTCPFlags{
		listen:   fs.String("tcp-listen", "", "UDP'si engelli cihazlar için TCP dinleme adresi, ör. :443 veya 203.0.113.5:443 (boş: kapalı; ADR-0032). 1024 altı port için root veya CAP_NET_BIND_SERVICE gerekir"),
		maxConns: fs.Int("tcp-max-conns", 0, fmt.Sprintf("en fazla TCP bağlantısı (0: varsayılan %d; en fazla %d)", coordinator.DefaultTCPMaxConns, coordinator.MaxTCPMaxConns)),
		perIP:    fs.Int("tcp-max-conns-per-ip", 0, fmt.Sprintf("bir adresten en fazla TCP bağlantısı (0: varsayılan %d)", coordinator.DefaultTCPMaxConnsPerIP)),
	}
}

func (f coordinatorTCPFlags) resolve() (string, int, int, error) {
	if err := service.ValidCoordinatorTCP(*f.listen, *f.maxConns, *f.perIP); err != nil {
		return "", 0, 0, usageError("%v", err)
	}
	return *f.listen, *f.maxConns, *f.perIP, nil
}

// notifyReadyWhenSynced tells systemd the tunnel is up (the interface has
// its addresses, so services may bind to them) and updates the status
// line once the first sync with the coordinator succeeded. Outside a
// Type=notify unit it does nothing.
func notifyReadyWhenSynced(ctx context.Context, engine *node.Engine, name string) {
	if _, err := sdnotify.Ready("Tünel açık: " + name + "; koordinatör bekleniyor"); err != nil {
		return
	}
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				_, _ = sdnotify.Stopping()
				return
			case <-t.C:
			}
			if st := engine.Status(); !st.LastSync.IsZero() && st.LastSyncError == "" {
				_, _ = sdnotify.Status("Bağlı: " + name)
				<-ctx.Done()
				_, _ = sdnotify.Stopping()
				return
			}
		}
	}()
}

// notifyCoordinatorReady tells systemd once the coordinator's WireGuard
// device is up.
func notifyCoordinatorReady(ctx context.Context, srv *coordinator.Server, port int, tcpListen string) {
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-srv.Ready():
		}
		status := fmt.Sprintf("Koordinatör %d/udp", port)
		if tcpListen != "" {
			status += " ve " + tcpListen + "/tcp"
		}
		_, _ = sdnotify.Ready(status + " dinliyor")
		<-ctx.Done()
		_, _ = sdnotify.Stopping()
	}()
}

// Bounds of "openscale wait --timeout".
const (
	defaultWaitTimeout = 60 * time.Second
	maxWaitTimeout     = time.Hour
	waitPoll           = time.Second
)

// cmdWait waits until the tunnel is ready (F-149): for scripts and units
// that must start after OpenScale, e.g. a server bound to the tunnel IP.
func cmdWait(env *Env, args []string) error {
	fs := newFlagSet(env, "wait")
	stateDir := fs.String("state-dir", "", "ön planda 'openscale up' ile açılan tünelin durum klasörü")
	timeout := fs.Duration("timeout", defaultWaitTimeout, "en fazla bu kadar bekle (1s-1h)")
	live := fs.Bool("live", false, "yalnızca tünelin çalışmasını bekle; koordinatörle eşitlemeyi bekleme")
	quiet := fs.Bool("quiet", false, "çıktı yazma; yalnızca çıkış kodu")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *timeout < time.Second || *timeout > maxWaitTimeout {
		return usageError("--timeout 1s ile 1h arasında olmalı")
	}
	ctx, cancel := context.WithTimeout(envContext(env), *timeout)
	defer cancel()
	last := ""
	for {
		ready, why := waitProbe(env, ctx, *stateDir, *live)
		if ready {
			if !*quiet {
				fmt.Fprintln(env.Stdout, "Tünel hazır.")
			}
			return nil
		}
		if why != last && !*quiet {
			fmt.Fprintf(env.Stderr, "bekleniyor: %s\n", why)
			last = why
		}
		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return fmt.Errorf("tünel %s içinde hazır olmadı: %s", *timeout, why)
			}
			return ctx.Err()
		case <-time.After(waitPoll):
		}
	}
}

// waitProbe asks the local API once.
func waitProbe(env *Env, ctx context.Context, stateDir string, live bool) (bool, string) {
	probeEnv := *env
	probeEnv.Ctx = ctx
	c, err := openLocalClient(&probeEnv, stateDir)
	if err != nil {
		return false, "çalışan tünel yok"
	}
	var h panel.HealthReport
	if err := c.get(&probeEnv, "/health", &h); err != nil {
		return false, err.Error()
	}
	if live && h.Live {
		return true, ""
	}
	if h.Ready {
		return true, ""
	}
	if len(h.Reasons) > 0 {
		return false, h.Reasons[0]
	}
	return false, "tünel hazır değil"
}
