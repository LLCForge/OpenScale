package cli

import (
	"context"
	"errors"
	"fmt"
	"image"
	"image/png"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/rdesk"
	"github.com/openscale/openscale/internal/trust"
)

// --- rdesk (ADR-0055) ---

// rdeskTimeout covers the on-screen approval on the target (at most two
// minutes) plus the first frame.
const rdeskTimeout = 3 * time.Minute

// parseMonitorFlag accepts "primary", "all" or a monitor number from 0.
func parseMonitorFlag(s string) (int, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "primary", "birincil":
		return rdesk.MonitorPrimary, nil
	case "all", "hepsi", "tumu", "tümü":
		return rdesk.MonitorAll, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || n > 15 {
		return 0, usageError("--monitor primary, all veya 0-15 arası bir numara olmalı")
	}
	return n, nil
}

func cmdRemoteDesktop(env *Env, args []string) error {
	fs := newFlagSet(env, "rdesk")
	rf := addRemoteFlags(fs)
	snapshot := fs.String("snapshot", "", "uzak ekranın görüntüsünün yazılacağı yeni PNG dosyası")
	monitor := fs.String("monitor", "primary", "monitör: primary (birincil), all (hepsi) veya 0'dan başlayan numara")
	timeout := fs.Duration("timeout", rdeskTimeout, "hedefteki onay ve ilk kare için en uzun bekleme")
	fs.Usage = func() {
		fmt.Fprintln(env.Stderr, "Kullanım: openscale rdesk <cihaz> --snapshot dosya.png [--monitor primary|all|N]")
		fmt.Fprintln(env.Stderr, "Uzak ekranı izleme izniyle (rdesk kuralı) bağlanır ve tek bir görüntü kaydeder; girdi göndermez.")
		fs.PrintDefaults()
	}
	if err := parseFlagsWithArgs(fs, args, 1); err != nil {
		return err
	}
	if *snapshot == "" {
		return usageError("--snapshot dosya.png gerekli (canlı görüntüleyici henüz yok)")
	}
	if !strings.EqualFold(filepath.Ext(*snapshot), ".png") {
		return usageError("--snapshot dosyasının uzantısı .png olmalı")
	}
	mon, err := parseMonitorFlag(*monitor)
	if err != nil {
		return err
	}
	if *timeout < 5*time.Second || *timeout > 10*time.Minute {
		return usageError("--timeout 5s ile 10m arasında olmalı")
	}
	// Fail before connecting so the target does not prompt for nothing.
	if _, err := os.Lstat(*snapshot); err == nil {
		return fmt.Errorf("%s zaten var; üzerine yazılmaz", *snapshot)
	}

	ctx := envContext(env)
	rc := loadRemoteContext(env, rf)
	name, addr, err := rc.resolveTarget(ctx, fs.Arg(0))
	if err != nil {
		return err
	}
	if name == "" {
		name = addr.String()
	}
	// The target decides; this only saves a pointless connection when the
	// local copy of the rules already says no.
	if rc.doc != nil && rc.self != "" {
		if _, known := rc.doc.DeviceByName(name); known && !rc.doc.AllowsRemoteDesktop(rc.self, name, trust.RemoteDesktopView) {
			return fmt.Errorf("kurallar %s cihazından %s cihazına uzak masaüstü izni vermiyor (rdesk kuralı gerekli)", rc.self, name)
		}
	}
	fmt.Fprintf(env.Stdout, "%s cihazına bağlanılıyor (yalnızca izleme); hedefte onay istenebilir...\n", name)
	sctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	img, mons, err := rdesk.Snapshot(sctx, netip.AddrPortFrom(addr, trust.RemoteDesktopPort), mon)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return errors.New("zaman aşımı: hedef onay vermedi veya ekranı şu anda okunamıyor (kilitli olabilir)")
		}
		return err
	}
	if err := writePNGExclusive(*snapshot, img); err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "%d×%d görüntü %s dosyasına yazıldı.\n", img.Rect.Dx(), img.Rect.Dy(), *snapshot)
	for i, m := range mons {
		primary := ""
		if m.Primary {
			primary = " (birincil)"
		}
		fmt.Fprintf(env.Stdout, "  monitör %d: %d×%d, konum %d,%d%s\n", i, m.Bounds.Dx(), m.Bounds.Dy(), m.Bounds.Min.X, m.Bounds.Min.Y, primary)
	}
	return nil
}

// writePNGExclusive creates path (never overwriting) readable only by the
// owner, since a screenshot can hold anything that was on the screen.
func writePNGExclusive(path string, img image.Image) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("%s oluşturulamadı: %w", path, err)
	}
	enc := png.Encoder{CompressionLevel: png.BestSpeed}
	if err := enc.Encode(f, img); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return fmt.Errorf("PNG yazılamadı: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("PNG yazılamadı: %w", err)
	}
	return nil
}
