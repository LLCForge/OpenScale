package healthmon

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/speedtest"
	"github.com/openscale/openscale/internal/trust"
)

// Speed test button (#763): one click measures download and upload against
// a peer or the exit node through the tunnel, using internal/speedtest.
// The button checks the signed document's speedtest rule first, runs one
// test at a time, waits a cooldown per target and keeps the last results
// for the panel.

// Speed limits.
const (
	SpeedCooldown   = 30 * time.Second
	maxSpeedHistory = 50
)

// Errors of the speed button.
var (
	ErrSpeedBusy     = errors.New("bir hız testi zaten sürüyor")
	ErrSpeedCooldown = errors.New("aynı cihaza art arda hız testi için biraz bekleyin")
	ErrSpeedDenied   = errors.New("bu cihaza hız testi için bir speedtest kuralı yok")
	ErrSpeedNoDevice = errors.New("böyle bir cihaz yok")
)

// SpeedRunner runs one test; speedtest.Run in production.
type SpeedRunner func(ctx context.Context, addr netip.AddrPort, dir speedtest.Direction, d time.Duration) (speedtest.Result, error)

// SpeedResult is one button press.
type SpeedResult struct {
	Target       string    `json:"target"`
	At           time.Time `json:"at"`
	DownloadMbps float64   `json:"downloadMbps"`
	UploadMbps   float64   `json:"uploadMbps"`
	Error        string    `json:"error,omitempty"`
}

// SpeedButton serializes speed tests.
type SpeedButton struct {
	Run      SpeedRunner
	Duration time.Duration
	Now      func() time.Time

	mu      sync.Mutex
	busy    bool
	last    map[string]time.Time
	history []SpeedResult
}

// NewSpeedButton uses speedtest.Run with its default duration.
func NewSpeedButton() *SpeedButton {
	return &SpeedButton{Run: speedtest.Run, Duration: speedtest.DefaultDuration}
}

func (b *SpeedButton) now() time.Time {
	if b.Now != nil {
		return b.Now()
	}
	return time.Now()
}

// Measure tests download then upload between self and target. target may
// be any device the rules allow, an exit node included.
func (b *SpeedButton) Measure(ctx context.Context, doc *trust.Document, self, target string) (SpeedResult, error) {
	if doc == nil {
		return SpeedResult{}, ErrSpeedNoDevice
	}
	dev, ok := doc.DeviceByName(target)
	if !ok || target == self {
		return SpeedResult{}, ErrSpeedNoDevice
	}
	if !doc.AllowsSpeedtest(self, target) {
		return SpeedResult{}, ErrSpeedDenied
	}
	addr := dev.IPv4
	if !addr.IsValid() {
		addr = dev.IPv6
	}
	return b.measureAddr(ctx, target, netip.AddrPortFrom(addr, trust.SpeedtestPort))
}

func (b *SpeedButton) measureAddr(ctx context.Context, target string, ap netip.AddrPort) (SpeedResult, error) {
	now := b.now()
	b.mu.Lock()
	if b.busy {
		b.mu.Unlock()
		return SpeedResult{}, ErrSpeedBusy
	}
	if b.last == nil {
		b.last = map[string]time.Time{}
	}
	if t, ok := b.last[target]; ok && now.Sub(t) < SpeedCooldown {
		b.mu.Unlock()
		return SpeedResult{}, ErrSpeedCooldown
	}
	b.busy = true
	b.last[target] = now
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		b.busy = false
		b.mu.Unlock()
	}()
	run := b.Run
	if run == nil {
		run = speedtest.Run
	}
	res := SpeedResult{Target: target, At: now}
	down, err := run(ctx, ap, speedtest.Download, b.Duration)
	if err == nil {
		res.DownloadMbps = down.Mbps()
		var up speedtest.Result
		up, err = run(ctx, ap, speedtest.Upload, b.Duration)
		if err == nil {
			res.UploadMbps = up.Mbps()
		}
	}
	if err != nil {
		res.Error = err.Error()
	}
	b.mu.Lock()
	b.history = append(b.history, res)
	if len(b.history) > maxSpeedHistory {
		b.history = b.history[len(b.history)-maxSpeedHistory:]
	}
	b.mu.Unlock()
	if err != nil {
		return res, fmt.Errorf("hız testi: %w", err)
	}
	return res, nil
}

// History returns the recent results, newest last.
func (b *SpeedButton) History() []SpeedResult {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]SpeedResult(nil), b.history...)
}
