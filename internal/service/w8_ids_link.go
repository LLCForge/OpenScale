package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/filter"
	"github.com/openscale/openscale/internal/netwatch"
	"github.com/openscale/openscale/internal/notify"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

// Packet path of the intrusion detector (#729, ADR-0221).
//
// The packet filter's flow tap (filter/w8_flowtap.go) samples new
// connection attempts from the headers; this loop drains it, feeds the
// netwatch detector of the monitor and turns alerts into events and
// notifications. In the owner's opt-in "auto quarantine" mode a source
// device whose alert suggests isolation is quarantined locally, for a
// limited time, by this device's filter only: nothing is signed, nothing
// leaves this computer and the owner lifts it from the quarantine list
// like any other.

// IDSFile is ids.json in the data directory.
const IDSFile = "ids.json"

// Event kinds of the link.
const (
	EventIDSQuarantine = "ids_quarantine"
)

// IDS link bounds.
const (
	idsStep            = 250 * time.Millisecond
	idsMaxPerStep      = 2048
	idsReloadEvery     = 10 * time.Second
	idsDefaultQuarMins = 30
	idsMaxQuarMins     = 24 * 60
	idsMaxFile         = 4 << 10
)

// IDSConfig is ids.json. The zero value runs detection without
// quarantine.
type IDSConfig struct {
	// Disabled turns sampling and detection off.
	Disabled bool `json:"disabled,omitempty"`
	// AutoQuarantine quarantines a source device locally when an alert
	// suggests it (port scan, sweep, connection storm, abused ports).
	AutoQuarantine bool `json:"auto_quarantine,omitempty"`
	// QuarantineMinutes is how long an automatic quarantine lasts
	// (default 30, 1 to 1440).
	QuarantineMinutes int `json:"quarantine_minutes,omitempty"`
}

// Validate checks the configuration.
func (c IDSConfig) Validate() error {
	if c.QuarantineMinutes < 0 || c.QuarantineMinutes > idsMaxQuarMins {
		return fmt.Errorf("quarantine_minutes 1 ile %d arasında olmalı", idsMaxQuarMins)
	}
	if c.Disabled && c.AutoQuarantine {
		return errors.New("algılama kapalıyken otomatik karantina açılamaz")
	}
	return nil
}

// QuarantineFor is the duration of an automatic quarantine.
func (c IDSConfig) QuarantineFor() time.Duration {
	if c.QuarantineMinutes == 0 {
		return idsDefaultQuarMins * time.Minute
	}
	return time.Duration(c.QuarantineMinutes) * time.Minute
}

// LoadIDSConfig reads ids.json strictly; a missing file is the default.
func LoadIDSConfig(dir string) (IDSConfig, error) {
	data, err := securefile.ReadLimited(dir+string(os.PathSeparator)+IDSFile, idsMaxFile)
	if errors.Is(err, fs.ErrNotExist) {
		return IDSConfig{}, nil
	}
	if err != nil {
		return IDSConfig{}, fmt.Errorf("saldırı algılama ayarı okunamadı: %w", err)
	}
	var c IDSConfig
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return IDSConfig{}, fmt.Errorf("saldırı algılama ayarı geçersiz: %w", err)
	}
	if dec.More() {
		return IDSConfig{}, errors.New("saldırı algılama ayarı geçersiz: fazladan veri")
	}
	return c, c.Validate()
}

// SaveIDSConfig validates and writes ids.json.
func SaveIDSConfig(dir string, c IDSConfig) error {
	if err := c.Validate(); err != nil {
		return err
	}
	return saveJSON(dir+string(os.PathSeparator)+IDSFile, c)
}

// idsLink connects one filter's tap to the monitor's detector.
type idsLink struct {
	dir      string
	mon      *w4Monitor
	tap      *filter.FlowTap
	attached *filter.Filter
	cfg      IDSConfig
	cfgAt    time.Time
	loaded   bool
}

func newIDSLink(dir string, m *w4Monitor) *idsLink {
	return &idsLink{dir: dir, mon: m, tap: filter.NewFlowTap(0)}
}

// reload rereads ids.json now and then; a broken file keeps the last
// good configuration and is reported once.
func (l *idsLink) reload(ctx context.Context, now time.Time) {
	if l.loaded && now.Sub(l.cfgAt) < idsReloadEvery {
		return
	}
	first := !l.loaded
	l.cfgAt, l.loaded = now, true
	c, err := LoadIDSConfig(l.dir)
	if err != nil {
		if first {
			l.mon.alert(ctx, "ids_config_error", "", err.Error(), notify.PriorityLow)
		}
		return
	}
	l.cfg = c
}

// attach installs the tap on f (nil detaches).
func (l *idsLink) attach(f *filter.Filter) {
	if l.attached == f {
		return
	}
	if l.attached != nil && l.attached.FlowTap() == l.tap {
		l.attached.SetFlowTap(nil)
	}
	if f != nil {
		f.SetFlowTap(l.tap)
	}
	l.attached = f
}

// step drains the tap once. doc and self describe the running engine.
func (l *idsLink) step(ctx context.Context, f *filter.Filter, doc *trust.Document, self string) int {
	now := l.mon.now()
	l.reload(ctx, now)
	if l.cfg.Disabled || f == nil {
		l.attach(nil)
		return 0
	}
	l.attach(f)
	return l.tap.Drain(idsMaxPerStep, func(r filter.TapRecord) {
		l.handle(ctx, f, doc, self, netwatch.Flow{At: now, Src: r.Src, Dst: r.Dst, Proto: r.Proto, Port: r.Port, Dropped: r.Dropped})
	})
}

func (l *idsLink) handle(ctx context.Context, f *filter.Filter, doc *trust.Document, self string, fl netwatch.Flow) {
	for _, a := range l.mon.ids.Observe(fl) {
		device := ""
		if doc != nil {
			if d, ok := doc.DeviceByAddr(a.Src); ok {
				device = d.Name
			}
		}
		subject := device
		if subject == "" {
			subject = "tünel içi kaynak"
		}
		l.mon.alert(ctx, EventIDSAlert, subject, a.Message, notify.PriorityHigh)
		if !l.cfg.AutoQuarantine || !a.Quarantine || device == "" || device == self || quarantined(f, device) {
			continue
		}
		d := l.cfg.QuarantineFor()
		if err := f.Quarantine(device, "ids:"+a.Kind, d); err != nil {
			l.mon.alert(ctx, EventIDSQuarantine, device, "Otomatik karantina uygulanamadı: "+err.Error(), notify.PriorityHigh)
			continue
		}
		l.mon.alert(ctx, EventIDSQuarantine, device,
			fmt.Sprintf("%s cihazı saldırı belirtisi nedeniyle bu cihazda %s yerel karantinaya alındı. Karantina listesinden kaldırılabilir.", device, idsMinutes(d)),
			notify.PriorityHigh)
	}
}

func quarantined(f *filter.Filter, device string) bool {
	for _, q := range f.Quarantined() {
		if q.Peer == device {
			return true
		}
	}
	return false
}

func idsMinutes(d time.Duration) string {
	m := int(d / time.Minute)
	if m%60 == 0 {
		return fmt.Sprintf("%d saat", m/60)
	}
	return fmt.Sprintf("%d dakika", m)
}

// idsLoop runs the link until ctx ends.
func (r *Runtime) idsLoop(ctx context.Context) {
	l := newIDSLink(r.cfg.DataDir, r.monitor())
	t := time.NewTicker(idsStep)
	defer t.Stop()
	defer l.attach(nil)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		var (
			f    *filter.Filter
			doc  *trust.Document
			self string
		)
		if e := r.currentEngine(); e != nil {
			f, doc = e.PacketFilter(), e.Document()
			if s, err := e.Self(); err == nil {
				self = s.Name
			}
		}
		l.step(ctx, f, doc, strings.TrimSpace(self))
	}
}
