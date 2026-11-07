package healthmon

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/sysinfo"
)

// Thresholds of disk and battery warnings (#774). The values come from
// sysinfo's read-only collectors (Windows, Linux and macOS); this package
// reads nothing from the system itself.
type Thresholds struct {
	// DiskFreePercent warns when a volume's free space falls below it.
	DiskFreePercent int `json:"disk_free_percent"`
	// DiskFreeBytes also warns below this many free bytes (0 disables).
	DiskFreeBytes uint64 `json:"disk_free_bytes,omitempty"`
	// BatteryHealthPercent warns when the full charge capacity falls below
	// this share of the design capacity.
	BatteryHealthPercent int `json:"battery_health_percent"`
	// BatteryLowPercent warns while discharging below this charge.
	BatteryLowPercent int `json:"battery_low_percent"`
	// IncludeRemovable also checks removable volumes.
	IncludeRemovable bool `json:"include_removable,omitempty"`
}

// DefaultThresholds are conservative defaults.
var DefaultThresholds = Thresholds{DiskFreePercent: 10, DiskFreeBytes: 5 << 30, BatteryHealthPercent: 70, BatteryLowPercent: 10}

// Validate checks the thresholds.
func (t Thresholds) Validate() error {
	if t.DiskFreePercent < 0 || t.DiskFreePercent > 90 || t.BatteryHealthPercent < 0 || t.BatteryHealthPercent > 100 || t.BatteryLowPercent < 0 || t.BatteryLowPercent > 90 {
		return fmt.Errorf("eşikler yüzde 0-90 (pil sağlığı 0-100) aralığında olmalı")
	}
	return nil
}

// Finding is one resource problem of a device.
type Finding struct {
	Kind    string
	Subject string // "device" or "device mount"
	Title   string
	Detail  string
}

// CheckResources evaluates a device's inventory. Volumes without a size
// (network shares, pseudo file systems) are skipped.
func CheckResources(device string, d *sysinfo.Detail, t Thresholds) []Finding {
	if d == nil {
		return nil
	}
	var out []Finding
	for _, v := range d.Volumes {
		if v.Size == 0 || (v.Removable && !t.IncludeRemovable) {
			continue
		}
		pct := int(v.Free * 100 / v.Size)
		low := (t.DiskFreePercent > 0 && pct < t.DiskFreePercent) || (t.DiskFreeBytes > 0 && v.Free < t.DiskFreeBytes && v.Size > 2*t.DiskFreeBytes)
		if low {
			mount := sysinfo.MaskMount(v.Mount)
			out = append(out, Finding{
				Kind:    KindDiskLow,
				Subject: device + " " + mount,
				Title:   fmt.Sprintf("%s: %s neredeyse dolu", device, mount),
				Detail:  fmt.Sprintf("Boş alan %%%d (%s / %s).", pct, humanBytes(v.Free), humanBytes(v.Size)),
			})
		}
	}
	if b := d.Battery; b != nil {
		if t.BatteryHealthPercent > 0 && b.Health > 0 && b.Health < t.BatteryHealthPercent {
			detail := fmt.Sprintf("Tam şarj kapasitesi tasarım değerinin %%%d'i.", b.Health)
			if b.Cycles > 0 {
				detail += fmt.Sprintf(" Döngü sayısı %d.", b.Cycles)
			}
			out = append(out, Finding{Kind: KindBatteryWorn, Subject: device, Title: device + ": pil yıpranmış", Detail: detail})
		}
		if t.BatteryLowPercent > 0 && b.State == "discharging" && b.Percent > 0 && b.Percent < t.BatteryLowPercent {
			out = append(out, Finding{Kind: KindBatteryLow, Subject: device, Title: fmt.Sprintf("%s: pil %%%d", device, b.Percent)})
		}
	}
	return out
}

func humanBytes(n uint64) string {
	const g = 1 << 30
	if n >= g {
		return fmt.Sprintf("%.1f GiB", float64(n)/g)
	}
	return fmt.Sprintf("%.0f MiB", float64(n)/(1<<20))
}

// ResourceWatcher reports a finding once when it appears and once when it
// clears (disk only), so an inventory refresh every few minutes does not
// repeat the same warning.
type ResourceWatcher struct {
	mu     sync.Mutex
	t      Thresholds
	active map[string]Finding
}

// NewResourceWatcher returns a watcher with thresholds t.
func NewResourceWatcher(t Thresholds) (*ResourceWatcher, error) {
	if err := t.Validate(); err != nil {
		return nil, err
	}
	return &ResourceWatcher{t: t, active: map[string]Finding{}}, nil
}

// Update evaluates one device's fresh inventory and returns new and
// cleared problems as events.
func (w *ResourceWatcher) Update(device string, d *sysinfo.Detail, now time.Time) []Event {
	found := CheckResources(device, d, w.t)
	w.mu.Lock()
	defer w.mu.Unlock()
	cur := map[string]Finding{}
	for _, f := range found {
		cur[f.Kind+"|"+f.Subject] = f
	}
	var out []Event
	keys := make([]string, 0, len(cur))
	for k := range cur {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if _, ok := w.active[k]; ok {
			continue
		}
		f := cur[k]
		sev := SeverityWarning
		if f.Kind == KindBatteryWorn {
			sev = SeverityInfo
		}
		out = append(out, Event{Kind: f.Kind, Severity: sev, Subject: f.Subject, Title: f.Title, Detail: f.Detail, At: now})
	}
	prefix := device
	for k, f := range w.active {
		if f.Subject != device && !hasPrefixWord(f.Subject, prefix) {
			continue
		}
		if _, ok := cur[k]; ok {
			continue
		}
		delete(w.active, k)
		if f.Kind == KindDiskLow {
			out = append(out, Event{Kind: KindDiskOK, Severity: SeverityInfo, Subject: f.Subject, At: now,
				Title: f.Subject + ": boş alan yeniden yeterli"})
		}
	}
	for k, f := range cur {
		w.active[k] = f
	}
	return out
}

func hasPrefixWord(s, prefix string) bool {
	return len(s) > len(prefix) && s[:len(prefix)] == prefix && s[len(prefix)] == ' '
}
