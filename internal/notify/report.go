package notify

import (
	"bytes"
	"fmt"
	"html/template"
	"sort"
	"strings"
	"time"
)

// Weekly report limits: the report lists device names the owner chose and
// counts, never addresses, MAC addresses, domains or user names.
const (
	maxReportDevices    = 10
	maxReportCategories = 12
	maxReportLines      = 20
)

// DeviceWeek is one device's week.
type DeviceWeek struct {
	Name     string
	BytesIn  uint64
	BytesOut uint64
	// Online is the device's state when the report was made; OfflineFor
	// how long it has been unreachable.
	Online     bool
	OfflineFor time.Duration
	// Version and Latest describe a pending update ("" when unknown or
	// up to date).
	Version string
	Latest  string
}

// UpdatePending reports whether the device runs an older version.
func (d DeviceWeek) UpdatePending() bool {
	return d.Latest != "" && d.Version != "" && d.Version != d.Latest
}

// WeeklyInput is what the caller gathered for the week.
type WeeklyInput struct {
	Network string
	From    time.Time
	To      time.Time
	Devices []DeviceWeek
	// Blocked counts blocked DNS answers by category (ads, trackers, ...).
	Blocked map[string]uint64
	// Incidents counts security and health events by kind (port scan,
	// service down, new LAN device, ...).
	Incidents map[string]int
	// ServiceDowntime is each monitored service's downtime in the week.
	ServiceDowntime map[string]time.Duration
}

// Count is a named number in a report.
type Count struct {
	Name  string
	Value uint64
}

// Weekly is the built report.
type Weekly struct {
	Network     string
	From, To    time.Time
	TotalIn     uint64
	TotalOut    uint64
	DeviceCount int
	TopDevices  []DeviceWeek
	Offline     []DeviceWeek
	Updates     []DeviceWeek
	Blocked     []Count
	BlockedSum  uint64
	Incidents   []Count
	Downtime    []Count // seconds
	Generated   time.Time
}

// BuildWeekly sums up in. It never fails; empty inputs give an empty
// report.
func BuildWeekly(in WeeklyInput, now time.Time) Weekly {
	w := Weekly{Network: cleanLine(in.Network), From: in.From, To: in.To, DeviceCount: len(in.Devices), Generated: now}
	devs := append([]DeviceWeek(nil), in.Devices...)
	for i := range devs {
		devs[i].Name = truncate(cleanLine(devs[i].Name), 64)
		w.TotalIn += devs[i].BytesIn
		w.TotalOut += devs[i].BytesOut
	}
	sort.SliceStable(devs, func(i, j int) bool {
		a, b := devs[i].BytesIn+devs[i].BytesOut, devs[j].BytesIn+devs[j].BytesOut
		if a != b {
			return a > b
		}
		return devs[i].Name < devs[j].Name
	})
	for _, d := range devs {
		if len(w.TopDevices) < maxReportDevices && d.BytesIn+d.BytesOut > 0 {
			w.TopDevices = append(w.TopDevices, d)
		}
		if !d.Online && len(w.Offline) < maxReportLines {
			w.Offline = append(w.Offline, d)
		}
		if d.UpdatePending() && len(w.Updates) < maxReportLines {
			w.Updates = append(w.Updates, d)
		}
	}
	sort.SliceStable(w.Offline, func(i, j int) bool { return w.Offline[i].Name < w.Offline[j].Name })
	sort.SliceStable(w.Updates, func(i, j int) bool { return w.Updates[i].Name < w.Updates[j].Name })
	w.Blocked, w.BlockedSum = topCounts(in.Blocked, maxReportCategories)
	inc := make(map[string]uint64, len(in.Incidents))
	for k, v := range in.Incidents {
		if v > 0 {
			inc[k] = uint64(v)
		}
	}
	w.Incidents, _ = topCounts(inc, maxReportLines)
	down := make(map[string]uint64, len(in.ServiceDowntime))
	for k, v := range in.ServiceDowntime {
		if v > 0 {
			down[k] = uint64(v / time.Second)
		}
	}
	w.Downtime, _ = topCounts(down, maxReportLines)
	return w
}

func topCounts(m map[string]uint64, limit int) ([]Count, uint64) {
	var sum uint64
	out := make([]Count, 0, len(m))
	for k, v := range m {
		sum += v
		out = append(out, Count{Name: truncate(cleanLine(k), 64), Value: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Value != out[j].Value {
			return out[i].Value > out[j].Value
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, sum
}

// HumanBytes formats a byte count with binary units.
func HumanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit && exp < 4; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTP"[exp])
}

// HumanDuration formats a duration in days, hours and minutes.
func HumanDuration(d time.Duration) string {
	if d < time.Minute {
		return "1 dakikadan az"
	}
	d = d.Round(time.Minute)
	days := d / (24 * time.Hour)
	d -= days * 24 * time.Hour
	h := d / time.Hour
	m := (d - h*time.Hour) / time.Minute
	var parts []string
	if days > 0 {
		parts = append(parts, fmt.Sprintf("%d gün", days))
	}
	if h > 0 {
		parts = append(parts, fmt.Sprintf("%d saat", h))
	}
	if m > 0 && days == 0 {
		parts = append(parts, fmt.Sprintf("%d dakika", m))
	}
	return strings.Join(parts, " ")
}

// Subject is the report's e-mail subject.
func (w Weekly) Subject() string {
	name := w.Network
	if name == "" {
		name = "Ağ"
	}
	return fmt.Sprintf("%s haftalık raporu (%s - %s)", name, w.From.Format("02.01.2006"), w.To.Format("02.01.2006"))
}

// Text renders the report as plain text.
func (w Weekly) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\n", w.Subject())
	fmt.Fprintf(&b, "Cihaz sayısı: %d\nToplam trafik: %s alınan, %s gönderilen\n", w.DeviceCount, HumanBytes(w.TotalIn), HumanBytes(w.TotalOut))
	if len(w.TopDevices) > 0 {
		b.WriteString("\nEn çok kullanan cihazlar:\n")
		for _, d := range w.TopDevices {
			fmt.Fprintf(&b, "- %s: %s\n", d.Name, HumanBytes(d.BytesIn+d.BytesOut))
		}
	}
	fmt.Fprintf(&b, "\nEngellenen DNS yanıtları: %d\n", w.BlockedSum)
	for _, c := range w.Blocked {
		fmt.Fprintf(&b, "- %s: %d\n", c.Name, c.Value)
	}
	if len(w.Incidents) > 0 {
		b.WriteString("\nOlaylar:\n")
		for _, c := range w.Incidents {
			fmt.Fprintf(&b, "- %s: %d\n", c.Name, c.Value)
		}
	}
	if len(w.Downtime) > 0 {
		b.WriteString("\nServis kesintileri:\n")
		for _, c := range w.Downtime {
			fmt.Fprintf(&b, "- %s: %s\n", c.Name, HumanDuration(time.Duration(c.Value)*time.Second))
		}
	}
	if len(w.Offline) > 0 {
		b.WriteString("\nÇevrimdışı cihazlar:\n")
		for _, d := range w.Offline {
			fmt.Fprintf(&b, "- %s (%s)\n", d.Name, HumanDuration(d.OfflineFor))
		}
	}
	if len(w.Updates) > 0 {
		b.WriteString("\nGüncelleme bekleyenler:\n")
		for _, d := range w.Updates {
			fmt.Fprintf(&b, "- %s: %s -> %s\n", d.Name, cleanLine(d.Version), cleanLine(d.Latest))
		}
	}
	return b.String()
}

var weeklyHTML = template.Must(template.New("weekly").Funcs(template.FuncMap{
	"bytes": HumanBytes,
	"dur":   HumanDuration,
	"secs":  func(v uint64) time.Duration { return time.Duration(v) * time.Second },
	"sum":   func(a, b uint64) uint64 { return a + b },
}).Parse(`<!doctype html>
<html lang="tr"><head><meta charset="utf-8"><title>{{.Subject}}</title></head>
<body style="font-family:sans-serif;line-height:1.5;color:#1d2433;background:#ffffff">
<h1 style="font-size:20px">{{.Subject}}</h1>
<p>Cihaz sayısı: {{.DeviceCount}}. Toplam trafik: {{bytes .TotalIn}} alınan, {{bytes .TotalOut}} gönderilen.</p>
{{if .TopDevices}}<h2 style="font-size:16px">En çok kullanan cihazlar</h2><ul>{{range .TopDevices}}<li>{{.Name}}: {{bytes (sum .BytesIn .BytesOut)}}</li>{{end}}</ul>{{end}}
<h2 style="font-size:16px">Engellenen DNS yanıtları: {{.BlockedSum}}</h2>
{{if .Blocked}}<ul>{{range .Blocked}}<li>{{.Name}}: {{.Value}}</li>{{end}}</ul>{{end}}
{{if .Incidents}}<h2 style="font-size:16px">Olaylar</h2><ul>{{range .Incidents}}<li>{{.Name}}: {{.Value}}</li>{{end}}</ul>{{end}}
{{if .Downtime}}<h2 style="font-size:16px">Servis kesintileri</h2><ul>{{range .Downtime}}<li>{{.Name}}: {{dur (secs .Value)}}</li>{{end}}</ul>{{end}}
{{if .Offline}}<h2 style="font-size:16px">Çevrimdışı cihazlar</h2><ul>{{range .Offline}}<li>{{.Name}} ({{dur .OfflineFor}})</li>{{end}}</ul>{{end}}
{{if .Updates}}<h2 style="font-size:16px">Güncelleme bekleyenler</h2><ul>{{range .Updates}}<li>{{.Name}}: {{.Version}} &rarr; {{.Latest}}</li>{{end}}</ul>{{end}}
<p style="color:#5b6475;font-size:12px">Bu rapor OpenScale tarafından sahibin kendi cihazında üretildi; adres, MAC adresi veya ziyaret edilen alan adı içermez.</p>
</body></html>
`))

// HTML renders the report as an HTML e-mail body; every value is escaped.
func (w Weekly) HTML() (string, error) {
	var b bytes.Buffer
	if err := weeklyHTML.Execute(&b, w); err != nil {
		return "", err
	}
	return b.String(), nil
}

// Message returns the report as a notification for the dispatcher.
func (w Weekly) Message() (Message, error) {
	h, err := w.HTML()
	if err != nil {
		return Message{}, err
	}
	return Message{
		Kind:     "weekly_report",
		Title:    w.Subject(),
		Body:     w.Text(),
		HTML:     h,
		Priority: PriorityLow,
		Key:      "weekly_report|" + w.To.UTC().Format("2006-01-02"),
		At:       w.Generated,
	}, nil
}
