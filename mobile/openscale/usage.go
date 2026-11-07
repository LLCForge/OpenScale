package openscale

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"github.com/openscale/openscale/internal/securefile"
)

// Mobile data usage counter (#471, P08). The app samples Android's per-UID
// traffic counters (TrafficStats for its own UID: the WireGuard tunnel,
// relays, the coordinator and every other socket of the app, which is kept
// out of its own VPN) and hands the deltas here with the network kind they
// were measured on. Totals are kept per calendar month (the month key comes
// from the app, in the phone's time zone) and per kind; nothing leaves the
// phone. UsageCheck turns them into the threshold state the metered
// connection mode (#385) reads.

const (
	maxUsageFile   = 64 << 10
	maxUsageMonths = 13
	// maxUsageDelta bounds one sample; a larger delta means a counter
	// glitch, not traffic.
	maxUsageDelta = 1 << 40
	usageWarnPct  = 80
)

var usageMu sync.Mutex

type usageBytes struct {
	Rx uint64 `json:"rx"`
	Tx uint64 `json:"tx"`
}

type usageMonth struct {
	Month    string     `json:"month"`
	WiFi     usageBytes `json:"wifi"`
	Cellular usageBytes `json:"cellular"`
	Other    usageBytes `json:"other"`
}

type usageFile struct {
	Version int          `json:"version"`
	Months  []usageMonth `json:"months"`
}

func checkUsagePath(path string) error {
	if checkStateDir(path) != nil || filepath.Dir(path) == path {
		return errors.New("kullanım dosyası mutlak ve temiz bir yol olmalı")
	}
	return nil
}

// validMonth accepts "YYYY-MM".
func validMonth(m string) bool {
	if len(m) != 7 || m[4] != '-' {
		return false
	}
	for i, c := range []byte(m) {
		if i != 4 && (c < '0' || c > '9') {
			return false
		}
	}
	mm := int(m[5]-'0')*10 + int(m[6]-'0')
	return mm >= 1 && mm <= 12
}

// loadUsage reads the counter file. A missing file is empty; a damaged one
// starts over (the counter is informational, never a security decision).
func loadUsage(path string) usageFile {
	data, err := securefile.ReadLimited(path, maxUsageFile)
	if err != nil {
		return usageFile{Version: 1}
	}
	var f usageFile
	if json.Unmarshal(data, &f) != nil || f.Version != 1 || len(f.Months) > maxUsageMonths {
		return usageFile{Version: 1}
	}
	for _, m := range f.Months {
		if !validMonth(m.Month) {
			return usageFile{Version: 1}
		}
	}
	return f
}

func satAdd(a, b uint64) uint64 {
	if a > math.MaxUint64-b {
		return math.MaxUint64
	}
	return a + b
}

// UsageAdd adds rx/tx bytes measured on network (wifi, cellular; anything
// else counts as other) to month ("YYYY-MM") in the counter file at path.
// Only the last 13 months are kept.
func UsageAdd(path, month, network string, rx, tx int) error {
	if err := checkUsagePath(path); err != nil {
		return err
	}
	if !validMonth(month) {
		return fmt.Errorf("geçersiz ay %q (YYYY-AA)", month)
	}
	if rx < 0 || tx < 0 || rx > maxUsageDelta || tx > maxUsageDelta {
		return errors.New("geçersiz kullanım miktarı")
	}
	if rx == 0 && tx == 0 {
		return nil
	}
	usageMu.Lock()
	defer usageMu.Unlock()
	f := loadUsage(path)
	i := slices.IndexFunc(f.Months, func(m usageMonth) bool { return m.Month == month })
	if i < 0 {
		f.Months = append(f.Months, usageMonth{Month: month})
		slices.SortFunc(f.Months, func(a, b usageMonth) int {
			switch {
			case a.Month < b.Month:
				return -1
			case a.Month > b.Month:
				return 1
			}
			return 0
		})
		if n := len(f.Months); n > maxUsageMonths {
			f.Months = f.Months[n-maxUsageMonths:]
		}
		i = slices.IndexFunc(f.Months, func(m usageMonth) bool { return m.Month == month })
		if i < 0 {
			// Older than every kept month: not worth keeping.
			return nil
		}
	}
	m := &f.Months[i]
	var b *usageBytes
	switch network {
	case netWiFi:
		b = &m.WiFi
	case netCellular:
		b = &m.Cellular
	default:
		b = &m.Other
	}
	b.Rx, b.Tx = satAdd(b.Rx, uint64(rx)), satAdd(b.Tx, uint64(tx))
	out, err := json.Marshal(f)
	if err != nil {
		return err
	}
	return securefile.Replace(path, out)
}

// UsageSummary returns the kept months as JSON:
// {"version":1,"months":[{"month":"2026-10","wifi":{"rx":..,"tx":..},
// "cellular":{..},"other":{..}}]}, oldest first.
func UsageSummary(path string) (string, error) {
	if err := checkUsagePath(path); err != nil {
		return "", err
	}
	usageMu.Lock()
	f := loadUsage(path)
	usageMu.Unlock()
	if f.Months == nil {
		f.Months = []usageMonth{}
	}
	out, err := json.Marshal(f)
	return string(out), err
}

type usageCheck struct {
	Month         string `json:"month"`
	CellularBytes uint64 `json:"cellular_bytes"`
	LimitBytes    int64  `json:"limit_bytes"`
	Percent       int    `json:"percent"`
	Warn          bool   `json:"warn"`
	Over          bool   `json:"over"`
}

// UsageCheck compares month's cellular total (rx+tx) with limitBytes (0:
// no limit) and returns {"month","cellular_bytes","limit_bytes","percent",
// "warn","over"} as JSON; warn is set from 80 %.
func UsageCheck(path, month string, limitBytes int) (string, error) {
	if err := checkUsagePath(path); err != nil {
		return "", err
	}
	if !validMonth(month) {
		return "", fmt.Errorf("geçersiz ay %q (YYYY-AA)", month)
	}
	if limitBytes < 0 {
		return "", errors.New("sınır negatif olamaz")
	}
	usageMu.Lock()
	f := loadUsage(path)
	usageMu.Unlock()
	c := usageCheck{Month: month, LimitBytes: int64(limitBytes)}
	for _, m := range f.Months {
		if m.Month == month {
			c.CellularBytes = satAdd(m.Cellular.Rx, m.Cellular.Tx)
		}
	}
	if limitBytes > 0 {
		lim := uint64(limitBytes)
		pct := uint64(1000)
		if c.CellularBytes/lim < 10 {
			// No overflow: the quotient is below 10 and the remainder
			// below lim, which is at most MaxInt64.
			pct = c.CellularBytes/lim*100 + c.CellularBytes%lim*100/lim
		}
		c.Percent = int(min(pct, 1000))
		c.Warn = c.Percent >= usageWarnPct
		c.Over = c.CellularBytes >= uint64(limitBytes)
	}
	out, err := json.Marshal(c)
	return string(out), err
}

// UsageReset removes the counter file.
func UsageReset(path string) error {
	if err := checkUsagePath(path); err != nil {
		return err
	}
	usageMu.Lock()
	defer usageMu.Unlock()
	err := os.Remove(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}
