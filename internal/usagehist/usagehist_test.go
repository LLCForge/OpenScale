package usagehist

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestTrafficDeltasAndReset(t *testing.T) {
	tr := NewTraffic()
	t0 := time.Date(2026, 10, 30, 10, 5, 0, 0, time.UTC)
	tr.Observe("nas", 1000, 500, t0) // baseline only
	if tr.Dirty() || len(tr.Devices()) != 0 {
		t.Fatal("baseline counted")
	}
	tr.Observe("nas", 1600, 700, t0.Add(10*time.Minute))
	tr.Observe("nas", 1700, 700, t0.Add(70*time.Minute)) // next hour
	tr.Observe("nas", 50, 20, t0.Add(80*time.Minute))    // tunnel restarted
	s := tr.Series("nas", 3, t0.Add(80*time.Minute))
	if len(s) != 3 || s[0].Rx != 0 || s[1].Rx != 600 || s[1].Tx != 200 || s[2].Rx != 150 || s[2].Tx != 20 {
		t.Fatalf("series: %+v", s)
	}
	if !s[2].Hour.Equal(time.Date(2026, 10, 30, 11, 0, 0, 0, time.UTC)) {
		t.Fatalf("hour: %v", s[2].Hour)
	}
	rx, tx := tr.Total("nas", 24, t0.Add(80*time.Minute))
	if rx != 750 || tx != 220 {
		t.Fatalf("total %d %d", rx, tx)
	}
	// Ignored input.
	tr.Observe("", 1, 1, t0)
	tr.Observe(string(make([]byte, 200)), 1, 1, t0)
}

func TestTrafficRetentionAndLimit(t *testing.T) {
	tr := NewTraffic()
	t0 := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	tr.Observe("a", 0, 0, t0)
	tr.Observe("a", 10, 10, t0.Add(time.Minute))
	later := t0.Add(31 * 24 * time.Hour)
	tr.Observe("a", 20, 20, later)
	s := tr.Series("a", RetainHours, later)
	var sum uint64
	for _, p := range s {
		sum += p.Rx
	}
	if sum != 10 {
		t.Fatalf("old hour kept: %d", sum)
	}
	for i := range MaxDevices + 10 {
		name := fmt.Sprintf("d%d", i)
		tr.Observe(name, 0, 0, later)
		tr.Observe(name, 1, 1, later)
	}
	if n := len(tr.Devices()); n > MaxDevices {
		t.Fatalf("devices %d", n)
	}
	tr.Forget(func(string) bool { return false })
	if len(tr.last) != 0 {
		t.Fatal("baselines not forgotten")
	}
}

func TestTrafficEncodeDecode(t *testing.T) {
	tr := NewTraffic()
	now := time.Date(2026, 10, 30, 10, 0, 0, 0, time.UTC)
	tr.Observe("nas", 0, 0, now)
	tr.Observe("nas", 123, 456, now)
	data, err := tr.Encode()
	if err != nil || tr.Dirty() {
		t.Fatal(err)
	}
	back, err := DecodeTraffic(data, now)
	if err != nil {
		t.Fatal(err)
	}
	if rx, tx := back.Total("nas", 1, now); rx != 123 || tx != 456 {
		t.Fatalf("round trip %d %d", rx, tx)
	}
	for _, bad := range []string{"", "{}", `{"schema":2,"devices":{}}`, `{"schema":1,"devices":{"":[]}}`, `{"schema":1,"devices":{},"x":1}`, `{"schema":1,"devices":{"a":[[99999999999,1,1]]}}`} {
		if _, err := DecodeTraffic([]byte(bad), now); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestResources(t *testing.T) {
	cpu := time.Duration(0)
	on := true
	r := NewResources(Probe{
		CPU:     func() (time.Duration, bool) { return cpu, true },
		Battery: func() Battery { v := on; return Battery{OnBattery: &v} },
		Mem:     func() (uint64, uint64, int) { return 1 << 20, 4 << 20, 12 },
	})
	t0 := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	r.Sample(t0) // baseline
	if len(r.Samples()) != 0 {
		t.Fatal("baseline stored")
	}
	cpu = 3 * time.Second
	r.Sample(t0.Add(time.Minute)) // 3s of 60s = 5%
	on = false
	cpu = 3*time.Second + 600*time.Millisecond
	r.Sample(t0.Add(2 * time.Minute)) // 1%
	s := r.Summarize()
	if s.Samples != 2 || s.MaxCPUPercent < 4.99 || s.MaxCPUPercent > 5.01 || s.AvgCPUPercent < 2.99 || s.AvgCPUPercent > 3.01 {
		t.Fatalf("summary %+v", s)
	}
	if s.BatteryShare == nil || *s.BatteryShare != 0.5 || s.CPUSecondsOnBattery != 3 || !s.CPUTimeKnown {
		t.Fatalf("battery %+v", s)
	}
	for i := range MaxSamples + 5 {
		r.Sample(t0.Add(time.Duration(i+3) * time.Minute))
	}
	if len(r.Samples()) != MaxSamples {
		t.Fatalf("ring %d", len(r.Samples()))
	}
}

func TestSystemProbe(t *testing.T) {
	p := SystemProbe()
	heap, sys, g := p.Mem()
	if heap == 0 || sys == 0 || g == 0 {
		t.Fatal("mem")
	}
	if runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		if d, ok := p.CPU(); !ok || d <= 0 {
			t.Fatalf("cpu %v %v", d, ok)
		}
	}
	_ = p.Battery() // unknown on desktops; must not fail
}

func TestLinuxBatteryParsing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("probe_unix.go")
	}
	dir := t.TempDir()
	write := func(name, value string) {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(value+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("BAT0/type", "Battery")
	write("BAT0/capacity", "81")
	write("BAT0/status", "Discharging")
	b := linuxBatteryForTest(dir)
	if b.Percent == nil || *b.Percent != 81 || b.OnBattery == nil || !*b.OnBattery {
		t.Fatalf("battery %+v", b)
	}
}
