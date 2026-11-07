package usagehist

import (
	"runtime"
	"sync"
	"time"
)

// Limits of the resource history.
const (
	// SampleEvery is how often the service samples its own cost.
	SampleEvery = 5 * time.Minute
	// MaxSamples keeps one day of samples.
	MaxSamples = int(24 * time.Hour / SampleEvery)
)

// Battery is the power state at a sample; nil fields are unknown.
type Battery struct {
	// OnBattery is true while the computer runs on battery.
	OnBattery *bool `json:"onBattery,omitempty"`
	// Percent is the charge left, 0-100.
	Percent *int `json:"percent,omitempty"`
}

// Sample is OpenScale's cost over one interval.
type Sample struct {
	At time.Time `json:"at"`
	// CPUPercent is the share of one processor core used since the
	// previous sample (100 = one core fully busy).
	CPUPercent float64 `json:"cpuPercent"`
	// CPUSeconds is the processor time used since the previous sample.
	CPUSeconds float64 `json:"cpuSeconds"`
	HeapBytes  uint64  `json:"heapBytes"`
	SysBytes   uint64  `json:"sysBytes"`
	Goroutines int     `json:"goroutines"`
	Battery
}

// Summary sums up the samples.
type Summary struct {
	Samples       int     `json:"samples"`
	AvgCPUPercent float64 `json:"avgCpuPercent"`
	MaxCPUPercent float64 `json:"maxCpuPercent"`
	MaxHeapBytes  uint64  `json:"maxHeapBytes"`
	LastSysBytes  uint64  `json:"lastSysBytes"`
	// CPUSecondsOnBattery is processor time used while on battery: the
	// part of OpenScale's cost that drained the battery.
	CPUSecondsOnBattery float64 `json:"cpuSecondsOnBattery"`
	// BatteryShare is the share of samples taken on battery (0-1); nil
	// when the power state is unknown (desktops, servers).
	BatteryShare *float64 `json:"batteryShare,omitempty"`
	// CPUTimeKnown is false where the process's processor time cannot be
	// read; CPU figures are then zero.
	CPUTimeKnown bool `json:"cpuTimeKnown"`
}

// Probe reads the process and power state; tests replace it.
type Probe struct {
	// CPU returns the process's total processor time; ok false when the
	// system cannot tell.
	CPU     func() (time.Duration, bool)
	Battery func() Battery
	Mem     func() (heap, sys uint64, goroutines int)
}

// SystemProbe reads this process and this computer.
func SystemProbe() Probe {
	return Probe{CPU: processCPU, Battery: batteryState, Mem: goMem}
}

func goMem() (uint64, uint64, int) {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.HeapAlloc, ms.Sys, runtime.NumGoroutine()
}

// Resources is the ring of samples, safe for concurrent use.
type Resources struct {
	mu      sync.Mutex
	probe   Probe
	samples []Sample
	lastCPU time.Duration
	lastAt  time.Time
	cpuOK   bool
}

// NewResources returns an empty history using probe.
func NewResources(p Probe) *Resources {
	if p.CPU == nil {
		p.CPU = func() (time.Duration, bool) { return 0, false }
	}
	if p.Battery == nil {
		p.Battery = func() Battery { return Battery{} }
	}
	if p.Mem == nil {
		p.Mem = goMem
	}
	return &Resources{probe: p}
}

// Sample takes one sample at now. The first call only sets the baseline
// of the processor time.
func (r *Resources) Sample(now time.Time) {
	cpu, ok := r.probe.CPU()
	heap, sys, gor := r.probe.Mem()
	bat := r.probe.Battery()
	r.mu.Lock()
	defer r.mu.Unlock()
	first := r.lastAt.IsZero()
	s := Sample{At: now.UTC(), HeapBytes: heap, SysBytes: sys, Goroutines: gor, Battery: bat}
	if ok && !first && r.cpuOK && now.After(r.lastAt) && cpu >= r.lastCPU {
		used := cpu - r.lastCPU
		s.CPUSeconds = used.Seconds()
		s.CPUPercent = 100 * used.Seconds() / now.Sub(r.lastAt).Seconds()
	}
	r.lastCPU, r.lastAt, r.cpuOK = cpu, now, ok
	if first {
		return
	}
	r.samples = append(r.samples, s)
	if len(r.samples) > MaxSamples {
		r.samples = append(r.samples[:0:0], r.samples[len(r.samples)-MaxSamples:]...)
	}
}

// Samples returns a copy of the samples, oldest first.
func (r *Resources) Samples() []Sample {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Sample(nil), r.samples...)
}

// Summarize sums the samples up.
func (r *Resources) Summarize() Summary {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := Summary{Samples: len(r.samples), CPUTimeKnown: r.cpuOK}
	var total float64
	known, onBattery := 0, 0
	for _, x := range r.samples {
		total += x.CPUPercent
		s.MaxCPUPercent = max(s.MaxCPUPercent, x.CPUPercent)
		s.MaxHeapBytes = max(s.MaxHeapBytes, x.HeapBytes)
		s.LastSysBytes = x.SysBytes
		if x.OnBattery != nil {
			known++
			if *x.OnBattery {
				onBattery++
				s.CPUSecondsOnBattery += x.CPUSeconds
			}
		}
	}
	if len(r.samples) > 0 {
		s.AvgCPUPercent = total / float64(len(r.samples))
	}
	if known > 0 {
		share := float64(onBattery) / float64(known)
		s.BatteryShare = &share
	}
	return s
}
