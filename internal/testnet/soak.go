package testnet

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Long-running stability test support (#575). A Soak samples the process's
// goroutines, heap and open file descriptors while a multi-node network
// runs, and Check decides whether any of them keeps growing. A leak is a
// steady upward trend after warm-up, not a single high sample: the slope
// of a least-squares line through the samples, projected over the whole
// measured span, must stay under the limits.

// Sample is one measurement.
type Sample struct {
	At         time.Time
	Goroutines int
	HeapBytes  uint64
	// FDs is the number of open file descriptors, or -1 where the platform
	// does not expose it cheaply (only Linux does, through /proc).
	FDs int
}

// SoakLimits bounds the growth Check tolerates over the measured span.
type SoakLimits struct {
	Goroutines int     // absolute growth
	HeapRatio  float64 // growth as a fraction of the starting heap
	HeapBytes  uint64  // and at least this many bytes (small heaps are noisy)
	FDs        int     // absolute growth
	// WarmUp skips this fraction of the samples at the start.
	WarmUp float64
}

// DefaultSoakLimits are the release gate of #575.
var DefaultSoakLimits = SoakLimits{Goroutines: 20, HeapRatio: 0.25, HeapBytes: 16 << 20, FDs: 16, WarmUp: 0.1}

// Soak collects samples.
type Soak struct {
	mu      sync.Mutex
	samples []Sample
}

// Take records one sample now.
func (s *Soak) Take(now time.Time) Sample {
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	smp := Sample{At: now, Goroutines: runtime.NumGoroutine(), HeapBytes: ms.HeapInuse, FDs: openFDs()}
	s.Add(smp)
	return smp
}

// Add records a sample taken elsewhere (tests).
func (s *Soak) Add(smp Sample) {
	s.mu.Lock()
	s.samples = append(s.samples, smp)
	s.mu.Unlock()
}

// Samples returns a copy of the samples.
func (s *Soak) Samples() []Sample {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Sample(nil), s.samples...)
}

func openFDs() int {
	if runtime.GOOS != "linux" {
		return -1
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return -1
	}
	return len(entries)
}

// slopeGrowth fits y = a + b*t and returns b times the span: the growth
// the trend predicts from the first to the last sample.
func slopeGrowth(t, y []float64) float64 {
	n := float64(len(t))
	if n < 2 {
		return 0
	}
	var st, sy, stt, sty float64
	for i := range t {
		st += t[i]
		sy += y[i]
		stt += t[i] * t[i]
		sty += t[i] * y[i]
	}
	den := n*stt - st*st
	if den == 0 {
		return 0
	}
	b := (n*sty - st*sy) / den
	return b * (t[len(t)-1] - t[0])
}

// Check reports every resource whose trend grows beyond the limits.
func (s *Soak) Check(l SoakLimits) error {
	all := s.Samples()
	skip := int(float64(len(all)) * l.WarmUp)
	smp := all[skip:]
	if len(smp) < 10 {
		return fmt.Errorf("too few samples after warm-up (%d); run longer", len(smp))
	}
	t := make([]float64, len(smp))
	g := make([]float64, len(smp))
	h := make([]float64, len(smp))
	f := make([]float64, len(smp))
	fdKnown := true
	for i, x := range smp {
		t[i] = x.At.Sub(smp[0].At).Seconds()
		g[i] = float64(x.Goroutines)
		h[i] = float64(x.HeapBytes)
		f[i] = float64(x.FDs)
		if x.FDs < 0 {
			fdKnown = false
		}
	}
	var problems []string
	if d := slopeGrowth(t, g); d > float64(l.Goroutines) {
		problems = append(problems, fmt.Sprintf("goroutine sayısı eğilimi +%.0f (sınır %d)", d, l.Goroutines))
	}
	limit := max(float64(l.HeapBytes), h[0]*l.HeapRatio)
	if d := slopeGrowth(t, h); d > limit {
		problems = append(problems, fmt.Sprintf("yığın eğilimi +%.1f MiB (sınır %.1f MiB)", d/(1<<20), limit/(1<<20)))
	}
	if fdKnown {
		if d := slopeGrowth(t, f); d > float64(l.FDs) {
			problems = append(problems, fmt.Sprintf("açık dosya tanıtıcısı eğilimi +%.0f (sınır %d)", d, l.FDs))
		}
	}
	if len(problems) > 0 {
		return errors.New("sızıntı: " + strings.Join(problems, "; "))
	}
	return nil
}
