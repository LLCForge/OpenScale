package testnet

import (
	"testing"
	"time"
)

func feed(s *Soak, n int, f func(i int) Sample) {
	t0 := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	for i := range n {
		smp := f(i)
		smp.At = t0.Add(time.Duration(i) * time.Minute)
		s.Add(smp)
	}
}

func TestSoakCheck(t *testing.T) {
	// Flat with noise: no leak.
	var flat Soak
	feed(&flat, 200, func(i int) Sample {
		return Sample{Goroutines: 50 + i%7, HeapBytes: 40<<20 + uint64(i%13)<<20, FDs: 30 + i%3}
	})
	if err := flat.Check(DefaultSoakLimits); err != nil {
		t.Fatalf("flat run: %v", err)
	}
	// One goroutine leaked every few minutes.
	var leak Soak
	feed(&leak, 200, func(i int) Sample { return Sample{Goroutines: 50 + i/5, HeapBytes: 40 << 20, FDs: 30} })
	if err := leak.Check(DefaultSoakLimits); err == nil {
		t.Fatal("goroutine leak not found")
	}
	// Heap growing steadily by 1 MiB a minute.
	var heap Soak
	feed(&heap, 200, func(i int) Sample { return Sample{Goroutines: 50, HeapBytes: 40<<20 + uint64(i)<<20, FDs: -1} })
	if err := heap.Check(DefaultSoakLimits); err == nil {
		t.Fatal("heap growth not found")
	}
	// File descriptors leaking.
	var fds Soak
	feed(&fds, 200, func(i int) Sample { return Sample{Goroutines: 50, HeapBytes: 40 << 20, FDs: 30 + i/4} })
	if err := fds.Check(DefaultSoakLimits); err == nil {
		t.Fatal("fd leak not found")
	}
	// A warm-up spike is ignored.
	var warm Soak
	feed(&warm, 200, func(i int) Sample {
		g := 50
		if i < 15 {
			g = 10 + i*3
		}
		return Sample{Goroutines: g, HeapBytes: 40 << 20, FDs: 30}
	})
	if err := warm.Check(DefaultSoakLimits); err != nil {
		t.Fatalf("warm-up counted: %v", err)
	}
	var short Soak
	feed(&short, 5, func(int) Sample { return Sample{} })
	if err := short.Check(DefaultSoakLimits); err == nil {
		t.Fatal("five samples accepted")
	}
	var live Soak
	if s := live.Take(time.Now()); s.Goroutines < 1 || s.HeapBytes == 0 {
		t.Fatalf("sample %+v", s)
	}
}
