package service

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestObserverHistories(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	o := NewObserver(ObserverConfig{Dir: dir, Now: clock})

	// Without a tunnel only the resources are sampled.
	o.sampleHistories(now)
	now = now.Add(6 * time.Minute)
	o.sampleHistories(now)
	if rep := o.ResourceUsage(); rep.Summary.Samples != 1 || rep.SampleEverySeconds != 300 || len(rep.Samples) != 1 {
		t.Fatalf("resources: %+v", rep)
	}

	h := o.histories()
	h.traffic.Observe("nas", 0, 0, now)
	h.traffic.Observe("nas", 5000, 700, now)
	rep, err := o.TrafficHistory("nas", 3)
	if err != nil || len(rep.Points) != 3 || rep.Points[2].Rx != 5000 || len(rep.Devices) != 1 || rep.Devices[0].Tx != 700 {
		t.Fatalf("traffic: %+v %v", rep, err)
	}

	// Saved owner-only and read back by the next Observer.
	o.saveHistory(now, true)
	path := filepath.Join(dir, trafficHistoryFile)
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	o2 := NewObserver(ObserverConfig{Dir: dir, Now: clock})
	if rep, _ := o2.TrafficHistory("nas", 1); len(rep.Points) != 1 || rep.Points[0].Rx != 5000 {
		t.Fatalf("reloaded: %+v", rep)
	}

	// A damaged file starts a new history instead of failing.
	if err := os.WriteFile(path, []byte("bozuk"), 0o600); err != nil {
		t.Fatal(err)
	}
	o3 := NewObserver(ObserverConfig{Dir: dir, Now: clock})
	if rep, _ := o3.TrafficHistory("", 24); len(rep.Devices) != 0 {
		t.Fatalf("damaged: %+v", rep)
	}
}
