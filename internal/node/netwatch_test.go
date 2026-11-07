package node

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// fakeNet is a network fingerprint source the test changes at will.
type fakeNet struct {
	fp  string
	err error
}

func (f *fakeNet) probe() (string, error) { return f.fp, f.err }

func TestNetWatcherDetectsChangesAndWake(t *testing.T) {
	src := &fakeNet{fp: "wlan0|192.168.1.5"}
	w := newNetWatcher(src.probe, 2*time.Second)
	t0 := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

	if ev := w.check(t0); ev != 0 {
		t.Fatalf("first check reported %v", ev)
	}
	if ev := w.check(t0.Add(2 * time.Second)); ev != 0 {
		t.Fatalf("steady state reported %v", ev)
	}
	// Moving to another network.
	src.fp = "eth0|10.0.0.7"
	if ev := w.check(t0.Add(4 * time.Second)); ev != netChanged {
		t.Fatalf("address change reported %v", ev)
	}
	// A failing probe is not a change, and the last good state is kept.
	src.err = errors.New("no interfaces")
	if ev := w.check(t0.Add(6 * time.Second)); ev != 0 {
		t.Fatalf("probe error reported %v", ev)
	}
	src.err = nil
	if ev := w.check(t0.Add(8 * time.Second)); ev != 0 {
		t.Fatalf("same network after an error reported %v", ev)
	}
	// A late tick within the slack is not a wake.
	if ev := w.check(t0.Add(14 * time.Second)); ev != 0 {
		t.Fatalf("late tick reported %v", ev)
	}
	// The computer slept for an hour and woke on another network.
	src.fp = "wlan0|172.20.1.9"
	if ev := w.check(t0.Add(time.Hour)); ev != netChanged|netWoke {
		t.Fatalf("wake on a new network reported %v", ev)
	}
	// The clock was set back.
	if ev := w.check(t0.Add(30 * time.Minute)); ev != netWoke {
		t.Fatalf("backward clock jump reported %v", ev)
	}
	if s := (netChanged | netWoke).String(); s != "address change+wake" {
		t.Fatalf("String %q", s)
	}
}

func TestNetWatcherIgnoresMonotonicClock(t *testing.T) {
	// time.Now carries a monotonic reading that stops during sleep on most
	// systems; the watcher must compare wall clock time only.
	src := &fakeNet{fp: "x"}
	w := newNetWatcher(src.probe, 2*time.Second)
	now := time.Now()
	w.check(now)
	if ev := w.check(now.Add(2 * time.Second)); ev != 0 {
		t.Fatalf("regular tick reported %v", ev)
	}
	if ev := w.check(now.Add(10 * time.Minute)); ev&netWoke == 0 {
		t.Fatal("long gap not reported as a wake")
	}
}

func TestSignalNetworkMergesEvents(t *testing.T) {
	e := &Engine{netWake: make(chan struct{}, 1)}
	e.signalNetwork(netChanged)
	e.signalNetwork(netWoke)
	select {
	case <-e.netWake:
	default:
		t.Fatal("run loop not woken")
	}
	if ev := e.takeNetwork(); ev != netChanged|netWoke {
		t.Fatalf("pending %v", ev)
	}
	if ev := e.takeNetwork(); ev != 0 {
		t.Fatalf("pending not cleared: %v", ev)
	}
}

func TestInterfaceFingerprintSkipsLoopbackAndOverlay(t *testing.T) {
	probe := interfaceFingerprint("OpenScale", func() []netip.Prefix {
		return []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")}
	})
	fp, err := probe()
	if err != nil {
		t.Skipf("no interface list on this system: %v", err)
	}
	for _, part := range strings.Split(fp, ",") {
		if part == "" {
			continue
		}
		_, addr, ok := strings.Cut(part, "|")
		if !ok {
			t.Fatalf("malformed entry %q", part)
		}
		if p, err := netip.ParsePrefix(addr); err == nil {
			if p.Bits() != 64 || !p.Addr().Is6() {
				t.Fatalf("IPv6 entry %q is not a /64", part)
			}
			continue
		}
		a, err := netip.ParseAddr(addr)
		if err != nil {
			t.Fatalf("unparsable entry %q", part)
		}
		if a.IsLoopback() || a.IsLinkLocalUnicast() || netip.MustParsePrefix("100.64.0.0/10").Contains(a) {
			t.Fatalf("entry %q should be skipped", part)
		}
	}
	again, err := probe()
	if err != nil || again != fp {
		t.Fatalf("fingerprint not stable: %q vs %q (%v)", fp, again, err)
	}
}
