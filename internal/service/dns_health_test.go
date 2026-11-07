package service

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/osnet"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/trust"
)

// A setting another program replaced is applied again at once (F-061).
func TestDNSWatchRepairsOverwrittenSettings(t *testing.T) {
	rec := &recordedApply{}
	var overwritten, repairs, verifies atomic.Int32
	w := DNSWatch{
		Magic:    osnet.DNSConfig{Interface: "OpenScale", Server: netip.MustParseAddr("100.80.255.254"), Domain: "openscale.internal"},
		Document: dnsDoc,
		Apply:    rec.apply,
		Verify: func(context.Context, osnet.DNSConfig, osnet.NetworkDNS) error {
			verifies.Add(1)
			if overwritten.CompareAndSwap(1, 0) {
				return osnet.ErrDNSOverwritten
			}
			return nil
		},
		VerifyEvery: time.Millisecond,
		OnRepair:    func(error) { repairs.Add(1) },
		Every:       5 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	waitFor(t, "first apply", 2*time.Second, func() bool { return len(rec.snapshot()) == 1 })
	waitFor(t, "verification", 2*time.Second, func() bool { return verifies.Load() > 1 })
	overwritten.Store(1)
	waitFor(t, "repair", 2*time.Second, func() bool { return len(rec.snapshot()) == 2 && repairs.Load() == 1 })
	time.Sleep(30 * time.Millisecond)
	if n := len(rec.snapshot()); n != 2 {
		t.Fatalf("intact settings applied again: %d calls", n)
	}
}

// Without the network's settings MagicDNS still routes everything through
// the exit node, and search domains follow the document (ADR-0034).
func TestNetworkDNSForSearchAndExit(t *testing.T) {
	doc := dnsDoc()
	doc.DNSDomain = "openscale.internal"
	doc.MagicDNS = &trust.MagicDNSSettings{Search: []string{"openscale.internal", "ev.lan"}}
	n := NetworkDNSFor(doc, true)
	if !n.ExitActive || len(n.Search) != 2 {
		t.Fatalf("%+v", n)
	}
	w := DNSWatch{Document: func() *trust.Document { return doc }, ExitActive: func() bool { return true }, Accept: func() bool { return false }}
	got := w.wanted()
	if !got.ExitActive || len(got.Search) != 0 || len(got.Split) != 0 || len(got.Overlay) != 2 {
		t.Fatalf("refused settings: %+v", got)
	}
}

func TestDNSHealthAlerts(t *testing.T) {
	r := &Runtime{cfg: Config{Now: func() time.Time { return time.Unix(5000, 0) }}}
	r.cfg.Hooks.DNSStatus = func(string) osnet.DNSSystemStatus { return osnet.DNSSystemStatus{GroupPolicyNRPT: true} }
	r.netDNSErr = describeDNSErr(errors.New("powershell yok"))
	r.dnsHealth.repairs, r.dnsHealth.lastRepair = 2, time.Unix(4900, 0)
	codes := map[string]bool{}
	for _, a := range r.dnsAlertsLocked(time.Unix(5000, 0)) {
		codes[a.Code] = true
	}
	for _, c := range []string{panel.HealthDNSNetworkFailed, panel.HealthDNSOverwritten, panel.HealthDNSGroupPolicy} {
		if !codes[c] {
			t.Errorf("alert %s missing: %v", c, codes)
		}
	}
	// An old repair is not shown any more.
	r.dnsHealth.lastRepair = time.Unix(0, 0)
	for _, a := range r.dnsAlertsLocked(time.Unix(5000, 0)) {
		if a.Code == panel.HealthDNSOverwritten {
			t.Fatal("old repair still shown")
		}
	}
}
