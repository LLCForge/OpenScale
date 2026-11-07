package node

import (
	"context"
	"net/netip"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/wgconf"
)

func quotaDevices() []trust.Device {
	var a, b trust.Device
	a.Name, a.IPv4, a.IPv6 = "laptop", netip.MustParseAddr("100.80.0.2"), netip.MustParseAddr("fd7a::2")
	b.Name, b.IPv4 = "phone", netip.MustParseAddr("100.80.0.3")
	a.WireGuardKey[0], b.WireGuardKey[0] = 1, 2
	return []trust.Device{a, b}
}

func TestExitQuotaMemberLimit(t *testing.T) {
	devs := quotaDevices()
	path := filepath.Join(t.TempDir(), "exit-quota.json")
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	cfg := ExitQuotaConfig{MemberLimit: 1000, StatePath: path, Now: func() time.Time { return now }, Block: func(context.Context, []netip.Addr) error { return nil }}
	q := newExitQuota(cfg)
	stats := map[trust.Key]wgconf.PeerStatus{
		devs[0].WireGuardKey: {RxBytes: 300, TxBytes: 200},
		devs[1].WireGuardKey: {RxBytes: 10},
	}
	if b := q.step(now, stats, devs); len(b) != 0 {
		t.Fatalf("blocked early: %v", b)
	}
	if u := q.st.Members["laptop"]; u == nil || u.Bytes != 500 || u.Warned {
		t.Fatalf("laptop: %+v", u)
	}
	stats[devs[0].WireGuardKey] = wgconf.PeerStatus{RxBytes: 600, TxBytes: 250}
	q.step(now, stats, devs)
	if u := q.st.Members["laptop"]; u.Bytes != 850 || !u.Warned || u.Blocked {
		t.Fatalf("laptop at 85%%: %+v", u)
	}
	stats[devs[0].WireGuardKey] = wgconf.PeerStatus{RxBytes: 800, TxBytes: 250}
	got := q.step(now, stats, devs)
	want := []netip.Addr{netip.MustParseAddr("100.80.0.2"), netip.MustParseAddr("fd7a::2")}
	if !slices.Equal(got, want) {
		t.Fatalf("blocked %v, want %v", got, want)
	}
	if err := q.save(now); err != nil {
		t.Fatal(err)
	}

	// Restart: the counters start from zero, the month's count stays.
	q2 := newExitQuota(cfg)
	stats = map[trust.Key]wgconf.PeerStatus{devs[0].WireGuardKey: {RxBytes: 5}}
	if got := q2.step(now.Add(time.Hour), stats, devs); !slices.Equal(got, want) {
		t.Fatalf("block lost after restart: %v", got)
	}
	if u := q2.st.Members["laptop"]; u.Bytes != 1055 {
		t.Fatalf("restart count: %+v", u)
	}

	// A new month lifts the block.
	if got := q2.step(time.Date(2026, 11, 1, 0, 0, 1, 0, time.UTC), stats, devs); len(got) != 0 {
		t.Fatalf("still blocked in a new month: %v", got)
	}
	if q2.st.Month != "2026-11" || q2.st.Total != 0 {
		t.Fatalf("new month state: %+v", q2.st)
	}
}

func TestExitQuotaTotalLimit(t *testing.T) {
	devs := quotaDevices()
	q := newExitQuota(ExitQuotaConfig{TotalLimit: 100, StatePath: filepath.Join(t.TempDir(), "q.json"),
		Block: func(context.Context, []netip.Addr) error { return nil }})
	stats := map[trust.Key]wgconf.PeerStatus{devs[1].WireGuardKey: {RxBytes: 150}}
	got := q.step(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), stats, devs)
	if len(got) != 3 || !q.st.TotalBlocked {
		t.Fatalf("total limit: %v %+v", got, q.st)
	}
}

func TestExitQuotaConfigValidate(t *testing.T) {
	ok := ExitQuotaConfig{MemberLimit: 1, StatePath: "x", Block: func(context.Context, []netip.Addr) error { return nil }}
	if err := ok.validate(); err != nil {
		t.Fatal(err)
	}
	for _, c := range []ExitQuotaConfig{
		{StatePath: "x", Block: ok.Block},
		{MemberLimit: 1, WarnPercent: 100, StatePath: "x", Block: ok.Block},
		{MemberLimit: 1, Block: ok.Block},
		{MemberLimit: 1, StatePath: "x"},
	} {
		if c.validate() == nil {
			t.Errorf("accepted %+v", c)
		}
	}
}
