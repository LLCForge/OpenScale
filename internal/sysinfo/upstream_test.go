package sysinfo

import (
	"strings"
	"testing"
	"time"
)

func TestUpstreamRoundTrip(t *testing.T) {
	SetUpstream(func() (UpstreamState, bool) {
		return UpstreamState{Label: "Mullvad · İsveç", Mode: UpstreamTunnel, LastHandshake: 1_790_000_000}, true
	})
	defer SetUpstream(nil)
	in := Collect(time.Unix(1_790_000_100, 0))
	data, err := in.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.UpstreamLabel != "Mullvad · İsveç" || got.UpstreamMode != UpstreamTunnel || got.UpstreamHandshake != 1_790_000_000 {
		t.Fatalf("upstream fields: %+v", got)
	}
	if !strings.Contains(string(data), `"xm":"tunnel"`) {
		t.Fatalf("encoded form: %s", data)
	}
}

func TestUpstreamNotConfigured(t *testing.T) {
	SetUpstream(func() (UpstreamState, bool) { return UpstreamState{}, false })
	defer SetUpstream(nil)
	data, err := Collect(time.Unix(1, 0)).Encode()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"xm"`) || strings.Contains(string(data), `"xu"`) {
		t.Fatalf("upstream fields without an upstream exit: %s", data)
	}
}

func TestUpstreamSanitize(t *testing.T) {
	bad, err := Decode([]byte(`{"xu":"x","xm":"route-all","xh":5}`))
	if err != nil {
		t.Fatal(err)
	}
	if bad.UpstreamLabel != "" || bad.UpstreamMode != "" || bad.UpstreamHandshake != 0 {
		t.Fatalf("unknown mode kept: %+v", bad)
	}
	long, err := Decode([]byte(`{"xu":"` + strings.Repeat("ş", 40) + `\u0007","xm":"blocked","xh":-3}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(long.UpstreamLabel) > maxUpstreamLabel || strings.Contains(long.UpstreamLabel, "\a") || long.UpstreamMode != UpstreamBlocked || long.UpstreamHandshake != 0 {
		t.Fatalf("not sanitized: %+v", long)
	}
}

func TestUpstreamPanicKeepsReport(t *testing.T) {
	SetUpstream(func() (UpstreamState, bool) { panic("manager gone") })
	defer SetUpstream(nil)
	if in := Collect(time.Unix(1, 0)); in.UpstreamMode != "" || in.OS == "" {
		t.Fatalf("report after a panicking source: %+v", in)
	}
}

func TestUpstreamDroppedBeforeInventoryAnnouncement(t *testing.T) {
	in := Info{
		OS: "linux", OSName: strings.Repeat("a", maxText), CPU: strings.Repeat("b", maxText), Version: strings.Repeat("c", maxText),
		Arch: strings.Repeat("d", maxText), PublicIP: strings.Repeat("e", maxText), SSHHostKey: "SHA256:" + strings.Repeat("f", 56),
		WakeMAC: "02:00:00:00:00:01", MemTotal: 1 << 62, MemFree: 1 << 62, DiskTotal: 1 << 62, DiskFree: 1 << 62,
		DetailVer: DetailVersion, DetailID: strings.Repeat("0", detailIDLen),
		UpstreamLabel: strings.Repeat("g", maxUpstreamLabel), UpstreamMode: UpstreamDirect, UpstreamHandshake: 1_790_000_000,
	}
	data, err := in.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > MaxEncoded {
		t.Fatalf("%d bytes", len(data))
	}
	got, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.UpstreamMode != "" || got.DetailID != in.DetailID {
		t.Fatalf("the upstream fields must go before the inventory announcement: %s", data)
	}
}
