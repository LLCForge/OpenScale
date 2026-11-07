package service

import (
	"testing"
	"time"

	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/sysinfo"
	"github.com/openscale/openscale/internal/trust"
)

func TestNetPlacesSwitchDefaultsOn(t *testing.T) {
	dir := t.TempDir()
	if on, err := LoadNetPlacesOn(dir); err != nil || !on {
		t.Fatalf("default = %v, %v", on, err)
	}
	if err := SaveNetPlacesOn(dir, false); err != nil {
		t.Fatal(err)
	}
	if on, err := LoadNetPlacesOn(dir); err != nil || on {
		t.Fatalf("after off = %v, %v", on, err)
	}
	if err := SaveNetPlacesOn(dir, true); err != nil {
		t.Fatal(err)
	}
	if on, _ := LoadNetPlacesOn(dir); !on {
		t.Fatal("switch did not turn on")
	}
}

func TestNetPlaceDevices(t *testing.T) {
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	dev := func(name string, exp time.Time) trust.Device {
		return trust.Device{Name: name, ExpiresAt: exp}
	}
	doc := &trust.Document{DNSDomain: "ev.openscale.internal", Devices: []trust.Device{
		dev("pc", now.Add(time.Hour)),
		dev("nas", now.Add(time.Hour)),
		dev("eski", now.Add(-time.Hour)),
		dev("laptop", now.Add(time.Hour)),
	}}
	inv := panel.Inventory{Devices: map[string]panel.Report{
		"nas":    {Info: sysinfo.Info{Detail: &sysinfo.Detail{Shares: []sysinfo.Share{{Name: "Delta"}}}}},
		"laptop": {Info: sysinfo.Info{}},
		"eski":   {Info: sysinfo.Info{Detail: &sysinfo.Detail{Shares: []sysinfo.Share{{Name: "x"}}}}},
		// Not in the document: never listed.
		"yabanci": {Info: sysinfo.Info{Detail: &sysinfo.Detail{Shares: []sysinfo.Share{{Name: "y"}}}}},
	}}
	got := netPlaceDevices(doc, "pc", inv, now)
	if len(got) != 2 || got[0].Name != "laptop" || got[1].Name != "nas" {
		t.Fatalf("devices = %+v", got)
	}
	if got[0].Known || len(got[0].Shares) != 0 {
		t.Fatalf("laptop = %+v", got[0])
	}
	if !got[1].Known || got[1].Host != "nas.ev.openscale.internal" || len(got[1].Shares) != 1 || got[1].Shares[0].Name != "Delta" {
		t.Fatalf("nas = %+v", got[1])
	}
	if netPlaceDevices(nil, "pc", inv, now) != nil {
		t.Fatal("devices without a document")
	}
}
