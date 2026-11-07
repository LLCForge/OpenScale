package service

import (
	"context"
	"encoding/base64"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/panel"
)

func TestDDNSSettingsAndCheck(t *testing.T) {
	r := &Runtime{cfg: Config{DataDir: t.TempDir(), Now: time.Now}, logger: slog.New(slog.DiscardHandler)}
	st := r.ddns()
	st.public = func() netip.Addr { return netip.MustParseAddr("192.168.1.2") }
	st.observed = func() (string, netip.Addr, bool) { return "ev.ornek.test", netip.MustParseAddr("203.0.113.9"), true }
	st.lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("198.51.100.4")}, nil
	}
	secret := base64.StdEncoding.EncodeToString([]byte("gizli değer otuz iki bayt uzun!!"))
	bad := []panel.DDNSConfigRequest{
		{Enabled: true, Server: "ns.ornek.test:53", Zone: "ornek.test", Name: "ev.ornek.test", KeyName: "k", Secret: &secret},
		{Enabled: true, Server: "0.0.0.0:53", Zone: "ornek.test", Name: "ev.ornek.test", KeyName: "k", Secret: &secret},
		{Enabled: true, Server: "192.0.2.53:53", Zone: "ornek.test", Name: "ev.baska.test", KeyName: "k", Secret: &secret},
		{Enabled: true, Server: "192.0.2.53:53", Zone: "ornek.test", Name: "ev.ornek.test", KeyName: "k"},
		{Enabled: true, Server: "192.0.2.53:53", Zone: "ornek.test", Name: "ev.ornek.test", KeyName: "k", Algorithm: "hmac-md5", Secret: &secret},
	}
	for i, c := range bad {
		if _, err := r.SetDDNS(c); err == nil {
			t.Errorf("settings %d accepted", i)
		}
	}
	out, err := r.SetDDNS(panel.DDNSConfigRequest{Enabled: true, Server: "192.0.2.53:53", Zone: "ornek.test", Name: "ev.ornek.test", KeyName: "ev-anahtari", Secret: &secret})
	if err != nil || !out.Updater.KeySet || !out.Updater.Enabled {
		t.Fatalf("settings: %+v %v", out, err)
	}
	data, _ := os.ReadFile(r.ddnsPath(ddnsConfigFn))
	if strings.Contains(string(data), secret) {
		t.Fatal("secret stored in the settings file")
	}
	// A private address is never published.
	if err := r.ddnsUpdate(context.Background(), true); err == nil || !strings.Contains(err.Error(), "genel") {
		t.Fatalf("private address: %v", err)
	}
	if err := r.ddnsUpdate(context.Background(), false); err != nil {
		t.Fatalf("scheduled with private address: %v", err)
	}
	v := r.ddnsCheck(context.Background())
	if v == nil || v.Status != "stale" || v.Observed != "203.0.113.9" {
		t.Fatalf("check: %+v", v)
	}
	// Removing the secret keeps the updater off.
	empty := ""
	if _, err := r.SetDDNS(panel.DDNSConfigRequest{Enabled: false, Server: "192.0.2.53:53", Zone: "ornek.test", Name: "ev.ornek.test", KeyName: "k", Secret: &empty}); err != nil {
		t.Fatal(err)
	}
	if out, _ := r.DDNSStatus(); out.Updater.KeySet || out.Check == nil {
		t.Fatalf("after removal: %+v", out)
	}
}
