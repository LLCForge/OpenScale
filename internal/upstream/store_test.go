package upstream

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestStoreImportUseList(t *testing.T) {
	st, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := testKeys(t)
	_, peer := testKeys(t)
	conf := []byte(mullvadStyle(priv, peer, "198.51.100.20:51820"))
	if _, err := st.Import("se-got", "Mullvad · İsveç", conf, false); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Import("se-got", "", conf, false); err == nil {
		t.Fatal("existing profile replaced without replace")
	}
	if _, err := st.Import("Bad Name", "", conf, false); err == nil {
		t.Fatal("bad name accepted")
	}
	if _, err := st.Import("x", "etiket\x07", conf, false); err == nil {
		t.Fatal("control character in label accepted")
	}

	path := filepath.Join(st.Dir(), "se-got.conf")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "Neat Otter") {
		t.Fatal("comment stored")
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("profile mode %v", info.Mode().Perm())
		}
		dinfo, _ := os.Stat(st.Dir())
		if dinfo.Mode().Perm() != 0o700 {
			t.Fatalf("folder mode %v", dinfo.Mode().Perm())
		}
		// A key file other users can read is refused, like device.key.
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := st.Load("se-got"); err == nil {
			t.Fatal("world-readable profile loaded")
		}
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if err := st.Use("yok"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Use(unknown) = %v", err)
	}
	if err := st.Use("se-got"); err != nil {
		t.Fatal(err)
	}
	list, err := st.List()
	if err != nil || len(list) != 1 {
		t.Fatalf("list %v %v", list, err)
	}
	p := list[0]
	if !p.Active || p.Label != "Mullvad · İsveç" || p.Endpoint.String() != "198.51.100.20:51820" || p.PublicKey == "" || p.DNS[0] != "10.64.0.1" {
		t.Fatalf("profile %+v", p)
	}
	if err := st.Remove("se-got"); err == nil {
		t.Fatal("active profile removed")
	}
	if err := st.UpdateSettings(func(s *Settings) error { s.Active = ""; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := st.Remove("se-got"); err != nil {
		t.Fatal(err)
	}
	s, _ := st.Settings()
	if len(s.Labels) != 0 {
		t.Fatalf("label kept after removal: %v", s.Labels)
	}
}

func TestSettingsValidation(t *testing.T) {
	st, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []func(*Settings){
		func(s *Settings) { s.OnDown = "leak" },
		func(s *Settings) { s.MTU = 9000 },
		func(s *Settings) { s.Active = "../x" },
	} {
		if err := st.UpdateSettings(func(s *Settings) error { bad(s); return nil }); err == nil {
			t.Fatal("invalid settings written")
		}
	}
	// A hand-edited file with an unknown field is refused, not ignored.
	if err := os.WriteFile(filepath.Join(st.Dir(), settingsFile), []byte(`{"active":"a","leak":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Settings(); err == nil {
		t.Fatal("unknown settings field accepted")
	}
}

func TestStatusRoundTrip(t *testing.T) {
	st, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := st.ReadStatus(); ok || err != nil {
		t.Fatalf("status before any run: %v %v", ok, err)
	}
	now := time.Unix(1_800_000_000, 0)
	in := Status{Active: "se-got", Mode: ModeTunnel, Connected: true, LastHandshake: now.Unix() - 30, RxBytes: 10, TxBytes: 20, Updated: now.Unix()}
	if err := st.WriteStatus(in); err != nil {
		t.Fatal(err)
	}
	out, ok, err := st.ReadStatus()
	if err != nil || !ok || out != in {
		t.Fatalf("status %+v %v %v", out, ok, err)
	}
	if out.Stale(now.Add(10*time.Second)) || !out.Stale(now.Add(5*time.Minute)) {
		t.Fatal("staleness")
	}
}
