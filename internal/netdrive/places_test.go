package netdrive

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/openscale/openscale/internal/sysinfo"
)

// testPlaces works in a temporary folder only: the real Network Shortcuts
// folder and APPDATA are never touched.
func testPlaces(t *testing.T) (*Places, *[]string) {
	t.Helper()
	root := t.TempDir()
	var links []string
	p := &Places{
		Dir:        filepath.Join(root, "Network Shortcuts"),
		RecordPath: filepath.Join(root, "state", "netplaces.json"),
		WriteLink: func(path, target, _ string) error {
			links = append(links, target)
			return os.WriteFile(path, []byte("LNK "+target), 0o600)
		},
		SetAttrs:   func(string, string) error { return nil },
		ClearAttrs: func(string) {},
		Changed:    func(string) {},
	}
	return p, &links
}

func nas(shares ...string) PlaceDevice {
	d := PlaceDevice{Name: "nas", Host: "nas.ev.openscale.internal", Known: true}
	for _, s := range shares {
		d.Shares = append(d.Shares, sysinfo.Share{Name: s})
	}
	return d
}

func exists(t *testing.T, p string) bool {
	t.Helper()
	_, err := os.Lstat(p)
	return err == nil
}

func TestPlaceTargetAndFolder(t *testing.T) {
	got, err := PlaceTarget("nas", "nas.ev.openscale.internal", "Arsiv")
	if err != nil || got != `\\nas.ev.openscale.internal\Arsiv` {
		t.Fatalf("target = %q, %v", got, err)
	}
	f, err := PlaceFolder("Arsiv", "nas")
	if err != nil || f != "Arsiv (nas)" {
		t.Fatalf("folder = %q, %v", f, err)
	}
	bad := []struct{ dev, host, share string }{
		{"nas", "nas.ev.openscale.internal", `..\x`},
		{"nas", "nas.ev.openscale.internal", "a/b"},
		{"nas", "nas.ev.openscale.internal", "c:"},
		{"nas", "nas.ev.openscale.internal", "IPC$"},
		{"nas", "evil.com", "x"},
		{"nas", "nas", "x"},
		{"nas", "other.ev.openscale.internal", "x"},
		{"nas", `nas.ev\..\x.internal`, "x"},
		{"NAS", "nas.ev.openscale.internal", "x"},
		{"../x", "nas.ev.openscale.internal", "x"},
		{"nas", "nas..openscale.internal", "x"},
	}
	for _, b := range bad {
		if _, err := PlaceTarget(b.dev, b.host, b.share); err == nil {
			t.Errorf("PlaceTarget(%q, %q, %q) accepted", b.dev, b.host, b.share)
		}
	}
	if _, err := PlaceFolder("x", "a b"); err == nil {
		t.Error("bad device folder accepted")
	}
}

func TestPlacesCreateAndRemove(t *testing.T) {
	p, links := testPlaces(t)
	res, err := p.Sync([]PlaceDevice{nas("Arsiv", "belgeler")})
	if err != nil || len(res.Errors) > 0 {
		t.Fatal(err, res.Errors)
	}
	if !slices.Equal(res.Added, []string{"Arsiv (nas)", "belgeler (nas)"}) {
		t.Fatalf("added = %v", res.Added)
	}
	dir := filepath.Join(p.Dir, "Arsiv (nas)")
	ini, err := os.ReadFile(filepath.Join(dir, "desktop.ini"))
	if err != nil || string(ini) != placeIniText {
		t.Fatalf("desktop.ini = %q, %v", ini, err)
	}
	if !slices.Contains(*links, `\\nas.ev.openscale.internal\Arsiv`) {
		t.Fatalf("links = %v", *links)
	}
	// A second run changes nothing.
	res, _ = p.Sync([]PlaceDevice{nas("Arsiv", "belgeler")})
	if len(res.Added)+len(res.Removed) != 0 {
		t.Fatalf("second run changed %+v", res)
	}
	// The share leaves the report: its location goes.
	res, _ = p.Sync([]PlaceDevice{nas("belgeler")})
	if !slices.Equal(res.Removed, []string{"Arsiv (nas)"}) || exists(t, dir) {
		t.Fatalf("removed = %v, folder left: %v", res.Removed, exists(t, dir))
	}
	// The device is revoked (absent from the document): all of its go.
	res, _ = p.Sync(nil)
	if !slices.Equal(res.Removed, []string{"belgeler (nas)"}) {
		t.Fatalf("removed = %v", res.Removed)
	}
	if owned, _ := p.Owned(); len(owned) != 0 {
		t.Fatalf("record keeps %v", owned)
	}
}

func TestPlacesUnknownDeviceKept(t *testing.T) {
	p, _ := testPlaces(t)
	if _, err := p.Sync([]PlaceDevice{nas("Arsiv")}); err != nil {
		t.Fatal(err)
	}
	unknown := nas()
	unknown.Known = false // no inventory yet (service restart, device offline)
	res, _ := p.Sync([]PlaceDevice{unknown})
	if len(res.Removed) != 0 || !exists(t, filepath.Join(p.Dir, "Arsiv (nas)")) {
		t.Fatalf("an unknown device's location was removed: %+v", res)
	}
}

func TestPlacesNeverTouchUserLocations(t *testing.T) {
	p, _ := testPlaces(t)
	// The user's own location with the same name as ours.
	user := filepath.Join(p.Dir, "Arsiv (nas)")
	if err := os.MkdirAll(user, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(user, "target.lnk"), []byte("user"), 0o600); err != nil {
		t.Fatal(err)
	}
	// An unrelated location of the user, like the Tailscale one.
	other := filepath.Join(p.Dir, "Arsiv (100.101.102.103)")
	if err := os.MkdirAll(other, 0o700); err != nil {
		t.Fatal(err)
	}
	res, err := p.Sync([]PlaceDevice{nas("Arsiv")})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(res.Conflicts, []string{"Arsiv (nas)"}) || len(res.Added) != 0 {
		t.Fatalf("result = %+v", res)
	}
	if _, err := p.RemoveAll(); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(user, "target.lnk")); err != nil || string(data) != "user" {
		t.Fatal("the user's location was changed")
	}
	if !exists(t, other) {
		t.Fatal("an unrelated location was removed")
	}
}

func TestPlacesUserChangedOrDeleted(t *testing.T) {
	p, _ := testPlaces(t)
	if _, err := p.Sync([]PlaceDevice{nas("Arsiv", "belgeler", "medya")}); err != nil {
		t.Fatal(err)
	}
	// The user points one of ours elsewhere: it is theirs now.
	changed := filepath.Join(p.Dir, "Arsiv (nas)")
	if err := os.WriteFile(filepath.Join(changed, "target.lnk"), []byte("elsewhere"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The user adds a file to another one: also theirs.
	extra := filepath.Join(p.Dir, "medya (nas)")
	if err := os.WriteFile(filepath.Join(extra, "not.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The user deletes the third: it is not made again.
	deleted := filepath.Join(p.Dir, "belgeler (nas)")
	for _, f := range []string{"desktop.ini", "target.lnk"} {
		if err := os.Remove(filepath.Join(deleted, f)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Remove(deleted); err != nil {
		t.Fatal(err)
	}
	res, _ := p.Sync([]PlaceDevice{nas("Arsiv", "belgeler", "medya")})
	if len(res.Added) != 0 || len(res.Removed) != 0 {
		t.Fatalf("result = %+v", res)
	}
	if exists(t, deleted) {
		t.Fatal("a location the user deleted came back")
	}
	// Device revoked: the changed ones stay.
	res, _ = p.Sync(nil)
	if len(res.Removed) != 0 || !exists(t, changed) || !exists(t, extra) {
		t.Fatalf("the user's changes were removed: %+v", res)
	}
	// Off and on again brings a deleted one back.
	if _, err := p.RemoveAll(); err != nil {
		t.Fatal(err)
	}
	res, _ = p.Sync([]PlaceDevice{nas("belgeler")})
	if !slices.Equal(res.Added, []string{"belgeler (nas)"}) {
		t.Fatalf("added = %v", res.Added)
	}
}

func TestPlacesHostileReport(t *testing.T) {
	p, links := testPlaces(t)
	evil := PlaceDevice{Name: "nas", Host: "nas.ev.openscale.internal", Known: true, Shares: []sysinfo.Share{
		{Name: `..\..\Startup`}, {Name: "../x"}, {Name: "a:b"}, {Name: "C$"}, {Name: "x\x00y"}, {Name: "ok"},
	}}
	wrongHost := PlaceDevice{Name: "pc", Host: "evil.example.com", Known: true, Shares: []sysinfo.Share{{Name: "z"}}}
	badName := PlaceDevice{Name: `..\pc`, Host: "pc.ev.openscale.internal", Known: true, Shares: []sysinfo.Share{{Name: "z"}}}
	res, err := p.Sync([]PlaceDevice{evil, wrongHost, badName})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(res.Added, []string{"ok (nas)"}) || len(*links) != 1 {
		t.Fatalf("added = %v links = %v", res.Added, *links)
	}
	entries, _ := os.ReadDir(p.Dir)
	if len(entries) != 1 {
		t.Fatalf("folders = %v", entries)
	}
	if exists(t, filepath.Join(filepath.Dir(p.Dir), "Startup")) {
		t.Fatal("path traversal")
	}
}

func TestPlacesCorruptRecordRefused(t *testing.T) {
	p, _ := testPlaces(t)
	if err := os.MkdirAll(filepath.Dir(p.RecordPath), 0o700); err != nil {
		t.Fatal(err)
	}
	// A planted record naming a folder outside the pattern is ignored.
	planted := `{"schema":1,"entries":[{"folder":"..","device":"nas","share":"x","target":"t","link_sha256":"00"}]}`
	if err := os.WriteFile(p.RecordPath, []byte(planted), 0o600); err != nil {
		t.Fatal(err)
	}
	if owned, err := p.Owned(); err != nil || len(owned) != 0 {
		t.Fatalf("owned = %v, %v", owned, err)
	}
	if err := os.WriteFile(p.RecordPath, []byte("{bozuk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Sync([]PlaceDevice{nas("Arsiv")}); err == nil || !strings.Contains(err.Error(), "bozuk") {
		t.Fatalf("corrupt record: %v", err)
	}
}

func TestPlacesLimit(t *testing.T) {
	p, _ := testPlaces(t)
	var devs []PlaceDevice
	for i := range 6 {
		d := PlaceDevice{Name: "pc" + string(rune('a'+i)), Known: true}
		d.Host = d.Name + ".ev.openscale.internal"
		for j := range sysinfo.MaxShares {
			d.Shares = append(d.Shares, sysinfo.Share{Name: "s" + string(rune('a'+j/26)) + string(rune('a'+j%26))})
		}
		devs = append(devs, d)
	}
	res, err := p.Sync(devs)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Added) != MaxPlaces {
		t.Fatalf("added %d, want %d", len(res.Added), MaxPlaces)
	}
}
