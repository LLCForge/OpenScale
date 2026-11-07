package service

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/containers"
	"github.com/openscale/openscale/internal/edgenet"
	"github.com/openscale/openscale/internal/filesend"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/trust"
)

func TestSyncPauseReasons(t *testing.T) {
	a, _ := testApps(t, "laptop", "nas", false)
	now := a.cfg.Now()
	if a.syncHeld(now) {
		t.Fatal("held without a reason")
	}
	if err := a.setSyncPause(panel.SyncPauseRequest{Paused: true, Hours: 2}); err != nil {
		t.Fatal(err)
	}
	r := a.syncPauseReasons(now)
	if len(r) != 1 || r[0].Reason != panel.SyncPauseOwner || r[0].Until == nil {
		t.Fatalf("owner pause %+v", r)
	}
	// The pause ends by itself.
	if a.syncHeld(now.Add(3 * time.Hour)) {
		t.Fatal("expired pause still holds")
	}
	if err := a.setSyncPause(panel.SyncPauseRequest{Paused: true}); err != nil {
		t.Fatal(err)
	}
	if err := a.setSyncPause(panel.SyncPauseRequest{Paused: false}); err != nil {
		t.Fatal(err)
	}
	if a.syncHeld(now) {
		t.Fatal("resume did not end the pause")
	}
	// P11's game and metered modes hold sync (#447, #385).
	for mode, want := range map[string]string{panel.EdgeModeGame: panel.SyncPauseGame, panel.EdgeModeMetered: panel.SyncPauseMetered} {
		if err := saveEdge(a.cfg.Dir, edgeFileState{Mode: &edgeMode{Name: mode, Since: now}}); err != nil {
			t.Fatal(err)
		}
		if r := a.syncPauseReasons(now); len(r) != 1 || r[0].Reason != want {
			t.Fatalf("%s: %+v", mode, r)
		}
	}
	if err := saveEdge(a.cfg.Dir, edgeFileState{Mode: &edgeMode{Name: panel.EdgeModeTravel, Since: now}}); err != nil {
		t.Fatal(err)
	}
	if a.syncHeld(now) {
		t.Fatal("travel mode must not hold sync")
	}
	a.p07().hold.Set("deneme", true, now)
	if r := a.syncPauseReasons(now); len(r) != 1 || r[0].Reason != "deneme" {
		t.Fatalf("code hold %+v", r)
	}
	a.p07().hold.Set("deneme", false, now)
	if a.syncHeld(now) {
		t.Fatal("hold not released")
	}
}

func TestSyncGuardThroughService(t *testing.T) {
	a, _ := testApps(t, "laptop", "nas", false,
		trust.Rule{From: []string{"laptop"}, To: []string{"nas"}, Service: trust.ServiceSync, Backup: true})
	dir := t.TempDir()
	t0 := time.Now().Add(-time.Hour).Truncate(time.Second)
	write := func(name string, data []byte, at time.Time) {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		_ = os.Chtimes(p, at, at)
	}
	for i := range 25 {
		write(fmt.Sprintf("not-%02d.txt", i), []byte(strings.Repeat(fmt.Sprintf("satır %d, sıradan metin. ", i), 50)), t0)
	}
	if err := a.SetSyncFolder(panel.SyncFolderChange{ID: "notlar", Path: dir, Mode: "sendreceive"}); err != nil {
		t.Fatal(err)
	}
	f, err := a.configuredFolder("notlar")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Scan(); err != nil {
		t.Fatal(err)
	}
	for i := range 20 {
		b := make([]byte, 8192)
		_, _ = rand.Read(b)
		write(fmt.Sprintf("not-%02d.txt", i), b, t0.Add(time.Minute))
	}
	if _, err := f.Scan(); err == nil {
		t.Fatal("encryption not detected")
	}
	st, err := a.syncGuardStatus()
	if err != nil || len(st.Folders) != 1 || st.Folders[0].Alarm == nil || st.Folders[0].Alarm.Modified != 20 {
		t.Fatalf("status %+v %v", st, err)
	}
	if err := a.clearSyncAlarm("yok"); err == nil {
		t.Fatal("unknown folder cleared")
	}
	if err := a.clearSyncAlarm("notlar"); err != nil {
		t.Fatal(err)
	}
	if err := a.clearSyncAlarm("notlar"); err == nil {
		t.Fatal("cleared twice")
	}
	if err := a.setSyncGuard(panel.SyncGuardRequest{ID: "notlar", Off: true}); err != nil {
		t.Fatal(err)
	}
	st, _ = a.syncGuardStatus()
	if !st.Folders[0].GuardOff || st.Folders[0].Alarm != nil {
		t.Fatalf("guard off %+v", st.Folders[0])
	}
	f, _ = a.configuredFolder("notlar")
	for i := range 20 {
		b := make([]byte, 8192)
		_, _ = rand.Read(b)
		write(fmt.Sprintf("not-%02d.txt", i), b, t0.Add(2*time.Minute))
	}
	if _, err := f.Scan(); err != nil {
		t.Fatalf("guard off still judges: %v", err)
	}
	if err := a.probeBackupNow(t.Context()); err == nil {
		t.Fatal("probe without a backup target")
	}
}

func TestSubnetInventory(t *testing.T) {
	own := []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}
	neigh := []edgenet.Neighbor{
		{Addr: netip.MustParseAddr("192.168.1.20"), MAC: "B8:27:EB:01:02:03"},
		{Addr: netip.MustParseAddr("192.168.1.5"), MAC: "da:11:22:33:44:55"},
		{Addr: netip.MustParseAddr("10.0.0.9"), MAC: "00:11:22:33:44:55"},
	}
	inv := subnetInventory(own, neigh)
	if len(inv.Devices) != 2 || inv.Devices[0].Addr != "192.168.1.5" || !inv.Devices[0].RandomMAC ||
		inv.Devices[1].Vendor != "Raspberry Pi" || inv.Devices[1].Rule != "192.168.1.20/32" {
		t.Fatalf("inventory %+v", inv)
	}
	if inv := subnetInventory(nil, neigh); len(inv.Devices) != 0 || inv.Note == "" {
		t.Fatalf("no routes %+v", inv)
	}
}

func TestFileLinksThroughService(t *testing.T) {
	a, _ := testApps(t, "laptop", "nas", false,
		trust.Rule{From: []string{"nas"}, To: []string{"laptop"}, Service: trust.ServiceServe})
	file := filepath.Join(t.TempDir(), "rapor.pdf")
	if err := os.WriteFile(file, []byte("%PDF-1.7"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.createFileLink(panel.FileLinkRequest{Path: filepath.Join(a.cfg.Dir, "x"), Device: "nas", Hours: 1, Downloads: 1}); err == nil {
		t.Fatal("data directory accepted")
	}
	if _, err := a.createFileLink(panel.FileLinkRequest{Path: file, Device: "laptop", Hours: 1, Downloads: 1}); err == nil {
		t.Fatal("link to self accepted")
	}
	if _, err := a.createFileLink(panel.FileLinkRequest{Path: file, Device: "nas", Hours: 0, Downloads: 1}); err == nil {
		t.Fatal("zero hours accepted")
	}
	res, err := a.createFileLink(panel.FileLinkRequest{Path: file, Device: "nas", Hours: 2, Downloads: 3})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.URL, ":4051/l/") || res.Link.Device != "nas" {
		t.Fatalf("created %+v", res)
	}
	if a.linksForServe() == nil {
		t.Fatal("live link does not open the serve port")
	}
	st, err := a.fileLinks()
	if err != nil || len(st.Links) != 1 || !st.Served {
		t.Fatalf("links %+v %v", st, err)
	}
	if err := a.revokeFileLink(res.Link.ID); err != nil {
		t.Fatal(err)
	}
	if a.linksForServe() != nil {
		t.Fatal("revoked link keeps the port")
	}
	// Scanning: refused without a scanner; inbox names are checked.
	a.filesP07().scanner = func() (filesend.Scanner, bool) { return filesend.Scanner{}, false }
	if err := a.setFileScan(panel.FileScanRequest{Enabled: true}); err == nil {
		t.Fatal("scan enabled without a scanner")
	}
	if _, err := a.inboxFile("../anahtar.key"); err == nil {
		t.Fatal("path traversal accepted")
	}
}

func TestServeSuggestions(t *testing.T) {
	r := &Runtime{cfg: Config{DataDir: t.TempDir(), Now: time.Now}}
	old := discoverContainers
	t.Cleanup(func() { discoverContainers = old })
	discoverContainers = func(context.Context) ([]containers.Suggestion, string, error) {
		return nil, "", containers.ErrUnsupported
	}
	out, err := r.ServeSuggestions(context.Background())
	if err != nil || out.Available || out.Error == "" {
		t.Fatalf("unsupported: %+v %v", out, err)
	}
	discoverContainers = func(context.Context) ([]containers.Suggestion, string, error) {
		return []containers.Suggestion{{Container: "jellyfin", Name: "medya", Type: "http", Target: "http://127.0.0.1:8096"}}, "/run/docker.sock", nil
	}
	out, err = r.ServeSuggestions(context.Background())
	if err != nil || !out.Available || len(out.Suggestions) != 1 || out.Suggestions[0].Published {
		t.Fatalf("suggestions: %+v %v", out, err)
	}
}
