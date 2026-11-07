package autoupdate

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/coordinator"
)

func TestParseSourceURL(t *testing.T) {
	if o, r, err := ParseSourceURL("https://github.com/LLCForge/OpenScale"); err != nil || o != "LLCForge" || r != "OpenScale" {
		t.Fatalf("%s %s %v", o, r, err)
	}
	for _, bad := range []string{
		"http://github.com/LLCForge/OpenScale", "https://example.com/LLCForge/OpenScale", "https://github.com/LLCForge",
		"https://github.com/LLCForge/OpenScale/releases", "https://user@github.com/a/b", "https://github.com/a/b?x=1",
		"https://github.com/../b", "https://github.com/a/b.git", "github.com/a/b",
	} {
		if _, _, err := ParseSourceURL(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

// fakeGitHub serves a release listing and its assets from folders, on
// 127.0.0.1 over TLS.
func fakeGitHub(t *testing.T, releases []ghRelease, assets map[string]string) *httptest.Server {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/LLCForge/OpenScale/releases" {
			_ = json.NewEncoder(w).Encode(releases)
			return
		}
		const pfx = "/LLCForge/OpenScale/releases/download/"
		if rest, ok := strings.CutPrefix(r.URL.Path, pfx); ok {
			tag, name, _ := strings.Cut(rest, "/")
			if dir, ok := assets[tag]; ok {
				http.ServeFile(w, r, filepath.Join(dir, filepath.Base(name)))
				return
			}
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func listing(t *testing.T, tag, dir string, prerelease bool) ghRelease {
	r := ghRelease{Tag: tag, Prerelease: prerelease}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		info, _ := e.Info()
		r.Assets = append(r.Assets, ghAsset{Name: e.Name(), Size: info.Size()})
	}
	return r
}

func TestSyncSource(t *testing.T) {
	k := newKeys(t)
	good := k.dist(t, "1.0.1", program("1.0.1"))
	newerUnsigned := t.TempDir() // a release without a signed manifest
	if err := os.WriteFile(filepath.Join(newerUnsigned, testArtifact), program("1.0.2"), 0o600); err != nil {
		t.Fatal(err)
	}
	forged := newKeys(t).dist(t, "1.0.3", program("1.0.3")) // signed by another root
	state := t.TempDir()
	srv := fakeGitHub(t, []ghRelease{
		listing(t, "v1.0.1", good, false), listing(t, "v1.0.2", newerUnsigned, false),
	}, map[string]string{"v1.0.1": good, "v1.0.2": newerUnsigned})
	opts := SyncOptions{StateDir: state, Root: k.root, Client: srv.Client(), APIBase: srv.URL, DownloadBase: srv.URL}

	if _, err := SyncSource(context.Background(), opts); err == nil {
		t.Fatal("sync without a source")
	}
	owner, repo, _ := ParseSourceURL("https://github.com/LLCForge/OpenScale")
	if err := WriteSource(state, &SourceConfig{Owner: owner, Repo: repo, Every: Duration(6 * time.Hour), Beta: true}); err != nil {
		t.Fatal(err)
	}
	res, err := SyncSource(context.Background(), opts)
	if err != nil || !res.Published || res.Version != "1.0.1" {
		t.Fatalf("%+v %v", res, err)
	}
	mirror := filepath.Join(state, coordinator.ReleaseMirrorDir)
	if !exists(filepath.Join(mirror, "openscale-1.0.1.release.json")) || !exists(filepath.Join(mirror, testArtifact+".gz")) {
		t.Fatal("not mirrored")
	}
	st, err := ReadSourceStatus(state)
	if err != nil || st.Source != "github.com/LLCForge/OpenScale" || st.Version != "1.0.1" || st.Error != "" || st.LastCheck.IsZero() {
		t.Fatalf("status %+v %v", st, err)
	}
	// Within the interval nothing is fetched.
	if res, err := SyncSource(context.Background(), opts); err != nil || !res.Skipped {
		t.Fatalf("%+v %v", res, err)
	}
	// The coordinator passes the source on to devices.
	h, _ := coordinator.ReleaseMirrorHandler(mirror, nil)
	w := &fakeCoordinator{handle: h}
	ann, err := announce(context.Background(), w, nil)
	if err != nil || ann.Source != "github.com/LLCForge/OpenScale" || ann.Checked.IsZero() || ann.Version != "1.0.1" {
		t.Fatalf("announcement %+v %v", ann, err)
	}

	// A newer release signed by another root is refused and the mirror kept.
	srv2 := fakeGitHub(t, []ghRelease{listing(t, "v1.0.1", good, false), listing(t, "v1.0.3", forged, false)},
		map[string]string{"v1.0.1": good, "v1.0.3": forged})
	opts2 := SyncOptions{StateDir: state, Root: k.root, Client: srv2.Client(), APIBase: srv2.URL, DownloadBase: srv2.URL, Force: true}
	if _, err := SyncSource(context.Background(), opts2); err == nil || !strings.Contains(err.Error(), "doğrulanamadı") {
		t.Fatalf("forged release: %v", err)
	}
	if !exists(filepath.Join(mirror, "openscale-1.0.1.release.json")) || exists(filepath.Join(mirror, "openscale-1.0.3.release.json")) {
		t.Fatal("mirror changed by a forged release")
	}
	if st, _ := ReadSourceStatus(state); st.Error == "" || st.Version != "1.0.3" && st.Version != "1.0.1" {
		t.Fatalf("status %+v", st)
	}
	// Stable only skips pre-releases.
	if r, v := pickRelease([]ghRelease{{Tag: "v1.1.0-beta.1", Prerelease: true, Assets: []ghAsset{{Name: "openscale-1.1.0-beta.1.release.json"}}},
		{Tag: "v1.0.1", Assets: []ghAsset{{Name: "openscale-1.0.1.release.json"}}}}, false); r == nil || v != "1.0.1" {
		t.Fatalf("stable pick %v", v)
	}
	if err := WriteSource(state, nil); err != nil {
		t.Fatal(err)
	}
	if c, err := ReadSource(state); err != nil || c != nil {
		t.Fatalf("source off: %+v %v", c, err)
	}
}
