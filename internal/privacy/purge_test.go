package privacy

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// countingReader yields a fixed byte and counts what was read.
type countingReader struct{ n int64 }

func (c *countingReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0xA5
	}
	c.n += int64(len(p))
	return len(p), nil
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// fakeDataDir builds a directory laid out like %ProgramData%\OpenScale.
func fakeDataDir(t *testing.T) (string, int64) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "OpenScale")
	files := map[string][]byte{
		"device/device.key":     bytes.Repeat([]byte("k"), 96),
		"device/anchor.json":    []byte(`{"root":"x"}`),
		"device/endpoints.json": []byte(`{"version":1}`),
		"settings.json":         []byte(`{"coordinator_port":0}`),
		"app.token":             []byte("token"),
		"logs/service.log":      bytes.Repeat([]byte("log line\n"), 5000),
		"logs/service.log.1":    []byte("old"),
	}
	var total int64
	for name, data := range files {
		writeFile(t, filepath.Join(dir, filepath.FromSlash(name)), data)
		total += int64(len(data))
	}
	return dir, total
}

func TestPurgeRemovesEverythingAfterOverwrite(t *testing.T) {
	dir, total := fakeDataDir(t)
	rnd := &countingReader{}
	res, err := Purge(dir, PurgeOptions{Random: rnd})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(dir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("directory still exists: %v", err)
	}
	if res.Files != 7 || res.Overwritten != 7 || res.Bytes != total {
		t.Fatalf("result %+v, want 7 files and %d bytes overwritten", res, total)
	}
	if rnd.n < total {
		t.Fatalf("random source read %d bytes, want at least %d", rnd.n, total)
	}
}

func TestPurgeRefusesForeignDirectory(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "notes.txt"), []byte("mine"))
	if _, err := Purge(dir, PurgeOptions{}); !errors.Is(err, ErrNotDataDir) {
		t.Fatalf("err = %v, want ErrNotDataDir", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "notes.txt")); err != nil {
		t.Fatalf("foreign file touched: %v", err)
	}
}

func TestPurgeRefusesUnsafeDirectories(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip(err)
	}
	root := filepath.VolumeName(home) + string(filepath.Separator)
	for _, d := range []string{home, root} {
		if _, err := CheckPurgeTarget(d, true); !errors.Is(err, ErrUnsafePath) {
			t.Errorf("CheckPurgeTarget(%s) = %v, want ErrUnsafePath", d, err)
		}
	}
}

func TestPurgeKeepsRootKeyUnlessAllowed(t *testing.T) {
	dir, _ := fakeDataDir(t)
	rootKey := filepath.Join(dir, "network", "root.key")
	writeFile(t, rootKey, []byte("encrypted root key"))
	if _, err := Purge(dir, PurgeOptions{}); !errors.Is(err, ErrRootKeyPresent) {
		t.Fatalf("err = %v, want ErrRootKeyPresent", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "device", "device.key")); err != nil {
		t.Fatalf("refused purge removed files: %v", err)
	}
	if _, err := Purge(dir, PurgeOptions{AllowRootKey: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(dir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("directory still exists: %v", err)
	}
}

// TestWipeFileSparesOtherHardLink: overwriting a file with a second name
// would destroy that other file's content; it is only unlinked.
func TestWipeFileSparesOtherHardLink(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")
	writeFile(t, a, []byte("shared content"))
	if err := os.Link(a, b); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	_, overwritten, err := WipeFile(a, &countingReader{})
	if err != nil {
		t.Fatal(err)
	}
	if overwritten {
		t.Fatal("hard-linked file was overwritten")
	}
	got, err := os.ReadFile(b)
	if err != nil || string(got) != "shared content" {
		t.Fatalf("other link damaged: %q, %v", got, err)
	}
}

// TestPurgeDoesNotFollowLinks: a link inside the data directory pointing
// outside is removed, its target stays.
func TestPurgeDoesNotFollowLinks(t *testing.T) {
	dir, _ := fakeDataDir(t)
	outside := filepath.Join(t.TempDir(), "keep.txt")
	writeFile(t, outside, []byte("keep me"))
	if err := os.Symlink(outside, filepath.Join(dir, "link.txt")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	res, err := Purge(dir, PurgeOptions{Random: &countingReader{}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(outside)
	if err != nil || string(got) != "keep me" {
		t.Fatalf("link target damaged: %q, %v", got, err)
	}
	if len(res.NotOverwritten) != 1 {
		t.Fatalf("NotOverwritten = %v, want the link", res.NotOverwritten)
	}
}

func TestPurgeRefusesSymlinkedDirectory(t *testing.T) {
	dir, _ := fakeDataDir(t)
	link := filepath.Join(t.TempDir(), "via-link")
	if err := os.Symlink(dir, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := Purge(link, PurgeOptions{}); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("err = %v, want ErrUnsafePath", err)
	}
}
