package syncdir

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func blobFiles(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() && strings.Contains(filepath.ToSlash(p), "/"+KindBlob) {
			out = append(out, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestProbe(t *testing.T) {
	src := newNode(t, "laptop", "x", FolderConfig{})
	t0 := time.Now().Add(-time.Hour).Truncate(time.Second)
	for i := range 6 {
		src.write(t, fmt.Sprintf("dosya-%d.txt", i), plainText(i), t0)
	}
	addr, targetDir := backupServer(t, Access{Peer: "laptop", Backup: true, Quota: 1 << 30})
	key, _ := NewBackupKey()
	c, err := Dial(testCtx(t), addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	store := c.Store("belgeler")
	if _, err := Probe(testCtx(t), key, store, ProbeOptions{}); !errors.Is(err, ErrNoSnapshot) {
		t.Fatalf("empty target: %v", err)
	}
	if _, err := Snapshot(testCtx(t), src.folder, key, store, ""); err != nil {
		t.Fatal(err)
	}
	src.write(t, "dosya-0.txt", "değişti", t0.Add(time.Minute))
	if _, err := Snapshot(testCtx(t), src.folder, key, store, ""); err != nil {
		t.Fatal(err)
	}
	all := ProbeOptions{Files: 100}
	res, err := Probe(testCtx(t), key, store, all)
	if err != nil || !res.OK || res.Checked != 6 || res.Files != 6 || res.Snapshots != 2 || res.OlderChecked == "" {
		t.Fatalf("healthy probe: %+v %v", res, err)
	}
	// A partial probe checks only some files.
	res, err = Probe(testCtx(t), key, store, ProbeOptions{Files: 2})
	if err != nil || !res.OK || res.Checked != 2 {
		t.Fatalf("partial probe: %+v %v", res, err)
	}
	// Another key cannot vouch for the backup.
	other, _ := NewBackupKey()
	res, err = Probe(testCtx(t), other, store, all)
	if err != nil || res.OK || len(res.Problems) == 0 {
		t.Fatalf("other key: %+v %v", res, err)
	}
	// Damage one object on the target (a bit flip).
	blobs := blobFiles(t, targetDir)
	if len(blobs) == 0 {
		t.Fatal("no blobs on target")
	}
	data, err := os.ReadFile(blobs[0])
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)/2] ^= 0x40
	if err := os.WriteFile(blobs[0], data, 0o600); err != nil {
		t.Fatal(err)
	}
	// Remove another one.
	if len(blobs) > 1 {
		if err := os.Remove(blobs[1]); err != nil {
			t.Fatal(err)
		}
	}
	res, err = Probe(testCtx(t), key, store, all)
	if err != nil || res.OK || len(res.Problems) == 0 {
		t.Fatalf("damaged probe: %+v %v", res, err)
	}
	// The reported paths are local paths of the source.
	for _, p := range res.Problems {
		if p.Path != "" && !strings.HasPrefix(p.Path, "dosya-") {
			t.Fatalf("problem path %q", p.Path)
		}
	}
	// A byte budget smaller than every file checks nothing and says so.
	res, err = Probe(testCtx(t), key, store, ProbeOptions{MaxBytes: 1})
	if err != nil || res.OK || res.Checked != 0 {
		t.Fatalf("budget: %+v %v", res, err)
	}
}
