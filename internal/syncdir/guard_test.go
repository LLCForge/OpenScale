package syncdir

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func randomBytes(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return string(b)
}

func plainText(i int) string {
	return strings.Repeat(fmt.Sprintf("Toplantı notu %d: bütçe, plan ve görev listesi. ", i), 40)
}

func TestEntropyAndVerdict(t *testing.T) {
	if e := Entropy([]byte(plainText(1))); e > 5.5 {
		t.Fatalf("text entropy %.2f", e)
	}
	if e := Entropy([]byte(randomBytes(64 << 10))); e < 7.9 {
		t.Fatalf("random entropy %.2f", e)
	}
	if sampleVerdict("a.txt", []byte(randomBytes(4096))) != 1 {
		t.Fatal("random .txt not flagged")
	}
	if sampleVerdict("a.zip", []byte(randomBytes(4096))) != 2 {
		t.Fatal("zip without PK not flagged")
	}
	if sampleVerdict("a.zip", append([]byte("PK\x03\x04"), randomBytes(4096)...)) != 0 {
		t.Fatal("valid zip flagged")
	}
	if sampleVerdict("a.mp4", []byte(randomBytes(4096))) != -1 {
		t.Fatal("compressed media judged")
	}
	if sampleVerdict("a.txt", []byte("kısa")) != -1 {
		t.Fatal("short file judged")
	}
}

func TestExtChanges(t *testing.T) {
	del := []string{"a/rapor.docx", "b.txt", "c.pdf"}
	add := []string{"a/rapor.docx.locked", "b.crypt", "yeni.txt"}
	if n := extChanges(del, add); n != 2 {
		t.Fatalf("ext changes %d", n)
	}
}

func TestAssess(t *testing.T) {
	prev := Index{}
	for i := range 40 {
		prev[fmt.Sprintf("belge-%02d.txt", i)] = e(plainText(i), 1)
	}
	content := map[string]string{}
	sample := func(p string) ([]byte, error) {
		c, ok := content[p]
		if !ok {
			return nil, fs.ErrNotExist
		}
		return []byte(c), nil
	}
	// Small edits: nothing.
	cur := Index{}
	for p, v := range prev {
		cur[p] = v
	}
	for i := range 5 {
		p := fmt.Sprintf("belge-%02d.txt", i)
		content[p] = plainText(i) + "ek"
		cur[p] = e(content[p], 2)
	}
	if a := Assess(GuardConfig{}, prev, cur, sample); a != nil {
		t.Fatalf("small edit alarmed: %+v", a)
	}
	// Mass rewrite with ordinary text (a reformat): nothing.
	for i := range 30 {
		p := fmt.Sprintf("belge-%02d.txt", i)
		content[p] = strings.ToUpper(plainText(i))
		cur[p] = e(content[p], 2)
	}
	if a := Assess(GuardConfig{}, prev, cur, sample); a != nil {
		t.Fatalf("plain mass change alarmed: %+v", a)
	}
	// Mass encryption: alarm.
	for i := range 30 {
		p := fmt.Sprintf("belge-%02d.txt", i)
		content[p] = randomBytes(8192)
		cur[p] = e(content[p], 3)
	}
	a := Assess(GuardConfig{}, prev, cur, sample)
	if a == nil || a.HighEntropy < 5 || a.Modified != 30 || a.Reason == "" {
		t.Fatalf("encryption not detected: %+v", a)
	}
	// Off and small folders are not judged.
	if Assess(GuardConfig{Off: true}, prev, cur, sample) != nil || Assess(GuardConfig{MinFiles: 100}, prev, cur, sample) != nil {
		t.Fatal("guard judged when it should not")
	}
	// Rename pattern: encrypted copies under a new extension.
	cur2 := Index{}
	for i := range 40 {
		p := fmt.Sprintf("belge-%02d.txt", i)
		if i < 15 {
			q := p + ".kilitli"
			content[q] = randomBytes(4096)
			cur2[q] = e(content[q], 3)
			continue
		}
		cur2[p] = prev[p]
	}
	a = Assess(GuardConfig{}, prev, cur2, sample)
	if a == nil || a.ExtChanged != 15 {
		t.Fatalf("rename pattern: %+v", a)
	}
	if b := AssessIndexes(GuardConfig{}, prev, cur2); b == nil || b.ExtChanged != 15 {
		t.Fatalf("index-only: %+v", b)
	}
}

func TestFolderGuardSuspendsAndClears(t *testing.T) {
	var alarms []string
	got := make(chan string, 4)
	a := newNode(t, "a", "b", FolderConfig{OnAlarm: func(id string, al Alarm) { got <- id + ":" + al.Source }})
	b := newNode(t, "b", "a", FolderConfig{})
	t0 := time.Now().Add(-time.Hour).Truncate(time.Second)
	for i := range 30 {
		a.write(t, fmt.Sprintf("notlar/not-%02d.md", i), plainText(i), t0)
	}
	b.pullFrom(t, a)
	if b.read(t, "notlar/not-07.md") != plainText(7) {
		t.Fatal("initial sync failed")
	}
	// "Ransomware" encrypts most files on a.
	for i := range 25 {
		a.write(t, fmt.Sprintf("notlar/not-%02d.md", i), randomBytes(8192), t0.Add(time.Minute))
	}
	if _, err := a.folder.Scan(); !errors.Is(err, ErrSuspended) {
		t.Fatalf("scan: %v", err)
	}
	select {
	case s := <-got:
		alarms = append(alarms, s)
	case <-time.After(5 * time.Second):
		t.Fatal("no alarm callback")
	}
	if alarms[0] != "docs:local" {
		t.Fatalf("alarm %v", alarms)
	}
	// b cannot pull the encrypted files; its copies stay good.
	c, err := Dial(testCtx(t), a.addr)
	if err != nil {
		t.Fatal(err)
	}
	_, err = b.folder.Pull(testCtx(t), "a", c.Folder("docs"))
	c.Close()
	if !errors.Is(err, ErrDenied) || !strings.Contains(err.Error(), "fidye") {
		t.Fatalf("pull from suspended folder: %v", err)
	}
	if b.read(t, "notlar/not-07.md") != plainText(7) {
		t.Fatal("good copy replaced")
	}
	// a itself pulls nothing while suspended, and it survives a reopen.
	c, _ = Dial(testCtx(t), b.addr)
	if _, err := a.folder.Pull(testCtx(t), "b", c.Folder("docs")); !errors.Is(err, ErrSuspended) {
		t.Fatalf("suspended pull: %v", err)
	}
	c.Close()
	re, err := OpenFolder(a.folder.Config())
	if err != nil {
		t.Fatal(err)
	}
	if al := re.Alarm(); al == nil || al.Modified != 25 || len(al.Examples) == 0 {
		t.Fatalf("alarm not persisted: %+v", al)
	}
	_ = re.Close()
	// The owner clears it: the current content becomes the baseline.
	if err := a.folder.ClearAlarm(); err != nil {
		t.Fatal(err)
	}
	if a.folder.Alarm() != nil {
		t.Fatal("alarm still set")
	}
	if _, err := a.folder.Scan(); err != nil {
		t.Fatalf("scan after clear: %v", err)
	}
	if _, err := os.Stat(filepath.Join(a.dir, MetaDir, guardFile)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("guard file left: %v", err)
	}
}

func TestPullFromPeerWithRenamePattern(t *testing.T) {
	a := newNode(t, "a", "b", FolderConfig{Guard: GuardConfig{Off: true}})
	b := newNode(t, "b", "a", FolderConfig{PropagateDeletes: true})
	t0 := time.Now().Add(-time.Hour).Truncate(time.Second)
	for i := range 30 {
		a.write(t, fmt.Sprintf("f-%02d.txt", i), plainText(i), t0)
	}
	b.pullFrom(t, a)
	// a has no guard (or an old version): it renames and encrypts.
	for i := range 20 {
		p := fmt.Sprintf("f-%02d.txt", i)
		if err := os.Remove(filepath.Join(a.dir, p)); err != nil {
			t.Fatal(err)
		}
		a.write(t, p+".sifreli", randomBytes(4096), t0.Add(time.Minute))
	}
	c, err := Dial(testCtx(t), a.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := b.folder.Pull(testCtx(t), "a", c.Folder("docs")); !errors.Is(err, ErrSuspended) {
		t.Fatalf("pull: %v", err)
	}
	if al := b.folder.Alarm(); al == nil || al.Source != "peer:a" {
		t.Fatalf("alarm %+v", al)
	}
	if b.read(t, "f-03.txt") != plainText(3) {
		t.Fatal("deletion propagated from a suspicious peer")
	}
}

func TestSnapshotRefusedWhileSuspended(t *testing.T) {
	src := newNode(t, "laptop", "x", FolderConfig{})
	t0 := time.Now().Add(-time.Hour).Truncate(time.Second)
	for i := range 25 {
		src.write(t, fmt.Sprintf("d-%02d.txt", i), plainText(i), t0)
	}
	addr, _ := backupServer(t, Access{Peer: "laptop", Backup: true, Quota: 1 << 30})
	key, _ := NewBackupKey()
	c, err := Dial(testCtx(t), addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := Snapshot(testCtx(t), src.folder, key, c.Store("d"), ""); err != nil {
		t.Fatal(err)
	}
	for i := range 20 {
		src.write(t, fmt.Sprintf("d-%02d.txt", i), randomBytes(8192), t0.Add(time.Minute))
	}
	if _, err := Snapshot(testCtx(t), src.folder, key, c.Store("d"), ""); !errors.Is(err, ErrSuspended) {
		t.Fatalf("snapshot while suspended: %v", err)
	}
	names, _ := Snapshots(testCtx(t), c.Store("d"))
	if len(names) != 1 {
		t.Fatalf("snapshots %v", names)
	}
}

func TestPauser(t *testing.T) {
	var p Pauser
	if p.Paused() {
		t.Fatal("zero value paused")
	}
	now := time.Now()
	p.Set("oyun", true, now)
	p.Set("ölçülü", true, now)
	p.Set("oyun", true, now.Add(time.Hour))
	if s, _ := p.Since("oyun"); !s.Equal(now.UTC()) {
		t.Fatal("since moved")
	}
	if r := p.Reasons(); len(r) != 2 || r[0] != "oyun" {
		t.Fatalf("reasons %v", r)
	}
	p.Set("oyun", false, now)
	p.Set("ölçülü", false, now)
	if p.Paused() {
		t.Fatal("still paused")
	}
}
