package audit

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixedNow() func() time.Time {
	t := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	return func() time.Time { t = t.Add(time.Second); return t }
}

func writeN(t *testing.T, l *Log, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := l.Append("document_changed", SeverityInfo, "belge değişti"); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAppendAndVerify(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(dir, fixedNow())
	if err != nil {
		t.Fatal(err)
	}
	var seen []Record
	l.OnAppend(func(r Record) { seen = append(seen, r) })
	writeN(t, l, 5)
	rep, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK || rep.Records != 5 || rep.FirstSeq != 1 || rep.LastSeq != 5 {
		t.Fatalf("report = %+v", rep)
	}
	if len(seen) != 5 || seen[4].Hash != rep.LastHash || seen[0].Prev != Genesis {
		t.Fatalf("callbacks = %+v", seen)
	}
	// Reopening continues the chain.
	l2, err := Open(dir, fixedNow())
	if err != nil {
		t.Fatal(err)
	}
	writeN(t, l2, 1)
	if rep, _ := Verify(dir); !rep.OK || rep.LastSeq != 6 {
		t.Fatalf("after reopen: %+v", rep)
	}
	recs, err := Tail(dir, 2)
	if err != nil || len(recs) != 2 || recs[0].Seq != 6 || recs[1].Seq != 5 {
		t.Fatalf("tail = %+v, %v", recs, err)
	}
}

func TestMessagesAreMasked(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(dir, fixedNow())
	if err != nil {
		t.Fatal(err)
	}
	key := strings.Repeat("A", 42) + "E="
	if err := l.Append("signature_failed", SeverityCritical, "uç 203.0.113.9:51820 anahtar "+key+"\x00son"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(dir, FileName))
	if bytes.Contains(data, []byte("203.0.113.9")) || bytes.Contains(data, []byte(key)) || bytes.Contains(data, []byte(`\u0000`)) {
		t.Fatalf("unmasked: %s", data)
	}
	if err := l.Append("Bad Kind", SeverityInfo, "x"); err == nil {
		t.Fatal("bad kind accepted")
	}
	if err := l.Append("ok", "loud", "x"); err == nil {
		t.Fatal("bad severity accepted")
	}
}

func TestTamperingIsFound(t *testing.T) {
	cases := map[string]func(t *testing.T, dir string){
		"edit": func(t *testing.T, dir string) {
			p := filepath.Join(dir, FileName)
			data, _ := os.ReadFile(p)
			data = bytes.Replace(data, []byte("belge değişti"), []byte("belge degisti"), 1)
			_ = os.WriteFile(p, data, 0o600)
		},
		"delete middle": func(t *testing.T, dir string) {
			p := filepath.Join(dir, FileName)
			lines := bytes.SplitAfter(mustRead(t, p), []byte("\n"))
			_ = os.WriteFile(p, bytes.Join(append(lines[:1:1], lines[2:]...), nil), 0o600)
		},
		"truncate end": func(t *testing.T, dir string) {
			p := filepath.Join(dir, FileName)
			lines := bytes.SplitAfter(mustRead(t, p), []byte("\n"))
			_ = os.WriteFile(p, bytes.Join(lines[:2], nil), 0o600)
		},
		"swap": func(t *testing.T, dir string) {
			p := filepath.Join(dir, FileName)
			lines := bytes.SplitAfter(mustRead(t, p), []byte("\n"))
			lines[0], lines[1] = lines[1], lines[0]
			_ = os.WriteFile(p, bytes.Join(lines, nil), 0o600)
		},
		"head removed": func(t *testing.T, dir string) {
			_ = os.Remove(filepath.Join(dir, HeadName))
		},
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			l, err := Open(dir, fixedNow())
			if err != nil {
				t.Fatal(err)
			}
			writeN(t, l, 4)
			tamper(t, dir)
			rep, err := Verify(dir)
			if err != nil {
				t.Fatal(err)
			}
			if rep.OK || len(rep.Problems) == 0 {
				t.Fatalf("tampering not found: %+v", rep)
			}
		})
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestTornLineIsCutAndRecorded(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(dir, fixedNow())
	if err != nil {
		t.Fatal(err)
	}
	writeN(t, l, 2)
	f, _ := os.OpenFile(filepath.Join(dir, FileName), os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = f.WriteString(`{"hash":"ab`)
	_ = f.Close()
	if _, err := Open(dir, fixedNow()); err != nil {
		t.Fatal(err)
	}
	rep, _ := Verify(dir)
	if !rep.OK || rep.LastSeq != 3 {
		t.Fatalf("report = %+v", rep)
	}
	recs, _ := Tail(dir, 1)
	if recs[0].Kind != "audit_torn_record" {
		t.Fatalf("last = %+v", recs[0])
	}
}

func TestRotationKeepsChain(t *testing.T) {
	old := maxFileSize
	maxFileSize = 8 << 10
	t.Cleanup(func() { maxFileSize = old })
	dir := t.TempDir()
	l, err := Open(dir, fixedNow())
	if err != nil {
		t.Fatal(err)
	}
	big := strings.Repeat("x", MaxMessage)
	n := int(maxFileSize)/(MaxMessage+200) + 3
	for i := 0; i < n; i++ {
		if err := l.Append("event", SeverityInfo, big); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, FileName+rotatedSuffix)); err != nil {
		t.Fatalf("no rotation: %v", err)
	}
	rep, err := Verify(dir)
	if err != nil || !rep.OK || rep.LastSeq != uint64(n) || rep.FirstSeq != 1 {
		t.Fatalf("report = %+v, %v", rep, err)
	}
}
