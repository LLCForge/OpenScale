package filesend

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestScannerHelper(t *testing.T) {
	mode := os.Getenv("FILESEND_SCAN_HELPER")
	if mode == "" {
		return
	}
	file := os.Args[len(os.Args)-1]
	switch mode {
	case "clean":
		os.Exit(0)
	case "infected":
		fmt.Printf("%s: Eicar-Test-Signature FOUND\n", file)
		os.Exit(1)
	case "defender":
		fmt.Println("Threat                  : Virus:DOS/EICAR_Test_File")
		os.Exit(2)
	default:
		os.Exit(7)
	}
}

func TestScan(t *testing.T) {
	file := filepath.Join(t.TempDir(), "gelen.bin")
	if err := os.WriteFile(file, []byte("veri"), 0o600); err != nil {
		t.Fatal(err)
	}
	helper := func(kind string) Scanner {
		return Scanner{Kind: kind, Path: os.Args[0], prefix: []string{"-test.run=^TestScannerHelper$", "--"},
			cloud: func() (bool, bool) { return true, true }}
	}
	cases := []struct {
		mode, kind, verdict, detail string
	}{
		{"clean", "clamav", VerdictClean, ""},
		{"infected", "clamav", VerdictInfected, "Eicar-Test-Signature"},
		{"defender", "defender", VerdictInfected, "Virus:DOS/EICAR_Test_File"},
		{"broken", "clamav", VerdictError, "antivirüs hata kodu döndürdü"},
	}
	for _, c := range cases {
		t.Setenv("FILESEND_SCAN_HELPER", c.mode)
		r := helper(c.kind).Scan(context.Background(), file)
		if r.Verdict != c.verdict || (c.detail != "" && r.Detail != c.detail) {
			t.Errorf("%s: %+v", c.mode, r)
		}
		if c.kind == "defender" && !strings.Contains(r.CloudNote, "Microsoft") {
			t.Errorf("cloud note missing: %+v", r)
		}
		if c.kind == "clamav" && r.CloudNote != "" {
			t.Errorf("clamav cloud note: %+v", r)
		}
	}
	if r := (Scanner{}).Scan(context.Background(), file); r.Verdict != VerdictUnavailable {
		t.Fatalf("no scanner: %+v", r)
	}
	if r := helper("clamav").Scan(context.Background(), "göreli.bin"); r.Verdict != VerdictUnavailable {
		t.Fatalf("relative path: %+v", r)
	}
}

func TestLinks(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "rapor özeti.pdf")
	if err := os.WriteFile(file, []byte("%PDF-1.7 içerik"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	clock := func() time.Time { return now }
	s, err := OpenLinkStore(filepath.Join(dir, "state", "links.json"), clock)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []struct {
		path string
		ttl  time.Duration
		n    int
	}{
		{"göreli.pdf", time.Hour, 1}, {file, time.Second, 1}, {file, time.Hour, 0}, {file, time.Hour, 101}, {dir, time.Hour, 1},
	} {
		if _, _, err := s.Create(bad.path, "telefon", bad.ttl, bad.n); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	l, tok, err := s.Create(file, "telefon", time.Hour, 2)
	if err != nil {
		t.Fatal(err)
	}
	get := func(method, path, peer string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.ServeLink(w, httptest.NewRequest(method, path, nil), peer)
		return w
	}
	// Another device, a wrong token and a wrong method are refused.
	if w := get("GET", LinkPrefix+tok, "dizustu"); w.Code != http.StatusNotFound {
		t.Fatalf("other device: %d", w.Code)
	}
	if w := get("GET", LinkPrefix+strings.Repeat("A", 43), "telefon"); w.Code != http.StatusNotFound {
		t.Fatalf("wrong token: %d", w.Code)
	}
	if w := get("POST", LinkPrefix+tok, "telefon"); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("post: %d", w.Code)
	}
	// HEAD does not count.
	if w := get("HEAD", LinkPrefix+tok, "telefon"); w.Code != http.StatusOK || w.Body.Len() != 0 {
		t.Fatalf("head: %d", w.Code)
	}
	w := get("GET", LinkPrefix+tok, "telefon")
	if w.Code != http.StatusOK || w.Body.String() != "%PDF-1.7 içerik" ||
		!strings.Contains(w.Header().Get("Content-Disposition"), "attachment") || w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("download: %d %q %v", w.Code, w.Body.String(), w.Header())
	}
	// The count survives a reopen.
	s2, err := OpenLinkStore(filepath.Join(dir, "state", "links.json"), clock)
	if err != nil {
		t.Fatal(err)
	}
	if ls := s2.List(); len(ls) != 1 || ls[0].Downloads != 1 || ls[0].ID != l.ID {
		t.Fatalf("reopened %+v", ls)
	}
	if strings.Contains(fmt.Sprint(s2.List()), tok) {
		t.Fatal("token stored in clear")
	}
	if w := get("GET", LinkPrefix+tok, "telefon"); w.Code != http.StatusOK {
		t.Fatalf("second download: %d", w.Code)
	}
	if w := get("GET", LinkPrefix+tok, "telefon"); w.Code != http.StatusNotFound {
		t.Fatalf("third download: %d", w.Code)
	}
	if s.Active() || len(s.List()) != 0 {
		t.Fatal("used up link still active")
	}
	// Expiry and a changed file.
	_, tok2, err := s.Create(file, "telefon", time.Hour, 5)
	if err != nil {
		t.Fatal(err)
	}
	later := now.Add(2 * time.Second)
	if err := os.WriteFile(file, []byte("değişti"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Chtimes(file, later, later)
	if w := get("GET", LinkPrefix+tok2, "telefon"); w.Code != http.StatusConflict {
		t.Fatalf("changed file: %d", w.Code)
	}
	now = now.Add(2 * time.Hour)
	if w := get("GET", LinkPrefix+tok2, "telefon"); w.Code != http.StatusNotFound {
		t.Fatalf("expired: %d", w.Code)
	}
	// Revoke.
	now = time.Now()
	l3, tok3, err := s.Create(file, "telefon", time.Hour, 1)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := s.Revoke(l3.ID); !ok || err != nil {
		t.Fatalf("revoke %v %v", ok, err)
	}
	if w := get("GET", LinkPrefix+tok3, "telefon"); w.Code != http.StatusNotFound {
		t.Fatalf("revoked: %d", w.Code)
	}
}
