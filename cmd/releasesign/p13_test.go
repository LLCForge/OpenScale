package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/release"
	"github.com/openscale/openscale/internal/securefile"
)

func TestWitnessAndAdvisoryCommands(t *testing.T) {
	dir := t.TempDir()
	p := func(n string) string { return filepath.Join(dir, n) }
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	e, out := testEnv(now)
	art := p("openscale-linux-amd64")
	if err := os.WriteFile(art, []byte("binary"), 0o644); err != nil {
		t.Fatal(err)
	}
	steps := [][]string{
		{"root-keygen", "-out", p("root.key"), "-pub", p("root.pub")},
		{"signing-keygen", "-out", p("signing.key"), "-pub", p("signing.pub")},
		{"certify", "-root-key", p("root.key"), "-signing-pub", p("signing.pub"), "-out", p("signing.cert"), "-days", "30"},
		{"sign", "-key", p("signing.key"), "-cert", p("signing.cert"), "-root-pub", p("root.pub"), "-version", "0.9.0", "-build", "b1",
			"-source-date-epoch", "1793361600", "-out", p("rel.json"), art},
		{"witness-keygen", "-out", p("witness.key"), "-pub", p("witness.pub")},
	}
	for _, s := range steps {
		if err := run(s, e); err != nil {
			t.Fatalf("%v: %v\n%s", s, err, out)
		}
	}

	// The independent machine built the same bytes.
	other := filepath.Join(dir, "ikinci")
	if err := os.MkdirAll(other, 0o755); err != nil {
		t.Fatal(err)
	}
	same := filepath.Join(other, "openscale-linux-amd64")
	if err := os.WriteFile(same, []byte("binary"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"witness", "-key", p("witness.key"), "-root-pub", p("root.pub"), "-release", p("rel.json"), "-builder", "ikinci makine", "-out", p("rel.witness.json"), same}, e); err != nil {
		t.Fatalf("witness: %v\n%s", err, out)
	}
	wk, err := loadPublicKey(p("witness.pub"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := securefile.ReadLimited(p("rel.witness.json"), release.MaxWitnessSize)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := release.VerifyWitness(wk, data); err != nil {
		t.Fatal(err)
	}
	// A different build is refused before any key is opened.
	if err := os.WriteFile(same, []byte("other bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"witness", "-key", p("witness.key"), "-root-pub", p("root.pub"), "-release", p("rel.json"), "-builder", "x", "-out", p("bad.witness.json"), same}, e); err == nil {
		t.Fatal("mismatching build witnessed")
	}
	// A signing key is not a witness key.
	if err := os.WriteFile(same, []byte("binary"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"witness", "-key", p("signing.key"), "-root-pub", p("root.pub"), "-release", p("rel.json"), "-builder", "x", "-out", p("bad.witness.json"), same}, e); err == nil {
		t.Fatal("signing key used as witness key")
	}

	src := `{"sequence": 1, "advisories": [{"id": "OSA-2026-0001", "severity": "high", "title": "Örnek açık", "introduced": "0.8.0", "fixed": "0.9.1", "published": "2026-10-30T00:00:00Z"}]}`
	if err := os.WriteFile(p("adv.src.json"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"advisory", "-root-key", p("root.key"), "-in", p("adv.src.json"), "-out", p("adv.json")}, e); err != nil {
		t.Fatalf("advisory: %v\n%s", err, out)
	}
	// The next list must carry a higher sequence.
	if err := run([]string{"advisory", "-root-key", p("root.key"), "-in", p("adv.src.json"), "-prev", p("adv.json"), "-out", p("adv2.json")}, e); err == nil || !strings.Contains(err.Error(), "sıra") {
		t.Fatalf("same sequence accepted: %v", err)
	}
	if err := os.WriteFile(p("bad.src.json"), []byte(`{"sequence": 2, "extra": true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"advisory", "-root-key", p("root.key"), "-in", p("bad.src.json"), "-out", p("adv3.json")}, e); err == nil {
		t.Fatal("unknown field accepted")
	}
}
