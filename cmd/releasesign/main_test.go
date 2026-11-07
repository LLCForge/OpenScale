package main

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/release"
	"github.com/openscale/openscale/internal/securefile"
)

func testEnv(now time.Time) (*env, *bytes.Buffer) {
	out := &bytes.Buffer{}
	return &env{
		stdout: out,
		stderr: out,
		now:    func() time.Time { return now },
		random: rand.Reader,
		passphrase: func(string, bool) ([]byte, error) {
			return []byte("uzun ve farklı parola 2026"), nil
		},
	}, out
}

func TestEndToEnd(t *testing.T) {
	dir := t.TempDir()
	p := func(n string) string { return filepath.Join(dir, n) }
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	e, out := testEnv(now)

	steps := [][]string{
		{"root-keygen", "-out", p("root.key"), "-pub", p("root.pub")},
		{"signing-keygen", "-out", p("signing.key"), "-pub", p("signing.pub")},
		{"certify", "-root-key", p("root.key"), "-signing-pub", p("signing.pub"), "-out", p("signing.cert"), "-days", "30"},
	}
	for _, s := range steps {
		if err := run(s, e); err != nil {
			t.Fatalf("%v: %v\n%s", s, err, out)
		}
	}
	// Keys are never overwritten.
	if err := run([]string{"root-keygen", "-out", p("root.key")}, e); err == nil {
		t.Fatal("existing key overwritten")
	}
	// A signing key cannot be used as a root key.
	if err := run([]string{"certify", "-root-key", p("signing.key"), "-signing-pub", p("signing.pub"), "-out", p("x.cert")}, e); err == nil {
		t.Fatal("signing key accepted as root key")
	}

	art := p("openscale-linux-amd64")
	if err := os.WriteFile(art, []byte("binary"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"sign", "-key", p("signing.key"), "-cert", p("signing.cert"), "-root-pub", p("root.pub"),
		"-version", "0.9.0", "-build", "20261030.1200", "-source-date-epoch", "1793361600",
		"-out", p("openscale-0.9.0.release.json"), "-sums", p("SHA256SUMS"), art}, e); err != nil {
		t.Fatalf("sign: %v\n%s", err, out)
	}

	root, err := loadPublicKey(p("root.pub"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := securefile.ReadLimited(p("openscale-0.9.0.release.json"), release.MaxSignedReleaseSize)
	if err != nil {
		t.Fatal(err)
	}
	v, err := release.Verify(root, data, release.VerifyOptions{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(art)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := v.Manifest.CheckFile("openscale-linux-amd64", f); err != nil {
		t.Fatal(err)
	}
	sums, err := os.ReadFile(p("SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(sums), "  openscale-linux-amd64\n") {
		t.Fatalf("SHA256SUMS: %q", sums)
	}

	// After the certificate expires, signing is refused.
	late, _ := testEnv(now.Add(31 * 24 * time.Hour))
	if err := run([]string{"sign", "-key", p("signing.key"), "-cert", p("signing.cert"), "-root-pub", p("root.pub"),
		"-version", "0.9.1", "-source-date-epoch", "0", "-out", p("late.json"), art}, late); err == nil {
		t.Fatal("signed with an expired certificate")
	}

	// Revocation.
	if err := run([]string{"revoke", "-root-key", p("root.key"), "-signing-pub", p("signing.pub"), "-out", p("revoked.json"), "-reason", "test"}, e); err != nil {
		t.Fatal(err)
	}
	revData, _ := os.ReadFile(p("revoked.json"))
	rev, err := release.VerifyRevocations(root, revData)
	if err != nil {
		t.Fatal(err)
	}
	if rev.Sequence != 1 {
		t.Fatalf("sequence %d", rev.Sequence)
	}
	if _, err := release.Verify(root, data, release.VerifyOptions{Now: now, Revocations: rev}); err == nil {
		t.Fatal("revoked key accepted")
	}
}

func TestWeakPassphraseRefused(t *testing.T) {
	e, _ := testEnv(time.Now())
	e.passphrase = func(string, bool) ([]byte, error) { return []byte("short"), nil }
	if err := run([]string{"root-keygen", "-out", filepath.Join(t.TempDir(), "root.key")}, e); err == nil {
		t.Fatal("weak passphrase accepted")
	}
}
