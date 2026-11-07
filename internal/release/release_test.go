package release

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

type fixture struct {
	root       PublicKey
	rootPriv   ed25519.PrivateKey
	signing    PublicKey
	signPriv   ed25519.PrivateKey
	certEnv    Envelope
	manifest   Manifest
	signedData []byte
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{}
	var err error
	if f.root, f.rootPriv, err = GenerateKey(rand.Reader); err != nil {
		t.Fatal(err)
	}
	if f.signing, f.signPriv, err = GenerateKey(rand.Reader); err != nil {
		t.Fatal(err)
	}
	f.certEnv, _, err = IssueCertificate(f.rootPriv, CertificateRequest{
		SigningKey: f.signing, Serial: 1, NotBefore: t0.Add(-time.Hour), Validity: DefaultCertificateValidity, Comment: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	a1, err := HashArtifact("openscale-linux-amd64", strings.NewReader("linux binary"))
	if err != nil {
		t.Fatal(err)
	}
	a2, err := HashArtifact("openscale-windows-amd64.exe", strings.NewReader("windows binary"))
	if err != nil {
		t.Fatal(err)
	}
	f.manifest = NewManifest("0.9.0", "20261030.1200", t0.Unix(), []Artifact{a2, a1})
	f.signedData, err = SignManifest(f.signPriv, f.certEnv, f.root, f.manifest, t0)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestSignAndVerify(t *testing.T) {
	f := newFixture(t)
	v, err := Verify(f.root, f.signedData, VerifyOptions{Now: t0.Add(24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if v.Manifest.Version != "0.9.0" || len(v.Manifest.Artifacts) != 2 {
		t.Fatalf("unexpected manifest: %+v", v.Manifest)
	}
	if v.Manifest.Artifacts[0].Name != "openscale-linux-amd64" {
		t.Fatal("artifacts are not sorted")
	}
	if err := v.Manifest.CheckFile("openscale-linux-amd64", strings.NewReader("linux binary")); err != nil {
		t.Fatal(err)
	}
	if err := v.Manifest.CheckFile("openscale-linux-amd64", strings.NewReader("linux binarY")); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("tampered file: got %v", err)
	}
	if err := v.Manifest.CheckFile("openscale-linux-amd64", strings.NewReader("linux binary plus")); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("longer file: got %v", err)
	}
	if err := v.Manifest.CheckFile("other", strings.NewReader("x")); !errors.Is(err, ErrNotInManifest) {
		t.Fatalf("unknown file: got %v", err)
	}
	if !strings.Contains(v.Manifest.SHA256Sums(), "  openscale-windows-amd64.exe\n") {
		t.Fatal("SHA256SUMS line missing")
	}
}

func TestVerifyRejectsWrongRoot(t *testing.T) {
	f := newFixture(t)
	other, _, _ := GenerateKey(rand.Reader)
	if _, err := Verify(other, f.signedData, VerifyOptions{Now: t0}); err == nil {
		t.Fatal("verified with another root key")
	}
}

func TestVerifyRejectsTamperedManifest(t *testing.T) {
	f := newFixture(t)
	var sr SignedRelease
	if err := json.Unmarshal(f.signedData, &sr); err != nil {
		t.Fatal(err)
	}
	sr.Manifest.Payload = bytes.Replace(sr.Manifest.Payload, []byte("0.9.0"), []byte("9.9.0"), 1)
	data, _ := json.Marshal(sr)
	if _, err := Verify(f.root, data, VerifyOptions{Now: t0}); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v, want ErrBadSignature", err)
	}
}

func TestVerifyRejectsSwappedContexts(t *testing.T) {
	f := newFixture(t)
	var sr SignedRelease
	if err := json.Unmarshal(f.signedData, &sr); err != nil {
		t.Fatal(err)
	}
	// A root-signed certificate presented as the manifest must fail.
	sr.Manifest = sr.Certificate
	data, _ := json.Marshal(sr)
	if _, err := Verify(f.root, data, VerifyOptions{Now: t0}); err == nil {
		t.Fatal("certificate accepted as manifest")
	}
}

func TestVerifyRejectsUnknownFieldsAndTrailingData(t *testing.T) {
	f := newFixture(t)
	if _, err := Verify(f.root, append(append([]byte(nil), f.signedData...), []byte("{}")...), VerifyOptions{Now: t0}); err == nil {
		t.Fatal("trailing data accepted")
	}
	bad := bytes.Replace(f.signedData, []byte(`"format"`), []byte(`"extra": 1, "format"`), 1)
	if _, err := Verify(f.root, bad, VerifyOptions{Now: t0}); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestCertificateValidity(t *testing.T) {
	f := newFixture(t)
	// Signing outside the validity period is refused.
	if _, err := SignManifest(f.signPriv, f.certEnv, f.root, f.manifest, t0.Add(DefaultCertificateValidity+2*time.Hour)); !errors.Is(err, ErrCertificateExpired) {
		t.Fatalf("got %v, want ErrCertificateExpired", err)
	}
	// An old release stays verifiable after the certificate expired...
	later := t0.Add(DefaultCertificateValidity + 30*24*time.Hour)
	if _, err := Verify(f.root, f.signedData, VerifyOptions{Now: later}); err != nil {
		t.Fatal(err)
	}
	// ...unless the caller requires a currently valid certificate.
	if _, err := Verify(f.root, f.signedData, VerifyOptions{Now: later, RequireValidNow: true}); !errors.Is(err, ErrCertificateExpired) {
		t.Fatalf("got %v, want ErrCertificateExpired", err)
	}
	// A manifest from the future is refused.
	if _, err := Verify(f.root, f.signedData, VerifyOptions{Now: t0.Add(-time.Hour)}); err == nil {
		t.Fatal("future manifest accepted")
	}
	// Too long validity is refused at issue time.
	if _, _, err := IssueCertificate(f.rootPriv, CertificateRequest{SigningKey: f.signing, NotBefore: t0, Validity: MaxCertificateValidity + time.Hour}); err == nil {
		t.Fatal("over-long certificate issued")
	}
	// The root key cannot certify itself.
	if _, _, err := IssueCertificate(f.rootPriv, CertificateRequest{SigningKey: f.root, NotBefore: t0, Validity: time.Hour}); err == nil {
		t.Fatal("root certified itself")
	}
}

func TestSignManifestChecksKeyAndRoot(t *testing.T) {
	f := newFixture(t)
	_, otherPriv, _ := GenerateKey(rand.Reader)
	if _, err := SignManifest(otherPriv, f.certEnv, f.root, f.manifest, t0); err == nil {
		t.Fatal("signed with a key the certificate does not name")
	}
	otherRoot, _, _ := GenerateKey(rand.Reader)
	if _, err := SignManifest(f.signPriv, f.certEnv, otherRoot, f.manifest, t0); err == nil {
		t.Fatal("signed with a certificate from another root")
	}
}

func TestRevocations(t *testing.T) {
	f := newFixture(t)
	data, err := SignRevocations(f.rootPriv, Revocations{Sequence: 2, Issued: t0, Revoked: []RevokedKey{{SigningKey: f.signing, Reason: "lost laptop"}}})
	if err != nil {
		t.Fatal(err)
	}
	rev, err := VerifyRevocations(f.root, data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(f.root, f.signedData, VerifyOptions{Now: t0, Revocations: rev}); !errors.Is(err, ErrRevoked) {
		t.Fatalf("got %v, want ErrRevoked", err)
	}
	other, _, _ := GenerateKey(rand.Reader)
	if _, err := VerifyRevocations(other, data); err == nil {
		t.Fatal("revocations verified with another root")
	}
	// A list signed by the signing key is not a revocation list.
	if _, err := SignRevocations(f.rootPriv, Revocations{Issued: t0, Revoked: []RevokedKey{{SigningKey: f.root}}}); err == nil {
		t.Fatal("root revoked itself")
	}
}

func TestManifestValidation(t *testing.T) {
	f := newFixture(t)
	cases := map[string]Manifest{
		"path":      NewManifest("1.0.0", "", 0, []Artifact{{Name: "../x", SHA256: strings.Repeat("a", 64)}}),
		"slash":     NewManifest("1.0.0", "", 0, []Artifact{{Name: "a/b", SHA256: strings.Repeat("a", 64)}}),
		"dot":       NewManifest("1.0.0", "", 0, []Artifact{{Name: ".hidden", SHA256: strings.Repeat("a", 64)}}),
		"duplicate": NewManifest("1.0.0", "", 0, []Artifact{{Name: "A", SHA256: strings.Repeat("a", 64)}, {Name: "a", SHA256: strings.Repeat("a", 64)}}),
		"hash":      NewManifest("1.0.0", "", 0, []Artifact{{Name: "a", SHA256: strings.Repeat("A", 64)}}),
		"version":   NewManifest("1.0", "", 0, []Artifact{{Name: "a", SHA256: strings.Repeat("a", 64)}}),
		"empty":     NewManifest("1.0.0", "", 0, nil),
		"build":     NewManifest("1.0.0", "a b", 0, []Artifact{{Name: "a", SHA256: strings.Repeat("a", 64)}}),
	}
	for name, m := range cases {
		if _, err := SignManifest(f.signPriv, f.certEnv, f.root, m, t0); err == nil {
			t.Errorf("%s: invalid manifest signed", name)
		}
	}
}

func TestSealedKey(t *testing.T) {
	_, priv, _ := GenerateKey(rand.Reader)
	pass := []byte("doğru at pil zımba 42")
	s, err := SealKey(priv, RoleSigning, pass, DefaultKDF, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	data, err := MarshalSealedKey(s)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := UnmarshalSealedKey(data)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s2.Open(pass)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, priv) {
		t.Fatal("opened key differs")
	}
	if _, err := s2.Open([]byte("wrong passphrase 123")); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("got %v", err)
	}
	// Relabelling a signing key as a root key breaks decryption.
	s2.Role = RoleRoot
	if _, err := s2.Open(pass); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("role change: got %v", err)
	}
	if _, err := SealKey(priv, RoleRoot, []byte("aaaaaaaaaaaaaaa"), DefaultKDF, rand.Reader); !errors.Is(err, ErrWeakPassphrase) {
		t.Fatalf("weak passphrase: got %v", err)
	}
	weak := DefaultKDF
	weak.MemoryKiB = 1024
	if _, err := SealKey(priv, RoleRoot, pass, weak, rand.Reader); err == nil {
		t.Fatal("weak KDF accepted")
	}
}

func TestPublicKeyText(t *testing.T) {
	k, _, _ := GenerateKey(rand.Reader)
	p, err := ParsePublicKey("  " + k.String() + "\n")
	if err != nil {
		t.Fatal(err)
	}
	if !p.Equal(k) {
		t.Fatal("round trip failed")
	}
	if _, err := ParsePublicKey("osrelkey1:AAAA"); err == nil {
		t.Fatal("short key accepted")
	}
	if _, err := ParsePublicKey(strings.TrimPrefix(k.String(), PublicKeyPrefix)); err == nil {
		t.Fatal("key without prefix accepted")
	}
	if NormalizeFingerprint(k.Fingerprint()) == "" || len(NormalizeFingerprint(k.Fingerprint())) != 64 {
		t.Fatal("bad fingerprint")
	}
}

func TestVersions(t *testing.T) {
	ordered := []string{"0.0.0-dev", "0.8.0-alpha", "0.8.0-alpha.1", "0.8.0-alpha.beta", "0.8.0-beta.2", "0.8.0-beta.11", "0.8.0-rc.1", "0.8.0", "0.8.1", "0.10.0", "1.0.0"}
	for i := 0; i+1 < len(ordered); i++ {
		c, err := CompareVersions(ordered[i], ordered[i+1])
		if err != nil {
			t.Fatal(err)
		}
		if c != -1 {
			t.Errorf("%s should be < %s", ordered[i], ordered[i+1])
		}
	}
	if c, _ := CompareVersions("1.2.3+build.5", "1.2.3"); c != 0 {
		t.Error("build metadata must not affect precedence")
	}
	for _, bad := range []string{"", "1", "1.2", "01.2.3", "1.2.3-", "1.2.3-01", "v1.2.3", "1.2.3 ", "1..3"} {
		if _, err := ParseVersion(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if err := CheckUpgrade("0.9.0", "0.8.0", false); !errors.Is(err, ErrRollback) {
		t.Fatalf("got %v, want ErrRollback", err)
	}
	if err := CheckUpgrade("0.9.0", "0.8.0", true); err != nil {
		t.Fatal(err)
	}
	if err := CheckUpgrade("0.9.0", "0.9.0", false); err != nil {
		t.Fatal(err)
	}
	if err := CheckUpgrade("0.0.0-dev", "0.9.0", false); err != nil {
		t.Fatal(err)
	}
}
