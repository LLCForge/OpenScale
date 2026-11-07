package release

import (
	"bytes"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"
)

func witnessFixture(t *testing.T) (*fixture, *Verified, string, PublicKey, []byte) {
	t.Helper()
	f := newFixture(t)
	v, err := Verify(f.root, f.signedData, VerifyOptions{Now: t0.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := ManifestDigest(f.signedData)
	if err != nil {
		t.Fatal(err)
	}
	wk, wpriv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// The independent machine reproduced the Linux binary only.
	a, err := HashArtifact("openscale-linux-amd64", strings.NewReader("linux binary"))
	if err != nil {
		t.Fatal(err)
	}
	w, err := NewWitness(v, digest, "ikinci derleme makinesi", []Artifact{a}, t0.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	data, err := SignWitness(wpriv, w)
	if err != nil {
		t.Fatal(err)
	}
	return f, v, digest, wk, data
}

func TestWitness(t *testing.T) {
	f, v, digest, wk, data := witnessFixture(t)
	w, err := VerifyWitness(wk, data)
	if err != nil {
		t.Fatal(err)
	}
	names, err := w.Confirms(&v.Manifest, digest)
	if err != nil || len(names) != 1 || names[0] != "openscale-linux-amd64" {
		t.Fatalf("confirms %v %v", names, err)
	}

	// Another key, a changed byte and a swapped context are refused.
	other, _, _ := GenerateKey(rand.Reader)
	if _, err := VerifyWitness(other, data); err == nil {
		t.Error("witness verified with another key")
	}
	if _, err := VerifyWitness(wk, bytes.Replace(data, []byte(`"payload": "`), []byte(`"payload": "A`), 1)); err == nil {
		t.Error("tampered witness verified")
	}
	if _, err := VerifyWitness(f.root, f.signedData); err == nil {
		t.Error("signed release accepted as witness")
	}

	// A witness for another manifest (re-signed release) does not confirm.
	if _, err := w.Confirms(&v.Manifest, strings.Repeat("0", 64)); !errors.Is(err, ErrWitnessMismatch) {
		t.Errorf("other manifest digest: %v", err)
	}
	// A different independent build is never signed.
	bad, _ := HashArtifact("openscale-linux-amd64", strings.NewReader("altered binary"))
	if _, err := NewWitness(v, digest, "x", []Artifact{bad}, t0); !errors.Is(err, ErrWitnessMismatch) {
		t.Errorf("mismatching build signed: %v", err)
	}
	unknown, _ := HashArtifact("extra.bin", strings.NewReader("x"))
	if _, err := NewWitness(v, digest, "x", []Artifact{unknown}, t0); !errors.Is(err, ErrWitnessMismatch) {
		t.Errorf("file outside the manifest signed: %v", err)
	}
	if _, err := NewWitness(v, digest, "x", nil, t0); err == nil {
		t.Error("empty witness signed")
	}
}

// The witness role is a sealed key role of its own.
func TestWitnessSealedKey(t *testing.T) {
	_, priv, _ := GenerateKey(rand.Reader)
	s, err := SealKey(priv, RoleWitness, []byte("tanık anahtarı parolası"), KDFParams{Time: 1, MemoryKiB: 64 * 1024, Threads: 1}, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	data, err := MarshalSealedKey(s)
	if err != nil {
		t.Fatal(err)
	}
	back, err := UnmarshalSealedKey(data)
	if err != nil || back.Role != RoleWitness {
		t.Fatalf("%v %v", back, err)
	}
	if _, err := SealKey(priv, "other", []byte("tanık anahtarı parolası"), DefaultKDF, rand.Reader); err == nil {
		t.Error("unknown role sealed")
	}
}

// The manifest format is unchanged by the witness (ADR-0148): a signed
// release has exactly the fields it had before.
func TestManifestEncodingUnchangedByWitness(t *testing.T) {
	f := newFixture(t)
	for _, field := range []string{"witness", "witnesses"} {
		if bytes.Contains(f.signedData, []byte(field)) {
			t.Fatalf("signed release mentions %q", field)
		}
	}
}

func FuzzVerifyWitness(fz *testing.F) {
	k, priv, _ := GenerateKey(rand.Reader)
	a, _ := HashArtifact("openscale-linux-amd64", strings.NewReader("x"))
	w := Witness{Builder: "b", Product: Product, Version: "1.0.0", Build: "1", ManifestSHA256: strings.Repeat("ab", 32), Created: t0, Artifacts: []Artifact{a}}
	data, err := SignWitness(priv, w)
	if err != nil {
		fz.Fatal(err)
	}
	fz.Add(data)
	fz.Add([]byte(`{"context":"openscale/release-witness/v1","payload":"e30=","signature":"AA=="}`))
	fz.Fuzz(func(t *testing.T, b []byte) {
		w, err := VerifyWitness(k, b)
		if err != nil {
			return
		}
		if w.validate() != nil {
			t.Fatal("verified witness is invalid")
		}
	})
}
