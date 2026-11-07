package updater

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/openscale/openscale/internal/release"
)

// signList returns a root-signed list naming the fixture's signing key when
// revoke is true.
func (f *fixture) signList(seq uint64, revoke bool) []byte {
	f.t.Helper()
	list := release.Revocations{Sequence: seq, Issued: f.now}
	if revoke {
		pub, err := release.PublicKeyFrom(f.signPriv.Public().(ed25519.PublicKey))
		if err != nil {
			f.t.Fatal(err)
		}
		list.Revoked = []release.RevokedKey{{SigningKey: pub, Reason: "sizdi"}}
	}
	data, err := release.SignRevocations(f.rootPriv, list)
	if err != nil {
		f.t.Fatal(err)
	}
	return data
}

// A list once stored on this device applies without --revocations (audit:
// openscale/release/revocation-optional-unpersisted-in-updater, case a).
func TestStoredRevocationsAppliedToUpdate(t *testing.T) {
	f := newFixture(t)
	dir := f.release("0.9.0", program("0.9.0", "ok"))
	if err := os.MkdirAll(f.state, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.state, "revocations.json"), f.signList(1, true), 0o600); err != nil {
		t.Fatal(err)
	}
	src, err := LoadSource(context.Background(), dir, "", artifact, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(f.opts(), src.Manifest); !errors.Is(err, release.ErrRevoked) {
		t.Fatalf("Verify with a stored list: got %v, want ErrRevoked", err)
	}
}

// A revoked signing key blocks the start-up self check (case c).
func TestStoredRevocationsBlockStart(t *testing.T) {
	f := newFixture(t)
	dir := f.release("0.9.0", program("0.9.0", "ok"))
	if _, err := f.apply(f.opts(), dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.state, "revocations.json"), f.signList(1, true), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := CheckInstalled(f.state, f.exe, f.root, f.now); !errors.Is(err, release.ErrRevoked) {
		t.Fatalf("CheckInstalled: got %v, want ErrRevoked", err)
	}
	v := VerifySelf(SelfVerifyConfig{Exe: f.exe, StateDir: f.state, Root: &f.root, Now: f.now, Signature: sig(SignatureAbsent, nil)})
	if !v.Block {
		t.Fatalf("self check passed with a revoked key: %+v", v)
	}
}

// An older list cannot replace the stored one (case d), and two lists with one
// sequence are a conflict.
func TestOlderRevocationsRefused(t *testing.T) {
	f := newFixture(t)
	dir := f.release("0.9.0", program("0.9.0", "ok"))
	if _, err := InstallRevocations(f.state, f.root, f.signList(5, false)); err != nil {
		t.Fatal(err)
	}
	old, err := release.VerifyRevocations(f.root, f.signList(4, false))
	if err != nil {
		t.Fatal(err)
	}
	o := f.opts()
	o.Revocations = old
	src, err := LoadSource(context.Background(), dir, "", artifact, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(o, src.Manifest); !errors.Is(err, ErrRevocationsStale) {
		t.Fatalf("older list: got %v, want ErrRevocationsStale", err)
	}
	if _, err := InstallRevocations(f.state, f.root, f.signList(4, true)); !errors.Is(err, ErrRevocationsStale) {
		t.Fatalf("install older list: got %v, want ErrRevocationsStale", err)
	}
	if _, err := InstallRevocations(f.state, f.root, f.signList(5, true)); !errors.Is(err, ErrRevocationsConflict) {
		t.Fatalf("same sequence: got %v, want ErrRevocationsConflict", err)
	}
}

// A given list is remembered even when it refuses this very release, and it
// then applies with no flag at all.
func TestApplyStoresGivenRevocations(t *testing.T) {
	f := newFixture(t)
	dir := f.release("0.9.0", program("0.9.0", "ok"))
	list, err := release.VerifyRevocations(f.root, f.signList(1, true))
	if err != nil {
		t.Fatal(err)
	}
	o := f.opts()
	o.Revocations = list
	if _, err := f.apply(o, dir); !errors.Is(err, release.ErrRevoked) {
		t.Fatalf("Apply: got %v, want ErrRevoked", err)
	}
	if f.installedVersion() != "0.8.0" {
		t.Fatal("the revoked release was installed")
	}
	if _, err := f.apply(f.opts(), dir); !errors.Is(err, release.ErrRevoked) {
		t.Fatalf("Apply without the flag: got %v, want ErrRevoked", err)
	}
}

// A list published next to the manifest is taken and stored; a later release
// without it does not lose it.
func TestApplyTakesListNextToManifest(t *testing.T) {
	f := newFixture(t)
	dir := f.release("0.9.0", program("0.9.0", "ok"))
	if err := os.WriteFile(filepath.Join(dir, RevocationsFile), f.signList(3, false), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := f.apply(f.opts(), dir); err != nil {
		t.Fatal(err)
	}
	known, err := KnownRevocations(f.state, f.root)
	if err != nil || known == nil || known.Sequence != 3 {
		t.Fatalf("stored list: %+v, %v", known, err)
	}
	// A stale list on a mirror is ignored, not an error.
	dir2 := f.release("0.9.1", program("0.9.1", "ok"))
	if err := os.WriteFile(filepath.Join(dir2, RevocationsFile), f.signList(2, true), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := f.apply(f.opts(), dir2); err != nil {
		t.Fatalf("stale list on a mirror: %v", err)
	}
	// A list next to the manifest that does not verify is refused.
	dir3 := f.release("0.9.2", program("0.9.2", "ok"))
	if err := os.WriteFile(filepath.Join(dir3, RevocationsFile), []byte("bozuk"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := f.apply(f.opts(), dir3); err == nil {
		t.Fatal("damaged list accepted")
	}
}

// A stored list that does not verify fails closed in both paths.
func TestDamagedStoredRevocationsFailClosed(t *testing.T) {
	f := newFixture(t)
	dir := f.release("0.9.0", program("0.9.0", "ok"))
	if _, err := f.apply(f.opts(), dir); err != nil {
		t.Fatal(err)
	}
	other, otherPriv, err := release.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := release.SignRevocations(otherPriv, release.Revocations{Sequence: 9, Issued: f.now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := release.VerifyRevocations(other, foreign); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.state, RevocationsFile), foreign, 0o600); err != nil {
		t.Fatal(err)
	}
	src, err := LoadSource(context.Background(), dir, "", artifact, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(f.opts(), src.Manifest); err == nil {
		t.Fatal("Verify passed with a list of another root")
	}
	v := VerifySelf(SelfVerifyConfig{Exe: f.exe, StateDir: f.state, Root: &f.root, Now: f.now, Signature: sig(SignatureAbsent, nil)})
	if !v.Block {
		t.Fatalf("self check passed with a list of another root: %+v", v)
	}
}

// The list embedded at release time applies without any file.
func TestEmbeddedRevocations(t *testing.T) {
	f := newFixture(t)
	dir := f.release("0.9.0", program("0.9.0", "ok"))
	oldRoot, oldList := EmbeddedRootKey, EmbeddedRevocations
	t.Cleanup(func() { EmbeddedRootKey, EmbeddedRevocations = oldRoot, oldList })
	EmbeddedRootKey = f.root.String()
	EmbeddedRevocations = base64.StdEncoding.EncodeToString(f.signList(1, true))
	src, err := LoadSource(context.Background(), dir, "", artifact, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(f.opts(), src.Manifest); !errors.Is(err, release.ErrRevoked) {
		t.Fatalf("embedded list: got %v, want ErrRevoked", err)
	}
	// It speaks only for its own root.
	other, _, err := release.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if list, err := KnownRevocations("", other); err != nil || list != nil {
		t.Fatalf("list for another root: %+v, %v", list, err)
	}
	EmbeddedRevocations = "%%%"
	if _, err := KnownRevocations("", f.root); err == nil {
		t.Fatal("damaged embedded list accepted")
	}
}
