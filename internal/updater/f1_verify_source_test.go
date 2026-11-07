package updater

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/openscale/openscale/internal/release"
)

// VerifySource refuses what Apply would refuse, and leaves no trace.
func TestVerifySourceHonoursPublishedList(t *testing.T) {
	f := newFixture(t)
	dir := f.release("0.9.0", program("0.9.0", "ok"))
	load := func() Source {
		t.Helper()
		src, err := LoadSource(context.Background(), dir, "", artifact, nil)
		if err != nil {
			t.Fatal(err)
		}
		return src
	}
	listPath := filepath.Join(dir, RevocationsFile)

	if _, err := VerifySource(f.opts(), load()); err != nil {
		t.Fatalf("no list: %v", err)
	}
	if err := os.WriteFile(listPath, f.signList(2, true), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySource(f.opts(), load()); !errors.Is(err, release.ErrRevoked) {
		t.Fatalf("published list: got %v, want ErrRevoked", err)
	}
	if _, err := os.Stat(filepath.Join(f.state, RevocationsFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("verification stored the list: %v", err)
	}

	// A published list that does not verify is refused.
	if err := os.WriteFile(listPath, []byte("bozuk"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySource(f.opts(), load()); err == nil {
		t.Fatal("damaged published list accepted")
	}

	// A stale published list cannot lift what the device already knows.
	if _, err := InstallRevocations(f.state, f.root, f.signList(5, true)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(listPath, f.signList(1, false), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySource(f.opts(), load()); !errors.Is(err, release.ErrRevoked) {
		t.Fatalf("stale published list: got %v, want ErrRevoked", err)
	}
}

// EnforcedRevocations picks the newest of the known, given and published lists.
func TestEnforcedRevocationsPicksNewest(t *testing.T) {
	f := newFixture(t)
	if list, err := EnforcedRevocations(f.state, f.root, nil, nil, nil); err != nil || list != nil {
		t.Fatalf("nothing known: %+v, %v", list, err)
	}
	if _, err := InstallRevocations(f.state, f.root, f.signList(3, false)); err != nil {
		t.Fatal(err)
	}
	list, err := EnforcedRevocations(f.state, f.root, nil, f.signList(7, false), nil)
	if err != nil || list == nil || list.Sequence != 7 {
		t.Fatalf("published newer: %+v, %v", list, err)
	}
	if list, err = EnforcedRevocations(f.state, f.root, nil, f.signList(1, false), nil); err != nil || list == nil || list.Sequence != 3 {
		t.Fatalf("published older: %+v, %v", list, err)
	}
	older, err := release.VerifyRevocations(f.root, f.signList(1, false))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = EnforcedRevocations(f.state, f.root, older, nil, nil); !errors.Is(err, ErrRevocationsStale) {
		t.Fatalf("given older: got %v, want ErrRevocationsStale", err)
	}
}
