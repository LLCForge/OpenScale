package service

import (
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openscale/openscale/internal/coordinator"
	"github.com/openscale/openscale/internal/trust"
)

func newIdleRuntime(t *testing.T) *Runtime {
	t.Helper()
	r, err := New(Config{
		DataDir: t.TempDir(),
		Argon2:  trust.Argon2Params{Time: 1, MemoryKiB: 64 * 1024, Threads: 1},
		Random:  rand.Reader,
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// The service reads the coordinator's disguise file before it builds the
// coordinator; a broken file stops the start instead of running plain.
func TestServiceCoordinatorObfsFile(t *testing.T) {
	r := newIdleRuntime(t)
	dir := r.path(CoordinatorDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, coordinator.ObfsFileName), []byte(`{"mode":"on"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.newCoordinatorWithObfs(context.Background(), coordinator.Config{}); err == nil {
		t.Fatal("broken disguise file accepted")
	}
	if err := coordinator.SaveObfsFile(dir, coordinator.ObfsFile{Mode: "auto"}); err != nil {
		t.Fatal(err)
	}
	_, err := r.newCoordinatorWithObfs(context.Background(), coordinator.Config{})
	if err == nil || !strings.Contains(err.Error(), "belgesi yok") {
		t.Fatalf("auto without a document: %v", err)
	}
}
