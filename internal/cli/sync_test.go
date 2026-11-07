package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestSyncKeyAndUsage(t *testing.T) {
	h := newHarness(t)
	key := filepath.Join(t.TempDir(), "yedek.key")
	out := h.run(exitOK, "sync", "key", "init", "--key", key)
	if !strings.Contains(out, "Parmak izi:") || !strings.Contains(out, "export") {
		t.Fatalf("init output: %s", out)
	}
	fp := out[strings.Index(out, "Parmak izi:"):]
	fp = strings.TrimSpace(strings.SplitN(fp, "\n", 2)[0])
	if again := h.run(exitOK, "sync", "key", "show", "--key", key); !strings.Contains(again, strings.TrimPrefix(fp, "Parmak izi: ")) {
		t.Fatalf("show: %s", again)
	}
	// Export needs a terminal for the passphrase.
	h.run(exitError, "sync", "key", "export", "--key", key)
	h.run(exitUsage, "sync")
	h.run(exitUsage, "sync", "nope")
	h.run(exitUsage, "sync", "pull", "tek-arguman")
	h.run(exitUsage, "sync", "serve")
	h.run(exitUsage, "sync", "backup", t.TempDir(), "cihaz", "--store", "Büyük Harf", "--key", key)
}
