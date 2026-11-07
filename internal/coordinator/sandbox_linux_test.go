//go:build linux

package coordinator

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestLandlockRestrictsFiles runs the sandbox in a child process (it cannot
// be undone) and checks that the state directory stays writable while
// another directory does not. Kernels without Landlock skip.
func TestLandlockRestrictsFiles(t *testing.T) {
	if dir := os.Getenv("OPENSCALE_LANDLOCK_CHILD"); dir != "" {
		landlockChild(dir, os.Getenv("OPENSCALE_LANDLOCK_OTHER"))
		return
	}
	state, other := t.TempDir(), t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestLandlockRestrictsFiles$", "-test.v")
	cmd.Env = append(os.Environ(), "OPENSCALE_LANDLOCK_CHILD="+state, "OPENSCALE_LANDLOCK_OTHER="+other)
	out, err := cmd.CombinedOutput()
	text := string(out)
	switch {
	case strings.Contains(text, "LANDLOCK-SKIP"):
		t.Skipf("Landlock unavailable: %s", text)
	case err != nil || !strings.Contains(text, "LANDLOCK-OK"):
		t.Fatalf("child: %v\n%s", err, text)
	}
	t.Logf("child: %s", strings.TrimSpace(text))
}

func landlockChild(state, other string) {
	res := RestrictFiles(state)
	if !res.Applied {
		os.Stdout.WriteString("LANDLOCK-SKIP " + res.Reason + "\n")
		return
	}
	if err := os.WriteFile(filepath.Join(state, "a.tmp"), []byte("x"), 0o600); err != nil {
		os.Stdout.WriteString("state dir not writable: " + err.Error() + "\n")
		os.Exit(1)
	}
	if err := os.Rename(filepath.Join(state, "a.tmp"), filepath.Join(state, "a")); err != nil {
		os.Stdout.WriteString("rename in state dir failed: " + err.Error() + "\n")
		os.Exit(1)
	}
	err := os.WriteFile(filepath.Join(other, "b"), []byte("x"), 0o600)
	if err == nil || !errors.Is(err, os.ErrPermission) {
		os.Stdout.WriteString("write outside the state dir was not denied\n")
		os.Exit(1)
	}
	if _, err := os.ReadFile("/etc/hostname"); err != nil && !errors.Is(err, os.ErrNotExist) {
		os.Stdout.WriteString("/etc not readable: " + err.Error() + "\n")
		os.Exit(1)
	}
	os.Stdout.WriteString("LANDLOCK-OK\n")
}
