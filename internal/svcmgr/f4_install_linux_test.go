//go:build linux

package svcmgr

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

const swapHelperEnv = "OPENSCALE_F4_SWAP_DST"

// TestHelperInstallAfterSwap plays "sudo ./openscale service install": another
// process has renamed the program and put its own file at the same path.
func TestHelperInstallAfterSwap(t *testing.T) {
	dst := os.Getenv(swapHelperEnv)
	if dst == "" {
		t.Skip("yardımcı süreç")
	}
	path := os.Args[0]
	if err := os.Rename(path, path+".asil"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("saldirganin programi"), 0o755); err != nil {
		t.Fatal(err)
	}
	src, err := runningProgramPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := copyProgram(src, dst); err != nil {
		t.Fatal(err)
	}
}

func TestInstallCopiesRunningImageAfterSwap(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	exe := filepath.Join(dir, "openscale")
	if err := os.WriteFile(exe, want, 0o755); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "kurulu")
	cmd := exec.Command(exe, "-test.run=^TestHelperInstallAfterSwap$")
	cmd.Env = append(os.Environ(), swapHelperEnv+"="+dst)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("yardımcı: %v\n%s", err, out)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("kurulan dosya çalışan program değil (%d bayt): yol yeniden okundu", len(got))
	}
}
