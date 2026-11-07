//go:build windows

package privsep

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The restricted token really starts a process at low integrity, and its
// restricting SIDs keep it from a file that only the account may read
// (low integrity alone would still allow reading it). System programs are
// used because they are readable by Users, like an installed program.
func TestRestrictedTokenStartsLowIntegrity(t *testing.T) {
	sys := filepath.Join(os.Getenv("SystemRoot"), "System32")
	whoami, cmdExe := filepath.Join(sys, "whoami.exe"), filepath.Join(sys, "cmd.exe")
	if _, err := os.Stat(whoami); err != nil {
		t.Skip("whoami.exe not found")
	}
	cmd, release, err := Command(whoami, []string{"/groups", "/fo", "csv", "/nh"}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.Output()
	release()
	if err != nil {
		t.Fatalf("restricted whoami: %v %s", err, out)
	}
	if !strings.Contains(string(out), "S-1-16-4096") { // Mandatory Label\Low Mandatory Level
		t.Fatalf("not low integrity:\n%s", out)
	}

	// The temporary directory is the account's own: Users has no access.
	secret := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(secret, []byte("gizli-icerik"), 0o600); err != nil {
		t.Fatal(err)
	}
	plain, err := exec.Command(cmdExe, "/c", "type", secret).Output()
	if err != nil || !strings.Contains(string(plain), "gizli-icerik") {
		t.Skipf("control read failed (%v); the directory is not the account's own", err)
	}
	cmd, release, err = Command(cmdExe, []string{"/c", "type", secret}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	out, _ = cmd.Output()
	release()
	if strings.Contains(string(out), "gizli-icerik") {
		t.Fatal("restricted process read a file only the account may read")
	}
}
