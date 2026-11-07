//go:build windows

package winapp

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestCheckTrustedPathSystemProgram(t *testing.T) {
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	// System32 belongs to TrustedInstaller; users only read and run.
	if err := CheckTrustedPath(filepath.Join(sys, "netsh.exe")); err != nil {
		t.Fatalf("netsh.exe not trusted: %v", err)
	}
	// Ancestors depend on how this computer was set up; only log.
	if err := CheckTrustedAncestors(filepath.Join(sys, "netsh.exe")); err != nil {
		t.Logf("ancestor warning on this computer: %v", err)
	}
}

func TestCheckTrustedPathUserFolder(t *testing.T) {
	f := filepath.Join(t.TempDir(), "openscale.exe")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if IsElevated() {
		// An elevated test owns the file as Administrators; the user's
		// temp folder still grants the user write access.
		t.Log("elevated test run")
	}
	if err := CheckTrustedPath(f); err == nil {
		t.Fatal("a program in the user's temp folder passed the trust check")
	}
}

func TestCheckTrustedPathProgramFiles(t *testing.T) {
	p := filepath.Join(knownFolder(windows.FOLDERID_ProgramFiles, "ProgramFiles", `C:\Program Files`), "Windows Defender", "MpCmdRun.exe")
	if _, err := os.Stat(p); err != nil {
		t.Skip("Windows Defender not installed")
	}
	if err := CheckTrustedPath(p); err != nil {
		t.Fatalf("a Program Files program failed the trust check: %v", err)
	}
}
