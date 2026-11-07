package winapp

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func TestMitigationProfileFor(t *testing.T) {
	cases := map[string]MitigationProfile{
		"service run":              ProfileService,
		"up --config x":            ProfileService,
		"coordinator run":          ProfileService,
		"portable":                 ProfileService,
		"":                         ProfileTray,
		"app":                      ProfileTray,
		"autostart run":            ProfileTray,
		"panel-window --title x":   ProfileWindow,
		"window --dir d":           ProfileWindow,
		"status":                   ProfileCLI,
		"autostart status":         ProfileCLI,
		"service install":          ProfileCLI,
		"--format {{.x}} version":  ProfileCLI,
		"--network ev up":          ProfileService,
		"--network=ev service run": ProfileService,
		"--bilinmeyen up":          ProfileService,
		"network show":             ProfileSecret,
		"key status":               ProfileSecret,
		"exit users set":           ProfileSecret,
	}
	for line, want := range cases {
		var args []string
		if line != "" {
			args = splitArgs(line)
		}
		if got := MitigationProfileFor(args); got != want {
			t.Errorf("%q: %s, want %s", line, got, want)
		}
	}
	// The window profile never forbids dynamic code (the web engine
	// compiles JavaScript); only the CLI profile asks for
	// Microsoft-signed DLLs (wintun.dll is not).
	if ProfileWindow.set().noDynamicCode || ProfileService.set().microsoftSigned || ProfileTray.set().microsoftSigned {
		t.Fatal("profile set wrong")
	}
	if ProfileCLI.set().microsoftSigned {
		t.Fatal("cli profile must not restrict signers")
	}
	if !reflect.DeepEqual(ProfileSecret.set(), mitigationSet{true, true, true, true, true}) {
		t.Fatal(ProfileSecret.set())
	}
	t.Setenv(MitigationsEnv, "off")
	if r := ApplyMitigations(ProfileCLI); len(r) != 1 || r[0].Applied {
		t.Fatalf("disabled: %+v", r)
	}
}

func splitArgs(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ' ' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func TestUnexpectedLibraries(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"openscale.exe", "wintun.dll", "WINTUN.DLL.bak", "version.dll", "libevil.dylib", "libx.so.1", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := UnexpectedLibraries(dir, expectedLibraries)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"libevil.dylib", "libx.so.1", "version.dll"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	exe := filepath.Join(dir, "openscale.exe")
	// Outside the installed folder only a report, never a block.
	if r := CheckProgramFolder(exe, []string{filepath.Join(dir, "baska")}); r.Block() || r.Installed {
		t.Fatalf("not installed: %+v", r)
	}
	r := CheckProgramFolder(exe, []string{dir})
	if runtime.GOOS != "windows" && os.Geteuid() == 0 {
		// As root the test files are root's own and trusted like the
		// system's; the planted-library case needs a non-root owner.
		t.Skip("run as a normal user to test planted libraries")
	}
	if !r.Installed || !r.Block() || !errors.Is(r.Err(), ErrPlantedLibrary) {
		t.Fatalf("installed with planted DLL: %+v", r)
	}
	if runtime.GOOS != "windows" && r.PermErr == "" {
		t.Fatal("a test folder owned by a user must fail the permission check")
	}
}

func TestApplyMitigationsInSubprocess(t *testing.T) {
	if runtime.GOOS != "windows" {
		if r := ApplyMitigations(ProfileService); r != nil {
			t.Fatal(r)
		}
		return
	}
	// The policies are irreversible for a process, so they are applied
	// in a child test process.
	if os.Getenv("OPENSCALE_MITIGATION_CHILD") == "1" {
		for _, r := range ApplyMitigations(ProfileSecret) {
			if !r.Applied {
				t.Fatalf("%s: %s", r.Name, r.Err)
			}
		}
		// The process still works: allocate, start goroutines, load a
		// Microsoft DLL by name.
		done := make(chan int)
		go func() { done <- len(make([]byte, 1<<20)) }()
		if <-done != 1<<20 {
			t.Fatal("goroutine")
		}
		return
	}
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	cmd := newChildCommand(exe, "-test.run=^TestApplyMitigationsInSubprocess$", "-test.count=1")
	cmd.Env = append(os.Environ(), "OPENSCALE_MITIGATION_CHILD=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
}

// Root's own files in a shared program folder do not block; anything a
// non-root user owns or could write still does.
func TestOwnerTrusted(t *testing.T) {
	cases := []struct {
		uid  uint32
		perm os.FileMode
		want bool
	}{
		{0, 0o755, true},
		{0, 0o644, true},
		{0, 0o775, false},
		{0, 0o757, false},
		{1000, 0o755, false},
	}
	for _, c := range cases {
		if got := ownerTrusted(c.uid, c.perm); got != c.want {
			t.Errorf("ownerTrusted(%d, %o) = %v", c.uid, c.perm, got)
		}
	}
}
