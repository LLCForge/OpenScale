//go:build windows

package winapp

import "testing"

func TestRunCommand(t *testing.T) {
	got, err := RunCommand(`C:\Program Files\OpenScale\openscale.exe`, "autostart", "run")
	if err != nil || got != `"C:\Program Files\OpenScale\openscale.exe" autostart run` {
		t.Fatalf("RunCommand = %q, %v", got, err)
	}
	if p := RunCommandProgram(got); p != `C:\Program Files\OpenScale\openscale.exe` {
		t.Fatalf("program = %q", p)
	}
	for _, bad := range [][]string{
		{`openscale.exe`},
		{`C:\a"b\openscale.exe`},
		{`C:\%TEMP%\openscale.exe`},
		{`C:\OpenScale\openscale.exe`, "a b"},
		{`C:\OpenScale\openscale.exe`, ""},
		{`C:\OpenScale\openscale.exe`, "x\"y"},
	} {
		if _, err := RunCommand(bad[0], bad[1:]...); err == nil {
			t.Errorf("RunCommand(%q) accepted", bad)
		}
	}
	if RunCommandProgram(`openscale.exe run`) != "" || RunCommandProgram(`"unterminated`) != "" {
		t.Fatal("unquoted or broken command parsed")
	}
}
