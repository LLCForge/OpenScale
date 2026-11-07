//go:build windows

package svcmgr

import "github.com/openscale/openscale/internal/winapp"

// EnableAutostart writes the Run value for exe. The all-users value
// (HKLM) needs an elevated process.
func EnableAutostart(scope Scope, exe string) (AutostartEntry, error) {
	e := AutostartEntry{Scope: scope, Path: runPath(scope)}
	all := scope == ScopeAllUsers
	if all && !winapp.IsElevated() {
		return e, ErrNeedsAdmin
	}
	cmd, err := winapp.RunCommand(exe, AutostartArgs()...)
	if err != nil {
		return e, err
	}
	if err := winapp.SetRunEntry(all, cmd); err != nil {
		return e, err
	}
	e.Installed, e.Ours, e.Program = true, true, exe
	return e, nil
}

// DisableAutostart removes the Run value.
func DisableAutostart(scope Scope) (bool, error) {
	all := scope == ScopeAllUsers
	if all && !winapp.IsElevated() {
		return false, ErrNeedsAdmin
	}
	_, ok, err := winapp.GetRunEntry(all)
	if err != nil || !ok {
		return false, err
	}
	return true, winapp.DeleteRunEntry(all)
}

// AutostartState describes the Run value of scope.
func AutostartState(scope Scope) (AutostartEntry, error) {
	e := AutostartEntry{Scope: scope, Path: runPath(scope)}
	v, ok, err := winapp.GetRunEntry(scope == ScopeAllUsers)
	if err != nil || !ok {
		return e, err
	}
	e.Installed = true
	e.Program = winapp.RunCommandProgram(v)
	e.Ours = e.Program != ""
	return e, nil
}

func runPath(scope Scope) string {
	root := `HKCU\`
	if scope == ScopeAllUsers {
		root = `HKLM\`
	}
	return root + winapp.RunKeyPath + `\` + winapp.RunValueName
}
