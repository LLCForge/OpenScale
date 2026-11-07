//go:build !windows

package svcmgr

import (
	"os"
	"runtime"
)

// autostartPaths resolves the entry files of this system.
func autostartPath(scope Scope) (string, error) {
	if scope == ScopeAllUsers {
		return SystemAutostartPath(runtime.GOOS)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return UserAutostartPath(runtime.GOOS, home, os.Getenv("XDG_CONFIG_HOME"))
}

// EnableAutostart writes the sign-in entry for exe. The all-users entry
// needs root.
func EnableAutostart(scope Scope, exe string) (AutostartEntry, error) {
	p, err := autostartPath(scope)
	if err != nil {
		return AutostartEntry{Scope: scope}, err
	}
	if scope == ScopeAllUsers && os.Geteuid() != 0 {
		return AutostartEntry{Scope: scope, Path: p}, ErrNeedsRoot
	}
	data, err := RenderAutostart(runtime.GOOS, exe)
	if err != nil {
		return AutostartEntry{Scope: scope, Path: p}, err
	}
	dirPerm := os.FileMode(0o700)
	if scope == ScopeAllUsers {
		dirPerm = 0o755
	}
	removeLegacyAutostart(p)
	if err := writeAutostartFile(p, data, dirPerm); err != nil {
		return AutostartEntry{Scope: scope, Path: p}, err
	}
	return AutostartEntry{Scope: scope, Path: p, Installed: true, Ours: true, Program: exe}, nil
}

// DisableAutostart removes the entry if OpenScale wrote it.
func DisableAutostart(scope Scope) (bool, error) {
	p, err := autostartPath(scope)
	if err != nil {
		return false, err
	}
	if scope == ScopeAllUsers && os.Geteuid() != 0 {
		return false, ErrNeedsRoot
	}
	legacy := removeLegacyAutostart(p)
	removed, err := removeAutostartFile(p)
	return removed || legacy, err
}

// AutostartState describes the entry of scope.
func AutostartState(scope Scope) (AutostartEntry, error) {
	p, err := autostartPath(scope)
	if err != nil {
		return AutostartEntry{Scope: scope}, err
	}
	e, err := autostartFileState(scope, p)
	if err != nil {
		return e, err
	}
	return legacyAutostartState(e), nil
}
