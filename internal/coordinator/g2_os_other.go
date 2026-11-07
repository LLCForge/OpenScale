//go:build !linux

package coordinator

import "runtime"

// stateFileSystem cannot tell a RAM file system apart outside Linux; RAM
// mode is refused there (fail closed).
func stateFileSystem(string) (string, bool, error) { return runtime.GOOS, false, nil }

func swapActive() bool { return false }

// ensureNoCoreDumps: on Windows crash dumps are turned off by the privacy
// package at process start (WER exclusion, cmd/openscale/hardening.go); on
// other systems RLIMIT_CORE is set there as well. Nothing more to do here.
func ensureNoCoreDumps() string { return "process" }
