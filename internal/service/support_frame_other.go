//go:build !windows

package service

// canDrawFrame: the #671 frame exists only on Windows so far; elsewhere
// the support notice is the notification and the panel bar (ADR-0232).
func canDrawFrame() bool { return false }
