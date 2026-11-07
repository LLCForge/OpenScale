//go:build !windows

package rdesk

import "context"

// NewSystemFrame is only implemented on Windows; elsewhere a session with
// Config.RequireFrame does not start (ADR-0200).
func NewSystemFrame(FrameInfo) (SessionFrame, error) { return nil, ErrUnsupported }

// WatchKillHotkey is only implemented on Windows (ADR-0200).
func WatchKillHotkey(context.Context, Hotkey, func()) error { return ErrUnsupported }
