//go:build !windows

package service

// newRemoteDesktopHost returns nil: outside Windows the service runs as
// root without the user's display; "openscale up --rdesk" runs the server
// in the desktop session instead (ADR-0110).
func (r *Runtime) newRemoteDesktopHost() RemoteDesktopHost { return nil }

func (r *Runtime) helperHost() *helperHost { return nil }
