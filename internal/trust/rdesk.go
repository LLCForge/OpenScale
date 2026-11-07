package trust

// Remote desktop rules (ADR-0055).
//
// An rdesk rule grants watching the destination's screen. allow_control
// additionally grants keyboard, mouse and clipboard input, and
// allow_unattended lets the session start without the on-screen approval
// of the person at the destination. Watching and controlling are separate
// permissions: a session asks for one mode and gets it only when a rule
// permits exactly that mode. Every session, attended or not, shows a
// visible indicator on the destination and is logged there.

// RemoteDesktopMode is what a remote desktop session may do.
type RemoteDesktopMode string

// Remote desktop modes.
const (
	// RemoteDesktopView only watches the screen.
	RemoteDesktopView RemoteDesktopMode = "view"
	// RemoteDesktopControl watches and sends keyboard, mouse and
	// clipboard input.
	RemoteDesktopControl RemoteDesktopMode = "control"
)

// Valid reports whether m is a known mode.
func (m RemoteDesktopMode) Valid() bool {
	return m == RemoteDesktopView || m == RemoteDesktopControl
}

func remoteDesktopPermits(r Rule, mode RemoteDesktopMode) bool {
	switch mode {
	case RemoteDesktopView:
		return true
	case RemoteDesktopControl:
		return r.AllowControl
	}
	return false
}

// AllowsRemoteDesktop reports whether device from may open a remote
// desktop session of the given mode on device to. View needs any enabled
// rdesk allow rule; control needs one with allow_control. A matching rdesk
// deny rule, or a packet deny rule over the service port, wins.
func (doc *Document) AllowsRemoteDesktop(from, to string, mode RemoteDesktopMode) bool {
	if !mode.Valid() {
		return false
	}
	return doc.serviceAllowed(ServiceRemoteDesktop, from, to, func(r Rule) bool {
		return remoteDesktopPermits(r, mode)
	})
}

// RemoteDesktopUnattended reports whether a session of from on to in the
// given mode may start without on-screen approval: a rule that permits the
// mode must also set allow_unattended. It is false whenever
// AllowsRemoteDesktop is false.
func (doc *Document) RemoteDesktopUnattended(from, to string, mode RemoteDesktopMode) bool {
	if !mode.Valid() {
		return false
	}
	return doc.serviceAllowed(ServiceRemoteDesktop, from, to, func(r Rule) bool {
		return r.AllowUnattended && remoteDesktopPermits(r, mode)
	})
}
