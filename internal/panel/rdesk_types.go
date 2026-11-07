package panel

import (
	"net/netip"
	"time"
)

// Remote desktop service connection (ADR-0055, ADR-0103, ADR-0110).

// RDeskSession is one remote desktop session on this computer.
type RDeskSession struct {
	ID         string     `json:"id"`
	Peer       string     `json:"peer"`
	Mode       string     `json:"mode"`
	Unattended bool       `json:"unattended"`
	Code       string     `json:"code"`
	Recording  bool       `json:"recording"`
	Clipboard  bool       `json:"clipboard"`
	Blank      bool       `json:"blank"`
	InputLock  bool       `json:"inputLock"`
	Started    time.Time  `json:"started"`
	Ended      *time.Time `json:"ended,omitempty"`
	Reason     string     `json:"reason,omitempty"`
}

// RDeskSettings are the owner's switches; every one is off by default.
type RDeskSettings struct {
	// Recording records every session encrypted on this computer.
	Recording bool `json:"recording"`
	// RecordingDays is how long recordings are kept (default 30).
	RecordingDays int `json:"recordingDays"`
	// LocalLock lets a control session blank the screen and lock input.
	LocalLock bool `json:"localLock"`
	// Power lets a control session restart this computer.
	Power bool `json:"power"`
	// FileRoots are the folders a control session with a files rule may
	// browse (ADR-0146); empty turns the session file browser off.
	FileRoots []string `json:"fileRoots"`
}

// RDeskSettingsChange changes some settings; nil keeps a value.
type RDeskSettingsChange struct {
	Recording     *bool `json:"recording"`
	RecordingDays *int  `json:"recordingDays"`
	LocalLock     *bool `json:"localLock"`
	Power         *bool `json:"power"`
	// FileRoots replaces the folder list; an empty list turns it off.
	FileRoots *[]string `json:"fileRoots"`
}

// RDeskStatus is the remote desktop state of this computer.
type RDeskStatus struct {
	// Supported: this computer can run the remote desktop server.
	Supported bool `json:"supported"`
	// Hosted: a rule lets other devices open sessions here.
	Hosted bool `json:"hosted"`
	// Running: the server (or the desktop helper) is listening.
	Running bool   `json:"running"`
	Error   string `json:"error"`
	// Runner is "helper" (Windows desktop helper), "inprocess" or "".
	Runner   string         `json:"runner"`
	Settings RDeskSettings  `json:"settings"`
	Sessions []RDeskSession `json:"sessions"`
	Recent   []RDeskSession `json:"recent"`
}

// RemoteDesktopControl is implemented by the desktop service.
type RemoteDesktopControl interface {
	RDeskStatus() RDeskStatus
	SetRDeskSettings(c RDeskSettingsChange) error
}

// RDeskHelperDecision answers the desktop helper's authorization request.
type RDeskHelperDecision struct {
	Allowed    bool   `json:"allowed"`
	Unattended bool   `json:"unattended"`
	Peer       string `json:"peer"`
	Reason     string `json:"reason"`
	// Files allows the session file browser (ADR-0146).
	Files bool `json:"files,omitempty"`
}

// RDeskHelperState is polled by the helper: Generation changes whenever
// sessions must be checked again; Stop asks it to exit.
type RDeskHelperState struct {
	Generation uint64 `json:"generation"`
	Stop       bool   `json:"stop"`
}

// RDeskHelperEvent is a session event the helper reports.
type RDeskHelperEvent struct {
	Kind       string `json:"kind"`
	ID         uint64 `json:"id"`
	Peer       string `json:"peer"`
	Mode       string `json:"mode"`
	Unattended bool   `json:"unattended"`
	Code       string `json:"code"`
	Recording  bool   `json:"recording"`
	Clipboard  bool   `json:"clipboard"`
	Blank      bool   `json:"blank"`
	InputLock  bool   `json:"inputLock"`
	Reason     string `json:"reason"`
}

// RDeskHelperPower is a restart request a control session made.
type RDeskHelperPower struct {
	Peer     string `json:"peer"`
	SafeMode bool   `json:"safeMode"`
}

// RemoteDesktopHelperAPI serves the desktop helper the service starts in
// the user's session. Every call is made only after HelperAllowed accepted
// the request's token and calling process.
type RemoteDesktopHelperAPI interface {
	RDeskHelperAllowed(token, remote, local string) bool
	RDeskHelperAuthorize(remote netip.Addr, mode string) RDeskHelperDecision
	RDeskHelperState() RDeskHelperState
	RDeskHelperEvent(ev RDeskHelperEvent)
	RDeskHelperPower(req RDeskHelperPower) error
}
