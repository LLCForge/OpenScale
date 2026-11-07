package panel

import (
	"context"
	"io"
	"time"
)

// RemoteApps is the optional part of App that runs the remote access and
// diagnostics services of ADR-0030 and ADR-0031: the embedded SSH server,
// file inbox, Wake-on-LAN relay and speed test. The panel uses it when the
// desktop service implements it; the CLI panel and test apps do not.
type RemoteApps interface {
	// AppsStatus reports the services running on this computer.
	AppsStatus() AppsStatus
	// RemoteDevice says what this computer may do with another device,
	// from the signed rules, and what is known about it.
	RemoteDevice(name string) (RemoteDeviceView, error)
	// Inbox lists received files and offers waiting for a decision.
	Inbox() InboxView
	DecideOffer(id string, accept bool) error
	SetAutoAccept(device string, on bool) error
	DeleteInboxFile(name string) error
	// OpenInboxFile opens a received file for download.
	OpenInboxFile(name string) (io.ReadSeekCloser, InboxFile, error)
	// SendFile stores body (size bytes) and sends it to device in the
	// background; it returns the transfer id.
	SendFile(device, name string, body io.Reader, size int64) (string, error)
	Transfers() []TransferStatus
	// Wake asks a relay device on the target's LAN to send a magic packet.
	Wake(ctx context.Context, device string) (WakeResult, error)
	// SetWakeMAC sets (or with "" clears) the MAC address used to wake
	// device.
	SetWakeMAC(device, mac string) error
	SpeedTest(ctx context.Context, device string, upload bool, seconds int) (SpeedResult, error)
}

// ServiceState is one service running on this computer.
type ServiceState struct {
	// Hosted: a rule in the signed document makes this computer serve it.
	Hosted bool `json:"hosted"`
	// Running: the server listens on the tunnel address.
	Running bool   `json:"running"`
	Address string `json:"address"`
	Error   string `json:"error"`
}

// AppsStatus is the state of this computer's services.
type AppsStatus struct {
	SSH       ServiceState `json:"ssh"`
	Files     ServiceState `json:"files"`
	Wake      ServiceState `json:"wake"`
	Speedtest ServiceState `json:"speedtest"`
	// SSHFingerprint is this computer's SSH host key fingerprint.
	SSHFingerprint string `json:"sshFingerprint"`
	// PendingOffers counts file offers waiting for the owner.
	PendingOffers int `json:"pendingOffers"`
	// SSHSessions counts open SSH connections.
	SSHSessions int `json:"sshSessions"`
}

// RemoteDeviceView is what this computer may do with another device.
type RemoteDeviceView struct {
	Name string `json:"name"`
	IPv4 string `json:"ipv4"`
	FQDN string `json:"fqdn"`
	// SSHUsers lists the accounts this computer may log in as; SSHRoot
	// and SSHForward follow allow_root and allow_forward.
	SSHUsers   []string `json:"sshUsers"`
	SSHRoot    bool     `json:"sshRoot"`
	SSHForward bool     `json:"sshForward"`
	CanSend    bool     `json:"canSend"`
	CanSpeed   bool     `json:"canSpeedtest"`
	// WakeRelays are the devices that may relay a wake request.
	WakeRelays []string `json:"wakeRelays"`
	// WakeMAC is the address a wake request uses ("" when unknown).
	WakeMAC string `json:"wakeMac"`
	// SSHFingerprint is the device's host key fingerprint from its last
	// system report ("" when unknown).
	SSHFingerprint string `json:"sshFingerprint"`
	// SSHPort is the embedded server's port.
	SSHPort int `json:"sshPort"`
}

// InboxFile is a received file.
type InboxFile struct {
	Name       string    `json:"name"`
	Size       int64     `json:"size"`
	From       string    `json:"from"`
	ReceivedAt time.Time `json:"receivedAt"`
	// Executable: opening it may run code (#133); the panel warns.
	Executable bool `json:"executable"`
}

// PendingOffer is a file offer waiting for the owner's decision.
type PendingOffer struct {
	ID        string    `json:"id"`
	From      string    `json:"from"`
	Name      string    `json:"name"`
	Size      int64     `json:"size"`
	At        time.Time `json:"at"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// InboxView lists the inbox.
type InboxView struct {
	Files      []InboxFile    `json:"files"`
	Pending    []PendingOffer `json:"pending"`
	AutoAccept []string       `json:"autoAccept"`
}

// TransferStatus is an outgoing file transfer started from the panel.
type TransferStatus struct {
	ID        string    `json:"id"`
	Device    string    `json:"device"`
	Name      string    `json:"name"`
	Size      int64     `json:"size"`
	Sent      int64     `json:"sent"`
	State     string    `json:"state"` // sending, done, failed
	Error     string    `json:"error"`
	StartedAt time.Time `json:"startedAt"`
}

// Transfer states.
const (
	TransferSending = "sending"
	TransferDone    = "done"
	TransferFailed  = "failed"
)

// WakeResult reports which relay sent the magic packet.
type WakeResult struct {
	Relay string `json:"relay"`
	MAC   string `json:"mac"`
}

// SpeedResult is one speed test.
type SpeedResult struct {
	Device    string  `json:"device"`
	Direction string  `json:"direction"`
	Bytes     int64   `json:"bytes"`
	Seconds   float64 `json:"seconds"`
	Mbps      float64 `json:"mbps"`
}
