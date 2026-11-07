package panel

import (
	"context"
	"time"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/sysinfo"
	"github.com/openscale/openscale/internal/trust"
)

// App is the desktop service behind the panel (ADR-0014): it sets up or
// joins a network and runs the tunnel and coordinator. The CLI panel runs
// without one.
type App interface {
	Status() AppStatus
	// CreateNetwork creates a network with this computer as coordinator and
	// admin device, and returns the loaded network directory.
	CreateNetwork(ctx context.Context, in CreateNetworkInput) (*admin.Network, error)
	// JoinNetwork starts joining with an invite code in the background.
	JoinNetwork(code, name string) error
	CancelJoin()
	// Pending asks the coordinator for invite enrollments (admin devices).
	Pending(ctx context.Context) ([]trust.SignedInviteEnrollment, error)
	// LiveStats reports what WireGuard on this computer sees of other
	// devices, keyed by their WireGuard key.
	LiveStats() LiveStats
	// SetConnected turns this computer's tunnel on or off. The choice is
	// remembered across restarts; the coordinator role is not affected.
	SetConnected(on bool) error
	// Inventory returns the latest system reports collected through the
	// tunnel (ADR-0015).
	Inventory() Inventory
	// LocalSecurity reports remote desktop, SSH and listening ports on this
	// computer; SetRemoteAccess limits "rdp" or "ssh" to OpenScale.
	LocalSecurity(ctx context.Context, refresh bool) (LocalSecurity, error)
	SetRemoteAccess(service string, overlayOnly bool) error
	// SetExitNode chooses the exit node for this computer ("" for none).
	SetExitNode(name string) error
	// SetExitOptions sets the persistent kill switch and local network
	// access while an exit node is used (ADR-0023).
	SetExitOptions(killSwitch, allowLAN bool) error
	// SetShields refuses every connection other devices open to this
	// computer, whatever the rules allow (F-077).
	SetShields(on bool) error
	// ResetDevice forgets this computer's membership and key so it can
	// join again; refused on the computer holding the root key.
	ResetDevice() error
	// DisconnectFor turns the tunnel off until the chosen time passes
	// (Disconnect5Min, Disconnect1Hour or DisconnectMorning, F-121).
	DisconnectFor(choice string) error
	// SetPinned pins a device to the top of the lists (F-159).
	SetPinned(name string, pinned bool) error
	// ReleaseKillSwitchOnStop makes the next service stop remove the kill
	// switch: the owner closes OpenScale completely from the tray.
	ReleaseKillSwitchOnStop()
	// SetAcceptNetworkDNS chooses whether this computer applies the
	// network-wide DNS settings of the signed document (F-065).
	SetAcceptNetworkDNS(accept bool) error
	// SetAdvanced changes the tunnel MTU, forced relay and the local
	// coordinator's relay limits; nil fields keep their value. The tunnel
	// or coordinator restarts to apply them.
	SetAdvanced(a AdvancedSettings) error
}

// AdvancedSettings are device and coordinator tuning knobs (F-019, F-022,
// F-026). Zero means the built-in default.
type AdvancedSettings struct {
	// MTU of the tunnel interface: 0 (default 1280) or 1280-1420.
	MTU *int `json:"mtu"`
	// ForceRelay reaches every peer through the coordinator.
	ForceRelay *bool `json:"forceRelay"`
	// RelayRate (bytes per second per device) and RelayBurst (bytes) limit
	// the relay of the coordinator running on this computer.
	RelayRate  *int64 `json:"relayRate"`
	RelayBurst *int64 `json:"relayBurst"`
	// Faz 4 tunnel options (transport_types.go); durations in seconds.
	PostQuantum        *bool   `json:"postQuantum"`
	PSKRotationSec     *int64  `json:"pskRotationSec"`
	TCPFallback        *string `json:"tcpFallback"`
	DisableTCPFallback *bool   `json:"disableTcpFallback"`
	KeepaliveSec       *int64  `json:"keepaliveSec"`
	AdaptiveKeepalive  *bool   `json:"adaptiveKeepalive"`
	LazyPeers          *bool   `json:"lazyPeers"`
	LazyIdleSec        *int64  `json:"lazyIdleSec"`
	// TCP transport of the coordinator running on this computer.
	CoordinatorTCPListen        *string `json:"coordinatorTcpListen"`
	CoordinatorTCPMaxConns      *int    `json:"coordinatorTcpMaxConns"`
	CoordinatorTCPMaxConnsPerIP *int    `json:"coordinatorTcpMaxConnsPerIp"`
}

// Timed disconnect choices (F-121).
const (
	Disconnect5Min    = "5m"
	Disconnect1Hour   = "1h"
	DisconnectMorning = "morning"
)

// Health alert levels, shared with the overview warnings.
const (
	LevelDanger  = "danger"
	LevelWarning = "warning"
	LevelInfo    = "info"
)

// Health alert codes (F-193). They are stable: the panel and the tray may
// act on them, so a code is never reused for another meaning.
const (
	HealthTunnelDown             = "tunnel_down"
	HealthTunnelPaused           = "tunnel_paused"
	HealthDeviceRemoved          = "device_removed"
	HealthCoordinatorUnreachable = "coordinator_unreachable"
	HealthCoordinatorFailed      = "coordinator_failed"
	HealthDNSNotApplied          = "dns_not_applied"
	HealthExitUnreachable        = "exit_unreachable"
	HealthKillSwitchFailed       = "killswitch_failed"
	HealthMembershipExpiring     = "membership_expiring"
	HealthDocumentExpiring       = "document_expiring"
	HealthClockSkew              = "clock_skew"
	HealthJoinFailed             = "join_failed"
	// DNS codes (F-062, ADR-0034).
	HealthDNSNetworkFailed       = "dns_network_failed"
	HealthDNSOverwritten         = "dns_overwritten"
	HealthDNSGroupPolicy         = "dns_group_policy"
	HealthDNSResolverUnreachable = "dns_resolver_unreachable"
	// Codes only the owner's overview uses.
	HealthNoBackup           = "no_backup"
	HealthNoRules            = "no_rules"
	HealthUnusedTag          = "unused_tag"
	HealthDNSResolverBlocked = "dns_resolver_blocked"
)

// HealthAlert is one coded, graded problem the owner should know about.
type HealthAlert struct {
	Code    string `json:"code"`
	Level   string `json:"level"`
	Message string `json:"message"`
}

// Report is one computer's system report and when it was received.
type Report struct {
	Info sysinfo.Info
	At   time.Time
	Err  string
}

// Inventory holds the reports this computer collected. Other devices and
// the coordinator answer only admin devices.
type Inventory struct {
	Self        *Report
	Devices     map[string]Report
	Coordinator *Report
	// CoordinatorAddr is the coordinator's public address as WireGuard on
	// this computer reaches it.
	CoordinatorAddr string
}

// PeerTraffic is WireGuard's view of one peer.
type PeerTraffic struct {
	// Relayed is true when the peer is reached through the coordinator.
	Relayed       bool
	Endpoint      string
	LastHandshake time.Time
	RxBytes       uint64
	TxBytes       uint64
}

// LiveStats combines the tunnel's direct view of the peers it may reach and,
// when the coordinator runs on this computer, the coordinator's view of
// every device.
type LiveStats struct {
	Direct         map[trust.Key]PeerTraffic
	ViaCoordinator map[trust.Key]PeerTraffic
}

// CreateNetworkInput is what the welcome screen collects.
type CreateNetworkInput struct {
	Passphrase []byte
	DeviceName string
	// EndpointHost is how other devices reach this computer: a LAN or
	// public IP address, or a (dynamic) DNS name.
	EndpointHost string
	// EmptyPolicy starts the network without the "every device to every
	// device" rule (F-087, #286): default deny from the first moment. The
	// welcome screen asks; its default is on.
	EmptyPolicy bool
}

// App modes.
const (
	ModeSetup   = "setup"
	ModeJoining = "joining"
	ModeMember  = "member"
	ModeAdmin   = "admin"
)

// AppStatus is shown by the panel shell and the welcome screens.
type AppStatus struct {
	Mode              string             `json:"mode"`
	Hostname          string             `json:"hostname"`
	SuggestedEndpoint string             `json:"suggestedEndpoint"`
	Joining           *JoiningStatus     `json:"joining"`
	Device            *DeviceStatus      `json:"device"`
	Coordinator       *CoordinatorStatus `json:"coordinator"`
	Error             string             `json:"error"`
	// Health lists the current problems, most severe first (F-193).
	Health []HealthAlert `json:"health"`
	// PanelReadOnly: the panel refuses every change (F-180).
	PanelReadOnly bool `json:"panelReadOnly"`
	// NetworkName is the network's display name from the signed document
	// (F-160), "" when the owner has not set one.
	NetworkName string `json:"networkName"`
}

// JoiningStatus describes an invite join in progress.
type JoiningStatus struct {
	Name      string `json:"name"`
	ShortCode string `json:"shortCode"`
	Waiting   bool   `json:"waiting"`
	Error     string `json:"error"`
}

// DeviceStatus describes this computer's tunnel.
type DeviceStatus struct {
	Name            string     `json:"name"`
	FQDN            string     `json:"fqdn"`
	IPv4            string     `json:"ipv4"`
	IPv6            string     `json:"ipv6"`
	Running         bool       `json:"running"`
	Connected       bool       `json:"connected"`
	DocumentVersion uint64     `json:"documentVersion"`
	Peers           []PeerInfo `json:"peers"`
	// ExitNodes lists the other devices allowed to act as exit nodes.
	ExitNodes []PeerInfo `json:"exitNodes"`
	// ExitNode is the exit node in use; ExitNodeWanted the saved choice
	// (they differ while the routes are being set up or failed).
	ExitNode       string `json:"exitNode"`
	ExitNodeWanted string `json:"exitNodeWanted"`
	// KillSwitch and ExitAllowLAN are the saved exit options (ADR-0023);
	// KillSwitchSupported says whether this system has a persistent kill
	// switch, KillSwitchActive whether its filters are installed now.
	KillSwitch          bool   `json:"killSwitch"`
	ExitAllowLAN        bool   `json:"exitAllowLan"`
	KillSwitchSupported bool   `json:"killSwitchSupported"`
	KillSwitchActive    bool   `json:"killSwitchActive"`
	KillSwitchError     string `json:"killSwitchError"`
	// Shields: incoming connections from other devices are refused.
	Shields bool `json:"shields"`
	// DisconnectedUntil is when a timed disconnect ends (F-121).
	DisconnectedUntil *time.Time `json:"disconnectedUntil"`
	// LastExitNode is the last exit node chosen, if it still is one.
	LastExitNode string `json:"lastExitNode"`
	// Pinned lists the pinned device names (F-159).
	Pinned []string `json:"pinned"`
	// MembershipExpiresAt is when this computer's membership ends.
	MembershipExpiresAt *time.Time `json:"membershipExpiresAt"`
	// Removed is true when this computer is no longer in the signed
	// document (revoked); it must reset and join again.
	Removed       bool       `json:"removed"`
	LastSync      *time.Time `json:"lastSync"`
	LastSyncError string     `json:"lastSyncError"`
	Error         string     `json:"error"`
	// AcceptNetworkDNS: this computer applies the network's DNS settings
	// (F-065, default on). NetworkDNSActive says whether any are applied
	// now; NetworkDNSError why they could not be.
	AcceptNetworkDNS bool   `json:"acceptNetworkDns"`
	NetworkDNSActive bool   `json:"networkDnsActive"`
	NetworkDNSError  string `json:"networkDnsError"`
	// MTU (0 = default) and ForceRelay are the saved advanced settings.
	MTU        int  `json:"mtu"`
	ForceRelay bool `json:"forceRelay"`
	// Transport holds the saved Faz 4 options.
	Transport TransportSettings `json:"transport"`
	// CoordinatorOverTCP: UDP to the coordinator is blocked and the TCP
	// transport carries the control traffic (ADR-0032).
	CoordinatorOverTCP bool `json:"coordinatorOverTcp"`
	// Wave3 holds the automatic exit node, coordinator and network profile
	// state (connection wave 3, wave3_api.go).
	Wave3 *Wave3Status `json:"wave3,omitempty"`
}

// PeerInfo is another device this computer may reach.
type PeerInfo struct {
	Name    string `json:"name"`
	IPv4    string `json:"ipv4"`
	FQDN    string `json:"fqdn"`
	Online  bool   `json:"online"`
	Relayed bool   `json:"relayed"`
	// Pinned peers are listed first (F-159).
	Pinned bool `json:"pinned"`
	// Country is the ISO code of an exit node's public address ("" when
	// unknown), from the embedded GeoIP table.
	Country string `json:"country"`
	// PostQuantum is the peer's post-quantum PSK state (PostQuantum*), ""
	// while the tunnel does not run (ADR-0033).
	PostQuantum string `json:"postQuantum"`
	// Upstream is an exit node's upstream exit (ADR-0142) from its system
	// report; nil when it uses none or this computer has no report.
	Upstream *UpstreamView `json:"upstream,omitempty"`
}

// CoordinatorStatus describes the coordinator running on this computer.
type CoordinatorStatus struct {
	Endpoint string `json:"endpoint"`
	Running  bool   `json:"running"`
	Error    string `json:"error"`
	// Handoff is true once another coordinator was registered; this one
	// keeps serving devices that have not moved yet.
	Handoff bool `json:"handoff"`
	// RelayRate and RelayBurst are the saved relay limits (0 = default).
	RelayRate  int64 `json:"relayRate"`
	RelayBurst int64 `json:"relayBurst"`
	// TCPListen is the saved TCP transport address ("" = off) and TCPAddr
	// where it listens now; the limits are 0 for the defaults (ADR-0032).
	TCPListen        string `json:"tcpListen"`
	TCPAddr          string `json:"tcpAddr"`
	TCPMaxConns      int    `json:"tcpMaxConns"`
	TCPMaxConnsPerIP int    `json:"tcpMaxConnsPerIp"`
}
