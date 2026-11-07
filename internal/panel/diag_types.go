package panel

import (
	"context"
	"time"

	"github.com/openscale/openscale/internal/node"
)

// Diagnostics API (F-014, F-015, F-016, F-017, F-057, F-110, F-171, F-187,
// F-188, F-190, F-191, F-192, F-208). The command line reads it with the
// app token, the panel's "Tanı" page with a session. Every answer carries
// DiagSchema so scripts can tell a changed format from a broken one.

// DiagSchema is the version of the JSON documents below. A field is never
// renamed or given another meaning without raising it.
const DiagSchema = 1

// HealthCaptivePortal is the health alert of a detected captive portal
// (F-018): the network waits for its login page, which the tunnel hides.
const HealthCaptivePortal = "captive_portal"

// Path kinds of a peer.
const (
	PathDirect = "direct"
	PathRelay  = "relay"
	PathNone   = "none"
)

// Diagnostics is implemented by the desktop service and by a foreground
// "openscale up". Methods that need the service's settings return
// ErrNeedsService elsewhere.
type Diagnostics interface {
	DiagStatus() (DiagStatus, error)
	DiagNetCheck(ctx context.Context) (node.NetReport, error)
	DiagPaths() ([]node.PeerPath, error)
	DiagReconnect() error
	DiagRelayTest(ctx context.Context, peer string) (time.Duration, error)
	DiagPing(ctx context.Context, peer string) (PingResult, error)
	DiagDNS() (DNSStatus, error)
	DiagDNSQuery(ctx context.Context, name string) (DNSQueryResult, error)
	DiagWhois(query string) (WhoisResult, error)
	DiagEvents() []DiagEvent
	DiagWireGuard() (WGShow, error)
	DiagPacketTrace(req TraceRequest) (TraceResult, error)
	DiagHealth() HealthReport
	DiagLogLevel() string
	DiagSetLogLevel(level string) error
	DiagPrefs() ([]Pref, error)
	DiagSetPrefs(change map[string]string) ([]Pref, error)
}

// DiagSelf is this device as the signed document lists it.
type DiagSelf struct {
	Name      string     `json:"name"`
	FQDN      string     `json:"fqdn"`
	IPv4      string     `json:"ipv4"`
	IPv6      string     `json:"ipv6"`
	Tags      []string   `json:"tags,omitempty"`
	Roles     []string   `json:"roles,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// DiagPeer is one device this computer has a tunnel to (F-191).
type DiagPeer struct {
	Name string `json:"name"`
	FQDN string `json:"fqdn"`
	IPv4 string `json:"ipv4"`
	IPv6 string `json:"ipv6"`
	// Online: a handshake within the last few minutes.
	Online bool `json:"online"`
	// Path is PathDirect, PathRelay or PathNone.
	Path          string     `json:"path"`
	Endpoint      string     `json:"endpoint,omitempty"`
	LastHandshake *time.Time `json:"last_handshake,omitempty"`
	RxBytes       uint64     `json:"rx_bytes"`
	TxBytes       uint64     `json:"tx_bytes"`
	// LatencyMS is the last direct path probe's round trip, if any.
	LatencyMS   *float64 `json:"latency_ms,omitempty"`
	ExitNode    bool     `json:"exit_node"`
	ActiveExit  bool     `json:"active_exit"`
	PostQuantum string   `json:"post_quantum,omitempty"`
}

// DiagStatus is "openscale status".
type DiagStatus struct {
	Schema          int           `json:"schema"`
	Mode            string        `json:"mode"`
	Running         bool          `json:"running"`
	Connected       bool          `json:"connected"`
	Interface       string        `json:"interface,omitempty"`
	Self            *DiagSelf     `json:"self,omitempty"`
	Peers           []DiagPeer    `json:"peers"`
	ExitNode        string        `json:"exit_node,omitempty"`
	DocumentVersion uint64        `json:"document_version"`
	LastSync        *time.Time    `json:"last_sync,omitempty"`
	LastSyncError   string        `json:"last_sync_error,omitempty"`
	Health          []HealthAlert `json:"health"`
	// Traffic is router port mapping and traffic shaping while the tunnel
	// runs (ADR-0042, ADR-0043, ADR-0110).
	Traffic *DiagTraffic `json:"traffic,omitempty"`
}

// Ping methods: how a PingResult was measured.
const (
	PingICMP  = "icmp"
	PingRelay = "relay"
	PingProbe = "probe"
)

// PingResult is one "openscale ping" round (F-014).
type PingResult struct {
	Schema   int      `json:"schema"`
	Peer     string   `json:"peer"`
	IPv4     string   `json:"ipv4"`
	Path     string   `json:"path"`
	Endpoint string   `json:"endpoint,omitempty"`
	RTTMS    *float64 `json:"rtt_ms,omitempty"`
	Method   string   `json:"method,omitempty"`
	Error    string   `json:"error,omitempty"`
}

// SplitDNSInfo is one split DNS domain of the network.
type SplitDNSInfo struct {
	Domain      string   `json:"domain"`
	Nameservers []string `json:"nameservers"`
}

// DNSStatus is "openscale dns status" (F-057).
type DNSStatus struct {
	Schema             int            `json:"schema"`
	Domain             string         `json:"domain"`
	Resolver           string         `json:"resolver"`
	MagicDNSError      string         `json:"magic_dns_error,omitempty"`
	MagicDNSAllDevices bool           `json:"magicdns_all_devices"`
	NetworkDNSAccepted bool           `json:"network_dns_accepted"`
	NetworkDNSActive   bool           `json:"network_dns_active"`
	NetworkDNSError    string         `json:"network_dns_error,omitempty"`
	Nameservers        []string       `json:"nameservers"`
	Split              []SplitDNSInfo `json:"split"`
}

// DNSQueryResult is "openscale dns query" (F-057).
type DNSQueryResult struct {
	Schema   int      `json:"schema"`
	Name     string   `json:"name"`
	Resolver string   `json:"resolver"`
	Addrs    []string `json:"addrs"`
	RTTMS    float64  `json:"rtt_ms"`
	Error    string   `json:"error,omitempty"`
}

// WhoisDevice is a device found by "openscale whois" (F-110).
type WhoisDevice struct {
	Name      string     `json:"name"`
	FQDN      string     `json:"fqdn"`
	IPv4      string     `json:"ipv4"`
	IPv6      string     `json:"ipv6"`
	Tags      []string   `json:"tags"`
	Groups    []string   `json:"groups"`
	Roles     []string   `json:"roles"`
	AddedAt   time.Time  `json:"added_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Self      bool       `json:"self"`
	Online    bool       `json:"online"`
	Path      string     `json:"path,omitempty"`
	// Fingerprint identifies the device's WireGuard key without showing it.
	Fingerprint string `json:"fingerprint"`
}

// WhoisResult answers "openscale whois" and "openscale whoami".
type WhoisResult struct {
	Schema      int          `json:"schema"`
	Query       string       `json:"query"`
	Device      *WhoisDevice `json:"device,omitempty"`
	Coordinator bool         `json:"coordinator,omitempty"`
}

// Event kinds of the service's event list (F-017).
const (
	EventPeerOnline   = "peer_online"
	EventPeerOffline  = "peer_offline"
	EventPeerRelayed  = "peer_relayed"
	EventPeerDirect   = "peer_direct"
	EventTunnelUp     = "tunnel_up"
	EventTunnelDown   = "tunnel_down"
	EventCaptive      = "captive_portal"
	EventCaptiveClear = "captive_portal_cleared"
	EventSyncLost     = "coordinator_lost"
	EventSyncBack     = "coordinator_back"
)

// DiagEvent is one entry of the event list. It never holds addresses or
// endpoints; Peer is the device name from the signed document.
type DiagEvent struct {
	At      time.Time `json:"at"`
	Kind    string    `json:"kind"`
	Peer    string    `json:"peer,omitempty"`
	Message string    `json:"message"`
}

// WGPeer is one WireGuard peer of "openscale wg show" (F-208). Keys are
// public keys; private keys and pre-shared keys are never shown.
type WGPeer struct {
	Name          string     `json:"name"`
	PublicKey     string     `json:"public_key"`
	Endpoint      string     `json:"endpoint,omitempty"`
	Relayed       bool       `json:"relayed"`
	AllowedIPs    []string   `json:"allowed_ips"`
	LastHandshake *time.Time `json:"latest_handshake,omitempty"`
	RxBytes       uint64     `json:"rx_bytes"`
	TxBytes       uint64     `json:"tx_bytes"`
	PostQuantum   string     `json:"post_quantum,omitempty"`
}

// WGShow is "openscale wg show".
type WGShow struct {
	Schema    int      `json:"schema"`
	Interface string   `json:"interface"`
	PublicKey string   `json:"public_key"`
	Peers     []WGPeer `json:"peers"`
}

// TraceRequest asks how the rules treat one packet (F-187). Src and Dst
// are device names or overlay addresses; Proto is tcp, udp, icmp or an IP
// protocol number.
type TraceRequest struct {
	Src   string `json:"src"`
	Dst   string `json:"dst"`
	Proto string `json:"proto"`
	Port  int    `json:"port"`
}

// TraceStep is one stage of a packet trace.
type TraceStep struct {
	Stage   string `json:"stage"`
	Outcome string `json:"outcome"`
	Detail  string `json:"detail"`
}

// TraceResult is the packet trace verdict.
type TraceResult struct {
	Schema  int         `json:"schema"`
	Src     string      `json:"src"`
	Dst     string      `json:"dst"`
	Proto   string      `json:"proto"`
	Port    int         `json:"port,omitempty"`
	Allowed bool        `json:"allowed"`
	Verdict string      `json:"verdict"`
	Steps   []TraceStep `json:"steps"`
}

// HealthReport is "openscale health" (F-192): live means the service
// answers, ready that the tunnel runs and is synchronized.
type HealthReport struct {
	Schema  int           `json:"schema"`
	Live    bool          `json:"live"`
	Ready   bool          `json:"ready"`
	Reasons []string      `json:"reasons"`
	Alerts  []HealthAlert `json:"alerts"`
}

// Pref is one persistent preference of "openscale get" (F-171).
type Pref struct {
	Key         string `json:"key"`
	Value       string `json:"value"`
	Default     string `json:"default"`
	Description string `json:"description"`
	// RestartsConnection: changing it restarts the tunnel or the local
	// coordinator (#799, service/pref_meta.go).
	RestartsConnection bool `json:"restarts_connection,omitempty"`
}
