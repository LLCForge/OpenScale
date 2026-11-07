package client

import "time"

// The JSON documents of the local API, schema 1 (docs/api/yerel-api.md).
// A field is never renamed or given another meaning without raising the
// schema; new fields may appear and are ignored by older programs.

// Schema is the local API document version this package understands.
const Schema = 1

// Alert is one coded, graded problem.
type Alert struct {
	Code    string `json:"code"`
	Level   string `json:"level"`
	Message string `json:"message"`
}

// Self is this device as the signed document lists it.
type Self struct {
	Name      string     `json:"name"`
	FQDN      string     `json:"fqdn"`
	IPv4      string     `json:"ipv4"`
	IPv6      string     `json:"ipv6"`
	Tags      []string   `json:"tags,omitempty"`
	Roles     []string   `json:"roles,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// Peer is one device this computer has a tunnel to.
type Peer struct {
	Name          string     `json:"name"`
	FQDN          string     `json:"fqdn"`
	IPv4          string     `json:"ipv4"`
	IPv6          string     `json:"ipv6"`
	Online        bool       `json:"online"`
	Path          string     `json:"path"`
	Endpoint      string     `json:"endpoint,omitempty"`
	LastHandshake *time.Time `json:"last_handshake,omitempty"`
	RxBytes       uint64     `json:"rx_bytes"`
	TxBytes       uint64     `json:"tx_bytes"`
	LatencyMS     *float64   `json:"latency_ms,omitempty"`
	ExitNode      bool       `json:"exit_node"`
	ActiveExit    bool       `json:"active_exit"`
	PostQuantum   string     `json:"post_quantum,omitempty"`
}

// Status is GET /api/local/status ("openscale status").
type Status struct {
	Schema          int        `json:"schema"`
	Mode            string     `json:"mode"`
	Running         bool       `json:"running"`
	Connected       bool       `json:"connected"`
	Interface       string     `json:"interface,omitempty"`
	Self            *Self      `json:"self,omitempty"`
	Peers           []Peer     `json:"peers"`
	ExitNode        string     `json:"exit_node,omitempty"`
	DocumentVersion uint64     `json:"document_version"`
	LastSync        *time.Time `json:"last_sync,omitempty"`
	LastSyncError   string     `json:"last_sync_error,omitempty"`
	Health          []Alert    `json:"health"`
}

// Health is GET /api/local/health.
type Health struct {
	Schema  int      `json:"schema"`
	Live    bool     `json:"live"`
	Ready   bool     `json:"ready"`
	Reasons []string `json:"reasons"`
	Alerts  []Alert  `json:"alerts"`
}

// Device is a device found by WhoIs. It is a device of the network, not
// a person: whoever uses that computer shares this identity.
type Device struct {
	Name        string     `json:"name"`
	FQDN        string     `json:"fqdn"`
	IPv4        string     `json:"ipv4"`
	IPv6        string     `json:"ipv6"`
	Tags        []string   `json:"tags"`
	Groups      []string   `json:"groups"`
	Roles       []string   `json:"roles"`
	AddedAt     time.Time  `json:"added_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	Self        bool       `json:"self"`
	Online      bool       `json:"online"`
	Path        string     `json:"path,omitempty"`
	Fingerprint string     `json:"fingerprint"`
}

// WhoIsResult is GET /api/local/whois.
type WhoIsResult struct {
	Schema      int     `json:"schema"`
	Query       string  `json:"query"`
	Device      *Device `json:"device,omitempty"`
	Coordinator bool    `json:"coordinator,omitempty"`
}

// PeerPath is one tunnel peer's path (GET /api/local/paths).
type PeerPath struct {
	Name          string    `json:"name"`
	ID            string    `json:"id"`
	Endpoint      string    `json:"endpoint"`
	Relayed       bool      `json:"relayed"`
	Class         string    `json:"class"`
	LastHandshake time.Time `json:"last_handshake"`
	PostQuantum   string    `json:"post_quantum"`
}

// Paths is GET /api/local/paths.
type Paths struct {
	Schema int        `json:"schema"`
	Peers  []PeerPath `json:"peers"`
}

// Event is one entry of the recent event list. It never holds addresses.
type Event struct {
	At      time.Time `json:"at"`
	Kind    string    `json:"kind"`
	Peer    string    `json:"peer,omitempty"`
	Message string    `json:"message"`
}

// Events is GET /api/local/events.
type Events struct {
	Schema int     `json:"schema"`
	Events []Event `json:"events"`
}

// StreamEvent is one event of the event stream (ADR-0105).
type StreamEvent struct {
	Seq      uint64    `json:"seq"`
	At       time.Time `json:"at"`
	Kind     string    `json:"kind"`
	Category string    `json:"category"`
	Severity string    `json:"severity"`
	Peer     string    `json:"peer,omitempty"`
	Message  string    `json:"message"`
}

// EventBatch is GET /api/local/events/poll.
type EventBatch struct {
	Schema int           `json:"schema"`
	Events []StreamEvent `json:"events"`
	// Next is the sequence number to ask from next time.
	Next uint64 `json:"next"`
}

// SplitDNS is one split DNS domain.
type SplitDNS struct {
	Domain      string   `json:"domain"`
	Nameservers []string `json:"nameservers"`
}

// DNS is GET /api/local/dns.
type DNS struct {
	Schema             int        `json:"schema"`
	Domain             string     `json:"domain"`
	Resolver           string     `json:"resolver"`
	MagicDNSError      string     `json:"magic_dns_error,omitempty"`
	MagicDNSAllDevices bool       `json:"magicdns_all_devices"`
	NetworkDNSAccepted bool       `json:"network_dns_accepted"`
	NetworkDNSActive   bool       `json:"network_dns_active"`
	NetworkDNSError    string     `json:"network_dns_error,omitempty"`
	Nameservers        []string   `json:"nameservers"`
	Split              []SplitDNS `json:"split"`
}

// Pref is one persistent preference.
type Pref struct {
	Key         string `json:"key"`
	Value       string `json:"value"`
	Default     string `json:"default"`
	Description string `json:"description"`
}

// Prefs is GET /api/local/prefs.
type Prefs struct {
	Schema int    `json:"schema"`
	Prefs  []Pref `json:"prefs"`
}
