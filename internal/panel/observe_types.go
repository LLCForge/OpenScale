package panel

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/openscale/openscale/internal/audit"
)

// Local observability (ADR-0105): the refused connection log (F-199), the
// Prometheus text metrics (F-198), the event stream (F-182), the security
// audit log (#187, #188), the diagnostics bundle (F-194), the debug packet
// capture (F-197) and profiling (F-201). All of it is served only on the
// loopback API; nothing is sent anywhere.

// Observability is offered by diagnostics sources that run a tunnel.
type Observability interface {
	Denied() (DeniedReply, error)
	ClearDenied() error
	// WriteMetrics writes the Prometheus text format; ErrMetricsOff while
	// the owner has not turned the endpoint on.
	WriteMetrics(w io.Writer) error
	// EventsSince returns the events after since, waiting up to wait for
	// the first one.
	EventsSince(ctx context.Context, since uint64, wait time.Duration) EventStreamReply
	AuditTail(n int) (AuditReply, error)
	AuditVerify() (audit.Report, error)
	Bundle(ctx context.Context) (BundleReply, error)
	// Capture writes a pcap stream to w until the request's limits or ctx
	// end it.
	Capture(ctx context.Context, req CaptureRequest, w io.Writer) (CaptureSummary, error)
	// Profile writes a pprof profile; ErrProfilingOff while profiling is
	// not turned on.
	Profile(ctx context.Context, req ProfileRequest, w io.Writer) error
	ObservePrefs() ObservePrefs
	SetObservePrefs(change ObservePrefsChange) (ObservePrefs, error)
}

// ObservabilitySource is implemented by Diagnostics that offer
// Observability.
type ObservabilitySource interface {
	Observability() Observability
}

var (
	// ErrMetricsOff: the metrics endpoint is off (the default).
	ErrMetricsOff = errors.New("yerel metrik uç noktası kapalı; açmak için: openscale metrics on")
	// ErrProfilingOff: profiling is off (the default).
	ErrProfilingOff = errors.New("profilleme kapalı; açmak için: openscale debug pprof on (bir saat sonra kendiliğinden kapanır)")
)

// Refusal reasons of DeniedEntry.Reason.
const (
	DenyNoRule       = "no_rule"
	DenyDenyRule     = "deny_rule"
	DenyDisabledRule = "disabled_rule"
	DenyShields      = "shields"
	DenyUnknownPeer  = "unknown_peer"
	DenyNotForDevice = "not_for_device"
	DenyExitUsers    = "exit_not_allowed"
	DenyUntracked    = "untracked"
	DenyFlowLimit    = "flow_limit"
	DenyNoDocument   = "no_document"
)

// DeniedEntry is one kind of refused traffic (F-199). Remote is set only
// when the other side is not a device, and then masked.
type DeniedEntry struct {
	// Direction is "in" (another device tried to reach this one) or "out".
	Direction string `json:"direction"`
	Peer      string `json:"peer,omitempty"`
	Remote    string `json:"remote,omitempty"`
	Proto     string `json:"proto"`
	Port      int    `json:"port,omitempty"`
	Reason    string `json:"reason"`
	// Rule is the 1-based rule number for deny_rule and disabled_rule.
	Rule  int       `json:"rule,omitempty"`
	Why   string    `json:"why"`
	Count uint64    `json:"count"`
	First time.Time `json:"first"`
	Last  time.Time `json:"last"`
}

// DeniedReply is "openscale denied".
type DeniedReply struct {
	Schema  int               `json:"schema"`
	Entries []DeniedEntry     `json:"entries"`
	Totals  map[string]uint64 `json:"totals"`
}

// Categories of StreamEvent.
const (
	CategoryConnection = "connection"
	CategorySecurity   = "security"
	CategoryDevice     = "device"
	CategoryKillSwitch = "killswitch"
)

// StreamEvent is one event of the event stream (F-182). Like DiagEvent it
// never holds addresses.
type StreamEvent struct {
	Seq      uint64    `json:"seq"`
	At       time.Time `json:"at"`
	Kind     string    `json:"kind"`
	Category string    `json:"category"`
	Severity string    `json:"severity"`
	Peer     string    `json:"peer,omitempty"`
	Message  string    `json:"message"`
	// Notify marks events the tray announces when notifications are on.
	Notify bool `json:"notify,omitempty"`
}

// EventStreamReply is one long-poll answer.
type EventStreamReply struct {
	Schema int           `json:"schema"`
	Events []StreamEvent `json:"events"`
	// Next is the sequence number to ask from next time.
	Next uint64 `json:"next"`
	// Notifications is whether desktop notifications are on (F-158).
	Notifications bool `json:"notifications"`
}

// AuditReply is "openscale audit list" with the chain check.
type AuditReply struct {
	Schema  int            `json:"schema"`
	Records []audit.Record `json:"records"`
	Verify  audit.Report   `json:"verify"`
}

// BundleFile is one file of the diagnostics bundle.
type BundleFile struct {
	Name    string `json:"name"`
	Content string `json:"content"`
}

// BundleReply is the content of a diagnostics bundle (F-194). The command
// line shows it and writes the zip only after the owner confirms.
type BundleReply struct {
	Schema    int          `json:"schema"`
	CreatedAt time.Time    `json:"created_at"`
	Files     []BundleFile `json:"files"`
}

// CaptureRequest selects a debug packet capture (F-197).
type CaptureRequest struct {
	Peer      string `json:"peer,omitempty"`
	Proto     string `json:"proto,omitempty"`
	Port      int    `json:"port,omitempty"`
	Direction string `json:"direction,omitempty"`
	Denied    bool   `json:"denied,omitempty"`
	Seconds   int    `json:"seconds"`
	MaxBytes  int64  `json:"max_bytes"`
	// Snap is how many bytes of each packet are kept; 0 keeps only the
	// headers (128 bytes).
	Snap int `json:"snap,omitempty"`
}

// Capture limits.
const (
	MaxCaptureSeconds = 600
	MaxCaptureBytes   = 256 << 20
	MinCaptureBytes   = 4 << 10
)

// CaptureSummary is sent as HTTP trailers after the pcap stream.
type CaptureSummary struct {
	Packets uint64
	Dropped uint64
	Bytes   int64
}

// ProfileRequest is one pprof profile (F-201).
type ProfileRequest struct {
	Kind    string `json:"kind"`
	Seconds int    `json:"seconds,omitempty"`
	Debug   int    `json:"debug,omitempty"`
}

// MaxProfileSeconds bounds a CPU profile.
const MaxProfileSeconds = 60

// ObservePrefs are the observability switches.
type ObservePrefs struct {
	Schema int `json:"schema"`
	// Metrics turns the Prometheus endpoint on (off by default).
	Metrics bool `json:"metrics"`
	// Notifications turns the tray notifications on (on by default).
	Notifications bool `json:"notifications"`
	// Profiling is on until ProfilingUntil (never saved).
	Profiling      bool       `json:"profiling"`
	ProfilingUntil *time.Time `json:"profiling_until,omitempty"`
}

// ObservePrefsChange changes the switches given.
type ObservePrefsChange struct {
	Metrics       *bool `json:"metrics,omitempty"`
	Notifications *bool `json:"notifications,omitempty"`
	Profiling     *bool `json:"profiling,omitempty"`
}
