package panel

import (
	"context"
	"net/http"
	"time"
)

// Exit node resolver and threat detection (ADR-0102, ADR-0110).

// Health codes of the resolver and threat detection.
const (
	HealthDNSSECBogus    = "dnssec_bogus"
	HealthThreatDetected = "threat_detected"
	HealthDoHBypass      = "doh_bypass"
)

// GuardSettings are the saved resolver and detection options.
type GuardSettings struct {
	ExitDNSUpstream    string `json:"exitDnsUpstream"`
	ExitDNSBlocklist   string `json:"exitDnsBlocklist"`
	DNSSECTrustAnchors string `json:"dnssecTrustAnchors"`
	ThreatScan         bool   `json:"threatScan"`
	ThreatBlock        bool   `json:"threatBlock"`
	BlockForSec        int64  `json:"blockForSec"`
	CanaryPorts        []int  `json:"canaryPorts"`
}

// GuardChange changes some options; nil keeps a value.
type GuardChange struct {
	ExitDNSUpstream    *string `json:"exitDnsUpstream"`
	ExitDNSBlocklist   *string `json:"exitDnsBlocklist"`
	DNSSECTrustAnchors *string `json:"dnssecTrustAnchors"`
	ThreatScan         *bool   `json:"threatScan"`
	ThreatBlock        *bool   `json:"threatBlock"`
	BlockForSec        *int64  `json:"blockForSec"`
	CanaryPorts        *[]int  `json:"canaryPorts"`
}

// ThreatView is one detection.
type ThreatView struct {
	Kind         string     `json:"kind"`
	Peer         string     `json:"peer,omitempty"`
	Count        int        `json:"count,omitempty"`
	Port         int        `json:"port,omitempty"`
	Canary       string     `json:"canary,omitempty"`
	At           time.Time  `json:"at"`
	BlockedUntil *time.Time `json:"blockedUntil,omitempty"`
}

// BlockedPeer is a peer whose new connections are refused.
type BlockedPeer struct {
	Peer  string    `json:"peer"`
	Until time.Time `json:"until"`
}

// DNSSECView are the validation counters of the recursive-dnssec resolver.
type DNSSECView struct {
	Secure   uint64 `json:"secure"`
	Insecure uint64 `json:"insecure"`
	Bogus    uint64 `json:"bogus"`
}

// DoHFinding is a browser profile that sends DNS past the system resolver.
type DoHFinding struct {
	Browser  string `json:"browser"`
	Profile  string `json:"profile"`
	Mode     string `json:"mode"`
	Resolver string `json:"resolver,omitempty"`
	Bypass   bool   `json:"bypass"`
}

// GuardStatus is the health screen's resolver and threat part.
type GuardStatus struct {
	Settings GuardSettings `json:"settings"`
	Running  bool          `json:"running"`
	DNSSEC   DNSSECView    `json:"dnssec"`
	Threats  []ThreatView  `json:"threats"`
	Blocked  []BlockedPeer `json:"blocked"`
}

// GuardControl is implemented by the desktop service.
type GuardControl interface {
	GuardStatus() GuardStatus
	SetGuards(c GuardChange) error
	UnblockPeer(name string) error
	DoHScan(ctx context.Context) ([]DoHFinding, error)
}

func (s *Server) guardRoutes(mux *http.ServeMux, read, write func(http.HandlerFunc) http.HandlerFunc) {
	mux.HandleFunc("GET /api/app/guards", read(s.handleGuards))
	mux.HandleFunc("POST /api/app/guards", write(s.handleSetGuards))
	mux.HandleFunc("POST /api/app/guards/unblock", write(s.handleUnblockPeer))
	mux.HandleFunc("GET /api/app/guards/doh", read(s.handleDoHScan))
}

func (s *Server) guardControl(w http.ResponseWriter) (GuardControl, bool) {
	c, ok := s.app.(GuardControl)
	if !ok {
		writeError(w, http.StatusNotFound, "Bu işlem yalnızca masaüstü uygulamasında var.")
	}
	return c, ok
}

func (s *Server) handleGuards(w http.ResponseWriter, _ *http.Request) {
	if c, ok := s.guardControl(w); ok {
		writeJSON(w, http.StatusOK, c.GuardStatus())
	}
}

func (s *Server) handleSetGuards(w http.ResponseWriter, r *http.Request) {
	c, ok := s.guardControl(w)
	if !ok {
		return
	}
	var req GuardChange
	if !decodeBody(w, r, &req) {
		return
	}
	if err := c.SetGuards(req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, c.GuardStatus())
}

func (s *Server) handleUnblockPeer(w http.ResponseWriter, r *http.Request) {
	c, ok := s.guardControl(w)
	if !ok {
		return
	}
	var req deviceRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if !validDeviceParam(req.Device) {
		writeError(w, http.StatusBadRequest, "Geçersiz cihaz adı.")
		return
	}
	if err := c.UnblockPeer(req.Device); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, c.GuardStatus())
}

func (s *Server) handleDoHScan(w http.ResponseWriter, r *http.Request) {
	c, ok := s.guardControl(w)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	f, err := c.DoHScan(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if f == nil {
		f = []DoHFinding{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"findings": f})
}

// DiagTraffic is the traffic part of "openscale status".
type DiagTraffic struct {
	PortMap   PortMapView `json:"port_map"`
	Shaping   ShapingView `json:"shaping"`
	TorActive bool        `json:"tor_active"`
}

// ThreatsReply is "openscale threats".
type ThreatsReply struct {
	Schema  int           `json:"schema"`
	DNSSEC  DNSSECView    `json:"dnssec"`
	Threats []ThreatView  `json:"threats"`
	Blocked []BlockedPeer `json:"blocked"`
}

// ThreatDiagnostics is implemented by the service and "openscale up".
type ThreatDiagnostics interface {
	DiagThreats() (ThreatsReply, error)
	DiagUnblock(peer string) error
}

func (a *diagAPI) threatRoutes(mux *http.ServeMux, prefix string, read, write func(http.HandlerFunc) http.HandlerFunc) {
	mux.HandleFunc("GET "+prefix+"/threats", read(a.with(a.threats)))
	mux.HandleFunc("POST "+prefix+"/threats/unblock", write(a.with(a.unblock)))
}

func (a *diagAPI) threats(w http.ResponseWriter, _ *http.Request, d Diagnostics) {
	t, ok := d.(ThreatDiagnostics)
	if !ok {
		diagFailed(w, ErrNeedsService)
		return
	}
	rep, err := t.DiagThreats()
	if err != nil {
		diagFailed(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

func (a *diagAPI) unblock(w http.ResponseWriter, r *http.Request, d Diagnostics) {
	t, ok := d.(ThreatDiagnostics)
	if !ok {
		diagFailed(w, ErrNeedsService)
		return
	}
	var req peerRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if !validDeviceParam(req.Peer) {
		writeError(w, http.StatusBadRequest, "Geçersiz cihaz adı.")
		return
	}
	if err := t.DiagUnblock(req.Peer); err != nil {
		diagFailed(w, err)
		return
	}
	writeJSON(w, http.StatusOK, okReply{Schema: DiagSchema, OK: true})
}

// DenyThreatBlocked is the refusal reason of a peer blocked after a scan.
const DenyThreatBlocked = "threat_blocked"
