package panel

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/openscale/openscale/internal/node"
)

// Traffic shaping, router port mapping and Tor (ADR-0042, ADR-0043,
// ADR-0044, ADR-0110). Padding and cover traffic cost bandwidth and battery;
// the roadmap allows turning them on only after the cost was shown, so the
// panel must send back the acknowledgement of the cost it displayed.

// TrafficSettings are the saved options.
type TrafficSettings struct {
	PortMap             bool     `json:"portMap"`
	PortMapDisable      []string `json:"portMapDisable"`
	Padding             string   `json:"padding"`
	CoverTraffic        int      `json:"coverTraffic"`
	InteractivePriority bool     `json:"interactivePriority"`
	TorSOCKS            string   `json:"torSocks"`
}

// TrafficChange changes some options; nil keeps a value. CostAck must be
// the Ack of the cost shown for the resulting padding and cover traffic
// whenever either is turned on or changed.
type TrafficChange struct {
	PortMap             *bool     `json:"portMap"`
	PortMapDisable      *[]string `json:"portMapDisable"`
	Padding             *string   `json:"padding"`
	CoverTraffic        *int      `json:"coverTraffic"`
	InteractivePriority *bool     `json:"interactivePriority"`
	TorSOCKS            *string   `json:"torSocks"`
	CostAck             string    `json:"costAck"`
}

// TrafficCost is the estimated cost of padding and cover traffic.
type TrafficCost struct {
	Padding        string  `json:"padding"`
	PaddingPercent float64 `json:"paddingPercent"`
	CoverTraffic   int     `json:"coverTraffic"`
	PacketsPerHour int64   `json:"packetsPerHour"`
	BytesPerDay    int64   `json:"bytesPerDay"`
	BytesPer30Days int64   `json:"bytesPer30Days"`
	MTU            int     `json:"mtu"`
	Ack            string  `json:"ack"`
}

// PortMapView is node.PortMapStatus for the panel and diagnostics.
type PortMapView struct {
	Enabled   bool       `json:"enabled"`
	Active    bool       `json:"active"`
	Protocol  string     `json:"protocol,omitempty"`
	External  string     `json:"external,omitempty"`
	RenewAt   *time.Time `json:"renewAt,omitempty"`
	LastError string     `json:"lastError,omitempty"`
}

// ShapingView is node.TrafficShapingStats.
type ShapingView struct {
	Padding             string `json:"padding"`
	PaddedPackets       uint64 `json:"paddedPackets"`
	PaddingBytes        uint64 `json:"paddingBytes"`
	CoverRate           int    `json:"coverRate"`
	CoverPackets        uint64 `json:"coverPackets"`
	CoverBytes          uint64 `json:"coverBytes"`
	InteractivePriority bool   `json:"interactivePriority"`
}

// TrafficStatus is the traffic card.
type TrafficStatus struct {
	Settings TrafficSettings `json:"settings"`
	Cost     TrafficCost     `json:"cost"`
	// PortMap and Shaping are nil while the tunnel does not run.
	PortMap   *PortMapView `json:"portMap"`
	Shaping   *ShapingView `json:"shaping"`
	TorActive bool         `json:"torActive"`
}

// TrafficControl is implemented by the desktop service.
type TrafficControl interface {
	TrafficStatus() TrafficStatus
	SetTraffic(c TrafficChange) error
}

// PaddingMode maps the setting name ("" or "off", "buckets", "mtu").
func PaddingMode(s string) (node.PaddingMode, bool) {
	switch s {
	case "", "off":
		return node.PaddingOff, true
	case "buckets":
		return node.PaddingBuckets, true
	case "mtu":
		return node.PaddingMTU, true
	}
	return node.PaddingOff, false
}

// CostAck binds an acknowledgement to the exact padding, cover rate and
// MTU whose cost was shown.
func CostAck(padding string, cover, mtu int) string {
	if padding == "off" {
		padding = ""
	}
	if mtu == 0 {
		mtu = node.DefaultMTU
	}
	sum := sha256.Sum256([]byte("openscale-traffic-cost-v1|" + padding + "|" + strconv.Itoa(cover) + "|" + strconv.Itoa(mtu)))
	return hex.EncodeToString(sum[:8])
}

// ComputeTrafficCost estimates the cost of padding and cover traffic.
func ComputeTrafficCost(padding string, cover, mtu int) (TrafficCost, error) {
	if mtu == 0 {
		mtu = node.DefaultMTU
	}
	mode, ok := PaddingMode(padding)
	if !ok {
		return TrafficCost{}, fmt.Errorf("dolgu kipi %q geçersiz", padding)
	}
	c := TrafficCost{Padding: padding, CoverTraffic: cover, MTU: mtu, Ack: CostAck(padding, cover, mtu)}
	if mode != node.PaddingOff {
		pct, err := node.PaddingCost(mode, mtu)
		if err != nil {
			return TrafficCost{}, err
		}
		c.PaddingPercent = pct
	}
	if cover > 0 {
		est, err := node.CoverTrafficCost(cover, mtu)
		if err != nil {
			return TrafficCost{}, err
		}
		c.PacketsPerHour, c.BytesPerDay, c.BytesPer30Days = est.PacketsPerHour, est.WireBytesPerDay, est.WireBytesPer30Days
	}
	return c, nil
}

func (s *Server) trafficRoutes(mux *http.ServeMux, read, write func(http.HandlerFunc) http.HandlerFunc) {
	mux.HandleFunc("GET /api/app/traffic", read(s.handleTraffic))
	mux.HandleFunc("GET /api/app/traffic/cost", read(s.handleTrafficCost))
	mux.HandleFunc("POST /api/app/traffic", write(s.handleSetTraffic))
}

func (s *Server) trafficControl(w http.ResponseWriter) (TrafficControl, bool) {
	c, ok := s.app.(TrafficControl)
	if !ok {
		writeError(w, http.StatusNotFound, "Bu işlem yalnızca masaüstü uygulamasında var.")
	}
	return c, ok
}

func (s *Server) handleTraffic(w http.ResponseWriter, _ *http.Request) {
	if c, ok := s.trafficControl(w); ok {
		writeJSON(w, http.StatusOK, c.TrafficStatus())
	}
}

// tunnelMTU is the saved MTU of this computer (0 = default).
func (s *Server) tunnelMTU() int {
	if st := s.app.Status(); st.Device != nil {
		return st.Device.MTU
	}
	return 0
}

func (s *Server) handleTrafficCost(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	cover := 0
	if v := q.Get("cover"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			writeError(w, http.StatusBadRequest, "Geçersiz sahte trafik hızı.")
			return
		}
		cover = n
	}
	c, err := ComputeTrafficCost(q.Get("padding"), cover, s.tunnelMTU())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func (s *Server) handleSetTraffic(w http.ResponseWriter, r *http.Request) {
	c, ok := s.trafficControl(w)
	if !ok {
		return
	}
	var req TrafficChange
	if !decodeBody(w, r, &req) {
		return
	}
	cur := c.TrafficStatus().Settings
	padding, cover := cur.Padding, cur.CoverTraffic
	if req.Padding != nil {
		padding = *req.Padding
	}
	if req.CoverTraffic != nil {
		cover = *req.CoverTraffic
	}
	if padding == "off" {
		padding = ""
	}
	mode, ok := PaddingMode(padding)
	if !ok {
		writeError(w, http.StatusBadRequest, "Dolgu kipi off, buckets veya mtu olmalı.")
		return
	}
	// SECURITY/ROADMAP: padding and cover traffic cannot be turned on or
	// changed unless the panel showed their cost for exactly these values.
	raising := (mode != node.PaddingOff && padding != cur.Padding) || (cover > 0 && cover != cur.CoverTraffic)
	if raising && req.CostAck != CostAck(padding, cover, s.tunnelMTU()) {
		writeError(w, http.StatusPreconditionRequired, "Önce dolgu ve sahte trafiğin maliyetini görüp onayla.")
		return
	}
	if err := c.SetTraffic(req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, c.TrafficStatus())
}
