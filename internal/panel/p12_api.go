package panel

import (
	"net/http"
	"strings"

	"github.com/openscale/openscale/internal/errcode"
	"github.com/openscale/openscale/internal/netreport"
	"github.com/openscale/openscale/internal/usagehist"
)

// P12 endpoints: the stable error code catalog (#550, ADR-0165), the
// readable network report (#553), per-device traffic history (#505) and
// OpenScale's own resource use (#516). All of them only read. The panel
// pages that show them are listed in docs/rakip-analizi/calisma/
// panel-devir-P12.md.

// UsageHistory is implemented by an Observability that keeps the traffic
// and resource histories (internal/service).
type UsageHistory interface {
	TrafficHistory(device string, hours int) (TrafficHistoryReply, error)
	ResourceUsage() ResourceReply
}

// TrafficDeviceTotal is one device's total over the asked hours.
type TrafficDeviceTotal struct {
	Name string `json:"name"`
	Rx   uint64 `json:"rx"`
	Tx   uint64 `json:"tx"`
}

// TrafficHistoryReply is GET .../traffic-history. Points is filled when a
// device was asked for, one per hour, oldest first.
type TrafficHistoryReply struct {
	Schema  int                  `json:"schema"`
	Hours   int                  `json:"hours"`
	Device  string               `json:"device,omitempty"`
	Devices []TrafficDeviceTotal `json:"devices"`
	Points  []usagehist.Point    `json:"points,omitempty"`
}

// ResourceReply is GET .../resources.
type ResourceReply struct {
	Schema             int                `json:"schema"`
	SampleEverySeconds int                `json:"sampleEverySeconds"`
	Summary            usagehist.Summary  `json:"summary"`
	Samples            []usagehist.Sample `json:"samples"`
}

// ErrorCodeReply is one catalog entry.
type ErrorCodeReply struct {
	Schema int `json:"schema"`
	errcode.Entry
}

// ErrorCatalogReply is GET /api/errors.
type ErrorCatalogReply struct {
	Schema  int             `json:"schema"`
	Catalog int             `json:"catalog"`
	Codes   []errcode.Entry `json:"codes"`
}

// maxDeviceQuery bounds the device name of a history query.
const maxDeviceQuery = 128

func (s *Server) p12Routes(mux *http.ServeMux) {
	owner := func(h http.HandlerFunc) http.HandlerFunc { return s.requireSession(s.requireNetwork(h)) }
	mux.HandleFunc("GET /api/errors", s.requireSession(s.handleErrorCatalog))
	mux.HandleFunc("GET /api/errors/{code}", s.requireSession(s.handleErrorCode))
	mux.HandleFunc("GET /api/network/report", owner(s.handleNetworkReport))
}

// p12ObserveRoutes adds the histories next to the other observability
// reads, for the panel (session) and the command line (app token).
func (a *diagAPI) p12ObserveRoutes(mux *http.ServeMux, prefix string, read func(http.HandlerFunc) http.HandlerFunc) {
	mux.HandleFunc("GET "+prefix+"/traffic-history", read(a.obs(a.trafficHistory)))
	mux.HandleFunc("GET "+prefix+"/resources", read(a.obs(a.resources)))
}

func usageHistory(w http.ResponseWriter, o Observability) (UsageHistory, bool) {
	h, ok := o.(UsageHistory)
	if !ok {
		writeError(w, http.StatusNotFound, "Bu tünel trafik ve kaynak geçmişi tutmuyor; OpenScale'i güncelleyin.")
	}
	return h, ok
}

func validDeviceQuery(s string) bool {
	if len(s) > maxDeviceQuery {
		return false
	}
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c >= 'A' && c <= 'Z', c == '.', c == '_':
		default:
			return false
		}
	}
	return true
}

func (a *diagAPI) trafficHistory(w http.ResponseWriter, r *http.Request, o Observability) {
	h, ok := usageHistory(w, o)
	if !ok {
		return
	}
	hours, ok := queryInt(r, "hours", 24, 1, usagehist.RetainHours)
	if !ok {
		writeError(w, http.StatusBadRequest, "hours 1-720 arasında olmalı.")
		return
	}
	device := r.URL.Query().Get("device")
	if !validDeviceQuery(device) {
		writeError(w, http.StatusBadRequest, "Cihaz adı geçersiz.")
		return
	}
	rep, err := h.TrafficHistory(device, hours)
	if err != nil {
		diagFailed(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

func (a *diagAPI) resources(w http.ResponseWriter, _ *http.Request, o Observability) {
	h, ok := usageHistory(w, o)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, h.ResourceUsage())
}

func (s *Server) handleErrorCatalog(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	if len(q) > 200 {
		writeError(w, http.StatusBadRequest, "Arama en fazla 200 karakter olabilir.")
		return
	}
	codes := errcode.All()
	if strings.TrimSpace(q) != "" {
		codes = errcode.Search(q)
	}
	if codes == nil {
		codes = []errcode.Entry{}
	}
	writeJSON(w, http.StatusOK, ErrorCatalogReply{Schema: 1, Catalog: errcode.CatalogVersion, Codes: codes})
}

func (s *Server) handleErrorCode(w http.ResponseWriter, r *http.Request) {
	e, ok := errcode.Lookup(r.PathValue("code"))
	if !ok {
		writeError(w, http.StatusNotFound, "Bu hata kodu bilinmiyor.")
		return
	}
	writeJSON(w, http.StatusOK, ErrorCodeReply{Schema: 1, Entry: e})
}

// handleNetworkReport answers the readable report as a download:
// format=md (default) or html. The HTML is a self-contained page with its
// own restrictive policy; it is sent as an attachment and never rendered
// inside the panel's origin.
func (s *Server) handleNetworkReport(w http.ResponseWriter, r *http.Request) {
	doc, ok := s.currentDocument(w)
	if !ok {
		return
	}
	rep := netreport.Build(doc, s.now())
	base := "openscale-ag-raporu-" + s.now().UTC().Format("20060102")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	switch r.URL.Query().Get("format") {
	case "", "md":
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+base+`.md"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(netreport.Markdown(rep)))
	case "html":
		page, err := netreport.HTML(rep)
		if err != nil {
			s.fail(w, err)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+base+`.html"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(page))
	case "json":
		writeJSON(w, http.StatusOK, rep)
	default:
		writeError(w, http.StatusBadRequest, "format md, html veya json olmalı.")
	}
}

// writeErrorCode writes an error answer with its stable code (#550); the
// code is omitted when the error has none.
func writeErrorCode(w http.ResponseWriter, status int, message string, err error) {
	code := errcode.Classify(err)
	if code == "" {
		writeError(w, status, message)
		return
	}
	writeJSON(w, status, map[string]string{"error": message, "code": code})
}
