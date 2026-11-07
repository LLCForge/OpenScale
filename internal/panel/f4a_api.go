package panel

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/fwtemplate"
	"github.com/openscale/openscale/internal/support"
	"github.com/openscale/openscale/internal/trust"
)

// Faz 4A/4E endpoints (ADR-0232): device icons (#233), firewall templates
// with ranges (#243) and the remote support toolbox (#852).
//
// Icons, templates and the support rule change the signed document and go
// through Server.change (dry run, diff, root key). The support toolbox
// itself acts from this computer through the desktop service; what it may
// read or end is decided by the signed rules on the target device, which
// also asks the person there and shows the "remotely connected" notice.

// SupportApp is what the desktop service offers the support screens.
type SupportApp interface {
	// SupportSnapshot asks device for one kind of snapshot.
	SupportSnapshot(ctx context.Context, device, kind string) (support.Snapshot, error)
	// SupportKill asks device to end a process.
	SupportKill(ctx context.Context, device string, pid int, name string) error
	// SupportLocal is this device's side: pending requests and sessions.
	SupportLocal() SupportLocalView
	// SupportDecide answers a pending request on this device.
	SupportDecide(id string, accept bool) error
	// SupportEndAll ends every support session on this device.
	SupportEndAll() int
}

// SupportLocalView is GET /api/app/support/local.
type SupportLocalView struct {
	Hosted   bool                  `json:"hosted"`
	Pending  []support.Request     `json:"pending"`
	Sessions []support.SessionInfo `json:"sessions"`
	Log      []support.LogEvent    `json:"log"`
}

const supportTimeout = 2 * time.Minute

func (s *Server) f4aRoutes(mux *http.ServeMux) {
	owner := func(h http.HandlerFunc) http.HandlerFunc { return s.requireSession(s.requireNetwork(h)) }
	ownerCheck := func(h http.HandlerFunc) http.HandlerFunc {
		return s.requireSession(s.requireCSRF(s.requireNetwork(h)))
	}
	ownerWrite := func(h http.HandlerFunc) http.HandlerFunc {
		return s.requireSession(s.requireCSRF(s.requireWritable(s.requireNetwork(h))))
	}
	read := func(h func(http.ResponseWriter, *http.Request, SupportApp)) http.HandlerFunc {
		return s.requireSession(s.requireApp(s.withSupport(h)))
	}
	write := func(h func(http.ResponseWriter, *http.Request, SupportApp)) http.HandlerFunc {
		return s.requireSession(s.requireCSRF(s.requireWritable(s.requireApp(s.withSupport(h)))))
	}
	mux.HandleFunc("GET /api/devices/icons", s.requireSession(s.handleIconList))
	mux.HandleFunc("POST /api/devices/icon", ownerWrite(s.handleDeviceIcon))
	mux.HandleFunc("GET /api/fwtemplate", owner(s.handleTemplateList))
	mux.HandleFunc("POST /api/fwtemplate/preview", ownerCheck(s.handleTemplatePreview))
	mux.HandleFunc("POST /api/fwtemplate/apply", ownerWrite(s.handleTemplateApply))
	mux.HandleFunc("GET /api/support/rule", owner(s.handleSupportRuleState))
	mux.HandleFunc("POST /api/support/rule", ownerWrite(s.handleSupportRule))
	mux.HandleFunc("GET /api/app/support/snapshot", read(s.handleSupportSnapshot))
	mux.HandleFunc("POST /api/app/support/kill", write(s.handleSupportKill))
	mux.HandleFunc("GET /api/app/support/local", read(s.handleSupportLocal))
	mux.HandleFunc("POST /api/app/support/local/decide", write(s.handleSupportDecide))
	mux.HandleFunc("POST /api/app/support/local/end", write(s.handleSupportEnd))
}

func (s *Server) withSupport(h func(http.ResponseWriter, *http.Request, SupportApp)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, ok := s.app.(SupportApp)
		if !ok {
			writeError(w, http.StatusNotImplemented, "Destek araçları bu sürümde yok.")
			return
		}
		h(w, r, a)
	}
}

// normalizeAddrEntries turns bare IP addresses into single-address CIDRs.
func normalizeAddrEntries(list []string) {
	for i, e := range list {
		list[i] = trust.NormalizeAddrEntry(e)
	}
}

// --- device icons (#233) ---

func (s *Server) handleIconList(w http.ResponseWriter, _ *http.Request) {
	icons := trust.DeviceIcons()
	out := make([]string, len(icons))
	for i, ic := range icons {
		out[i] = string(ic)
	}
	writeJSON(w, http.StatusOK, map[string][]string{"icons": out})
}

type deviceIconRequest struct {
	signRequest
	Name string `json:"name"`
	Icon string `json:"icon"`
}

func (s *Server) handleDeviceIcon(w http.ResponseWriter, r *http.Request) {
	var req deviceIconRequest
	if !decodeBody(w, r, &req) {
		return
	}
	icon := trust.DeviceIcon(strings.TrimSpace(req.Icon))
	if !validDeviceName(req.Name) || (icon != "" && !icon.Valid()) {
		writeError(w, http.StatusBadRequest, "Cihaz adı veya simge geçersiz.")
		return
	}
	s.change(w, req.signRequest, func(doc *trust.Document) error { return doc.SetDeviceIcon(req.Name, icon) })
}

// --- firewall templates (#243) ---

func (s *Server) handleTemplateList(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string][]fwtemplate.Info{"templates": fwtemplate.Templates()})
}

type templateRequest struct {
	signRequest
	Kind     string   `json:"kind"`
	Subject  string   `json:"subject"`
	Targets  []string `json:"targets"`
	Protocol string   `json:"protocol"`
	Ports    []string `json:"ports"`
	Isolate  bool     `json:"isolate"`
	// Base is the preview's fingerprint; apply refuses a changed document.
	Base string `json:"base"`
}

func (req templateRequest) params() (fwtemplate.Kind, fwtemplate.Params, bool) {
	targets, ok1 := cleanList(req.Targets, 16, maxReferenceLen)
	ports, ok2 := cleanList(req.Ports, 32, 11)
	subject := trust.NormalizeAddrEntry(req.Subject)
	if !ok1 || !ok2 || subject == "" || len(subject) > maxReferenceLen || len(req.Kind) > 32 || len(req.Protocol) > 8 {
		return "", fwtemplate.Params{}, false
	}
	return fwtemplate.Kind(req.Kind), fwtemplate.Params{Subject: subject, Targets: targets, Protocol: trust.Protocol(strings.ToLower(req.Protocol)),
		Ports: ports, Isolate: req.Isolate}, true
}

func (s *Server) handleTemplatePreview(w http.ResponseWriter, r *http.Request) {
	var req templateRequest
	if !decodeBody(w, r, &req) {
		return
	}
	kind, p, ok := req.params()
	if !ok {
		writeError(w, http.StatusBadRequest, "Şablon isteği geçersiz.")
		return
	}
	doc, ok := s.currentDocument(w)
	if !ok {
		return
	}
	plan, err := fwtemplate.Build(doc, kind, p)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if plan.Disabled == nil {
		plan.Disabled = []int{}
	}
	if plan.Warnings == nil {
		plan.Warnings = []string{}
	}
	if plan.Reach == nil {
		plan.Reach = []fwtemplate.ReachChange{}
	}
	writeJSON(w, http.StatusOK, plan)
}

func (s *Server) handleTemplateApply(w http.ResponseWriter, r *http.Request) {
	var req templateRequest
	if !decodeBody(w, r, &req) {
		return
	}
	kind, p, ok := req.params()
	if !ok || req.Base == "" {
		writeError(w, http.StatusBadRequest, "Şablon isteği geçersiz.")
		return
	}
	s.change(w, req.signRequest, func(doc *trust.Document) error {
		plan, err := fwtemplate.Build(doc, kind, p)
		if err != nil {
			return err
		}
		if plan.Base != req.Base {
			return fwtemplate.ErrStale
		}
		return plan.Apply(doc)
	})
}

// --- support rule (#852) ---

type supportRuleRequest struct {
	signRequest
	From      string `json:"from"`
	To        string `json:"to"`
	AllowKill bool   `json:"allowKill"`
}

// supportRuleState is GET /api/support/rule?from=&to=.
type supportRuleState struct {
	Read bool `json:"read"`
	Kill bool `json:"kill"`
}

func (s *Server) handleSupportRuleState(w http.ResponseWriter, r *http.Request) {
	from, to := r.URL.Query().Get("from"), r.URL.Query().Get("to")
	if !validDeviceName(from) || !validDeviceName(to) {
		writeError(w, http.StatusBadRequest, "Cihaz adı geçersiz.")
		return
	}
	doc, ok := s.currentDocument(w)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, supportRuleState{Read: doc.AllowsSupport(from, to, trust.SupportRead), Kill: doc.AllowsSupport(from, to, trust.SupportKill)})
}

func (s *Server) handleSupportRule(w http.ResponseWriter, r *http.Request) {
	var req supportRuleRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if !validDeviceName(req.From) || !validDeviceName(req.To) || req.From == req.To {
		writeError(w, http.StatusBadRequest, "Cihaz adı geçersiz.")
		return
	}
	desc := "Uzaktan destek: " + req.From + " -> " + req.To
	s.change(w, req.signRequest, func(doc *trust.Document) error {
		return doc.AddRule(trust.Rule{From: []string{req.From}, To: []string{req.To}, Service: trust.ServiceSupport, AllowKill: req.AllowKill, Description: desc})
	})
}

// --- support toolbox (#852) ---

func supportError(w http.ResponseWriter, err error) {
	var re *support.RemoteError
	switch {
	case errors.As(err, &re):
		writeError(w, http.StatusBadGateway, "Cihaz yanıtı: "+re.Message)
	case errors.Is(err, context.DeadlineExceeded):
		writeError(w, http.StatusGatewayTimeout, "Cihaz zamanında yanıt vermedi; karşıdaki kişi isteği onaylamamış olabilir.")
	default:
		writeError(w, http.StatusBadGateway, err.Error())
	}
}

func (s *Server) handleSupportSnapshot(w http.ResponseWriter, r *http.Request, a SupportApp) {
	device, kind := r.URL.Query().Get("device"), r.URL.Query().Get("kind")
	if !validDeviceParam(device) || !support.ValidKind(kind) {
		writeError(w, http.StatusBadRequest, "Cihaz veya tür geçersiz.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), supportTimeout)
	defer cancel()
	snap, err := a.SupportSnapshot(ctx, device, kind)
	if err != nil {
		supportError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, snap)
}

type supportKillRequest struct {
	Device string `json:"device"`
	PID    int    `json:"pid"`
	Name   string `json:"name"`
}

func (s *Server) handleSupportKill(w http.ResponseWriter, r *http.Request, a SupportApp) {
	var req supportKillRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if !validDeviceParam(req.Device) || req.PID <= 0 || req.Name == "" || len(req.Name) > support.MaxNameLen {
		writeError(w, http.StatusBadRequest, "Süreç geçersiz.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), supportTimeout)
	defer cancel()
	if err := a.SupportKill(ctx, req.Device, req.PID, req.Name); err != nil {
		supportError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"result": "Süreç " + strconv.Itoa(req.PID) + " sonlandırıldı."})
}

func (s *Server) handleSupportLocal(w http.ResponseWriter, _ *http.Request, a SupportApp) {
	v := a.SupportLocal()
	if v.Pending == nil {
		v.Pending = []support.Request{}
	}
	if v.Sessions == nil {
		v.Sessions = []support.SessionInfo{}
	}
	if v.Log == nil {
		v.Log = []support.LogEvent{}
	}
	writeJSON(w, http.StatusOK, v)
}

type supportDecideRequest struct {
	ID     string `json:"id"`
	Accept bool   `json:"accept"`
}

func (s *Server) handleSupportDecide(w http.ResponseWriter, r *http.Request, a SupportApp) {
	var req supportDecideRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.ID == "" || len(req.ID) > 64 {
		writeError(w, http.StatusBadRequest, "İstek bulunamadı.")
		return
	}
	if err := a.SupportDecide(req.ID, req.Accept); err != nil {
		writeError(w, http.StatusNotFound, "İstek bulunamadı veya süresi geçti.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleSupportEnd(w http.ResponseWriter, _ *http.Request, a SupportApp) {
	writeJSON(w, http.StatusOK, map[string]int{"ended": a.SupportEndAll()})
}
