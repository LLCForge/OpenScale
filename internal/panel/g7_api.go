package panel

import (
	"net/http"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/adblock"
	"github.com/openscale/openscale/internal/healthmon"
	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/notify"
	"github.com/openscale/openscale/internal/trust"
)

// Blocking, plugin and monitoring endpoints (ADR-0220, G7).
//
// The signed part (subscriptions with digests, category policy, keep list,
// DoH names, plugin pins) changes only through the shared change() path:
// a dry run shows the difference, the root key passphrase signs it. The
// running part (counters, plugin status, allow once, top list) is read
// from the exit node resolver of this process; the monitoring screens use
// the desktop service through MonitorApp and answer 501 without it.

// ExtensionsView is GET /api/g7/extensions.
type ExtensionsView struct {
	Blocking *trust.BlockingSettings   `json:"blocking"`
	Pins     []trust.PluginPin         `json:"pins"`
	Runtime  node.ExitExtensionsStatus `json:"runtime"`
	// Categories are the category names the policy understands.
	Categories []string `json:"categories"`
	// ExitNodes are the devices that run the resolver extensions.
	ExitNodes []string `json:"exit_nodes"`
}

type blockingRequest struct {
	signRequest
	Blocking trust.BlockingSettings `json:"blocking"`
}

type g7PinRequest struct {
	signRequest
	Pin trust.PluginPin `json:"pin"`
}

type unpinRequest struct {
	signRequest
	Name string `json:"name"`
}

type allowOnceRequest struct {
	Device  string `json:"device"`
	Name    string `json:"name"`
	Minutes int    `json:"minutes"`
}

type topRequest struct {
	Minutes int `json:"minutes"`
}

// TopView is GET /api/g7/adblock/top.
type TopView struct {
	Active bool                `json:"active"`
	Until  time.Time           `json:"until,omitzero"`
	Names  []adblock.NameCount `json:"names"`
	Once   []adblock.AllowOnce `json:"once"`
}

// MonitorApp is what the desktop service offers the monitoring screen
// (#763, #764, #774, #781-#784, #748, #749). Another group wires it into
// the service; until then the endpoints answer 501.
type MonitorApp interface {
	MonitorServices() []healthmon.ServiceStatus
	MonitorDevices() []MonitorDevice
	MonitorQuality(device string, coarse bool) ([]healthmon.Point, error)
	NotifyConfig() (notify.Config, error)
	SetNotifyConfig(notify.Config) error
	NotifyTest(label string) error
	WeeklyPreview() (subject, text string, err error)
	SpeedTest(target string) (healthmon.SpeedResult, error)
	SpeedHistory(target string) []healthmon.SpeedResult
	Wake(device string) error
	MapDrive(name string) error
	UnmapDrive(name string) error
}

// MonitorDevice is one device row of the monitoring screen.
type MonitorDevice struct {
	Name     string    `json:"name"`
	Watched  bool      `json:"watched"`
	Online   bool      `json:"online"`
	LastSeen time.Time `json:"last_seen,omitzero"`
	Warnings []string  `json:"warnings"`
}

func (s *Server) g7Routes(mux *http.ServeMux) {
	owner := func(h http.HandlerFunc) http.HandlerFunc { return s.requireSession(s.requireNetwork(h)) }
	ownerWrite := func(h http.HandlerFunc) http.HandlerFunc {
		return s.requireSession(s.requireCSRF(s.requireWritable(s.requireNetwork(h))))
	}
	local := func(h http.HandlerFunc) http.HandlerFunc {
		return s.requireSession(s.requireCSRF(s.requireWritable(h)))
	}
	mux.HandleFunc("GET /api/g7/extensions", owner(s.handleExtensions))
	mux.HandleFunc("POST /api/g7/blocking", ownerWrite(s.handleSetBlocking))
	mux.HandleFunc("POST /api/g7/plugins/pin", ownerWrite(s.handlePinPlugin))
	mux.HandleFunc("POST /api/g7/plugins/unpin", ownerWrite(s.handleUnpinPlugin))
	mux.HandleFunc("GET /api/g7/adblock/top", s.requireSession(s.handleAdblockTop))
	mux.HandleFunc("POST /api/g7/adblock/top", local(s.handleAdblockTopStart))
	mux.HandleFunc("POST /api/g7/adblock/allow-once", local(s.handleAllowOnce))
	mux.HandleFunc("POST /api/g7/adblock/allow-once/revoke", local(s.handleRevokeAllowOnce))

	read := func(h func(http.ResponseWriter, *http.Request, MonitorApp)) http.HandlerFunc {
		return s.requireSession(s.monitor(h))
	}
	write := func(h func(http.ResponseWriter, *http.Request, MonitorApp)) http.HandlerFunc {
		return s.requireSession(s.requireCSRF(s.requireWritable(s.monitor(h))))
	}
	mux.HandleFunc("GET /api/g7/monitor", read(s.handleMonitor))
	mux.HandleFunc("GET /api/g7/monitor/quality", read(s.handleQuality))
	mux.HandleFunc("GET /api/g7/notify", read(s.handleNotify))
	mux.HandleFunc("PUT /api/g7/notify", write(s.handleSetNotify))
	mux.HandleFunc("POST /api/g7/notify", write(s.handleSetNotify))
	mux.HandleFunc("POST /api/g7/notify/test", write(s.handleNotifyTest))
	mux.HandleFunc("GET /api/g7/notify/report", read(s.handleWeeklyPreview))
	mux.HandleFunc("POST /api/g7/speedtest", write(s.handleSpeedTest))
	mux.HandleFunc("GET /api/g7/speedtest", read(s.handleSpeedHistory))
	mux.HandleFunc("POST /api/g7/wake", write(s.handleG7Wake))
	mux.HandleFunc("POST /api/g7/drives/map", write(s.handleDriveMap))
}

func (s *Server) handleExtensions(w http.ResponseWriter, _ *http.Request) {
	doc, ok := s.currentDocument(w)
	if !ok {
		return
	}
	v := ExtensionsView{Blocking: doc.Blocking, Pins: doc.Plugins, Runtime: node.ExitExtensions()}
	if v.Pins == nil {
		v.Pins = []trust.PluginPin{}
	}
	for _, c := range adblock.AllCategories {
		v.Categories = append(v.Categories, c.String())
	}
	v.ExitNodes = []string{}
	for _, d := range doc.Devices {
		if d.HasRole(trust.RoleExitNode) {
			v.ExitNodes = append(v.ExitNodes, d.Name)
		}
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) handleSetBlocking(w http.ResponseWriter, r *http.Request) {
	var req blockingRequest
	if !decodeBody(w, r, &req) {
		return
	}
	defer wipeString(&req.Passphrase)
	b := req.Blocking
	s.change(w, req.signRequest, func(doc *trust.Document) error { return doc.SetBlocking(&b) })
}

func (s *Server) handlePinPlugin(w http.ResponseWriter, r *http.Request) {
	var req g7PinRequest
	if !decodeBody(w, r, &req) {
		return
	}
	defer wipeString(&req.Passphrase)
	p := req.Pin
	p.Name = strings.TrimSpace(p.Name)
	s.change(w, req.signRequest, func(doc *trust.Document) error { return doc.SetPluginPin(p) })
}

func (s *Server) handleUnpinPlugin(w http.ResponseWriter, r *http.Request) {
	var req unpinRequest
	if !decodeBody(w, r, &req) {
		return
	}
	defer wipeString(&req.Passphrase)
	name := strings.TrimSpace(req.Name)
	s.change(w, req.signRequest, func(doc *trust.Document) error { return doc.RemovePluginPin(name) })
}

// wipeString drops the request's copy of a secret; the bytes the change
// path signs with are wiped there (change).
func wipeString(p *string) { *p = "" }

func adblockEngine(w http.ResponseWriter) (*adblock.Engine, bool) {
	e := node.ExitAdblockEngine()
	if e == nil {
		writeError(w, http.StatusConflict, "Kategori engelleyici bu bilgisayarda çalışmıyor. Yalnızca engelleme açık bir çıkış düğümünde kullanılabilir.")
		return nil, false
	}
	return e, true
}

func (s *Server) handleAdblockTop(w http.ResponseWriter, _ *http.Request) {
	v := TopView{Names: []adblock.NameCount{}, Once: []adblock.AllowOnce{}}
	if e := node.ExitAdblockEngine(); e != nil {
		now := s.now()
		names, until := e.Top(20, now)
		if names != nil {
			v.Names = names
		}
		v.Until, v.Active = until, until.After(now)
		if o := e.AllowOnces(now); o != nil {
			v.Once = o
		}
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) handleAdblockTopStart(w http.ResponseWriter, r *http.Request) {
	var req topRequest
	if !decodeBody(w, r, &req) {
		return
	}
	e, ok := adblockEngine(w)
	if !ok {
		return
	}
	if req.Minutes <= 0 {
		e.StopTop()
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		return
	}
	until, err := e.StartTop(time.Duration(req.Minutes)*time.Minute, s.now())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]time.Time{"until": until})
}

func (s *Server) handleAllowOnce(w http.ResponseWriter, r *http.Request) {
	var req allowOnceRequest
	if !decodeBody(w, r, &req) {
		return
	}
	e, ok := adblockEngine(w)
	if !ok {
		return
	}
	a, err := e.AllowOnceFor(strings.TrimSpace(req.Device), strings.TrimSpace(req.Name), time.Duration(req.Minutes)*time.Minute, s.now())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, a)
}

func (s *Server) handleRevokeAllowOnce(w http.ResponseWriter, r *http.Request) {
	var req allowOnceRequest
	if !decodeBody(w, r, &req) {
		return
	}
	e, ok := adblockEngine(w)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"removed": e.RevokeAllowOnce(strings.TrimSpace(req.Device), strings.TrimSpace(req.Name))})
}

// --- monitoring (MonitorApp) ---

func (s *Server) monitor(h func(http.ResponseWriter, *http.Request, MonitorApp)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, ok := s.app.(MonitorApp)
		if p, has := s.app.(interface{ MonitorApp() MonitorApp }); !ok && has {
			a, ok = p.MonitorApp(), true
		}
		if !ok {
			writeError(w, http.StatusNotImplemented, "İzleme bu sürümde masaüstü servisine bağlı değil.")
			return
		}
		h(w, r, a)
	}
}

// MonitorView is GET /api/g7/monitor.
type MonitorView struct {
	Services []monitorService `json:"services"`
	Devices  []MonitorDevice  `json:"devices"`
}

type monitorService struct {
	Name          string    `json:"name"`
	State         string    `json:"state"`
	Since         time.Time `json:"since"`
	DowntimeSec   int64     `json:"downtime_sec"`
	LastError     string    `json:"last_error,omitempty"`
	LastLatencyMS int64     `json:"last_latency_ms"`
}

func (s *Server) handleMonitor(w http.ResponseWriter, _ *http.Request, a MonitorApp) {
	v := MonitorView{Services: []monitorService{}, Devices: a.MonitorDevices()}
	if v.Devices == nil {
		v.Devices = []MonitorDevice{}
	}
	for _, st := range a.MonitorServices() {
		v.Services = append(v.Services, monitorService{
			Name: st.Name, State: string(st.State), Since: st.Since,
			DowntimeSec: int64(st.Downtime / time.Second), LastError: st.Last.Error,
			LastLatencyMS: st.Last.Latency.Milliseconds(),
		})
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) handleQuality(w http.ResponseWriter, r *http.Request, a MonitorApp) {
	device := strings.TrimSpace(r.URL.Query().Get("device"))
	if device == "" || len(device) > 64 {
		writeError(w, http.StatusBadRequest, "Cihaz adı gerekli.")
		return
	}
	pts, err := a.MonitorQuality(device, r.URL.Query().Get("res") == "1h")
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	if pts == nil {
		pts = []healthmon.Point{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"device": device, "points": pts})
}

func (s *Server) handleNotify(w http.ResponseWriter, _ *http.Request, a MonitorApp) {
	c, err := a.NotifyConfig()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "Bildirim ayarları okunamadı.")
		return
	}
	writeJSON(w, http.StatusOK, c.Redacted())
}

func (s *Server) handleSetNotify(w http.ResponseWriter, r *http.Request, a MonitorApp) {
	var c notify.Config
	if !decodeBody(w, r, &c) {
		return
	}
	// "***" keeps the stored secret of the channel with the same label.
	if cur, err := a.NotifyConfig(); err == nil {
		old := map[string]notify.ChannelConfig{}
		for _, ch := range cur.Channels {
			old[ch.Label] = ch
		}
		for i, ch := range c.Channels {
			if ch.Token == "***" {
				c.Channels[i].Token = old[ch.Label].Token
			}
			if ch.Password == "***" {
				c.Channels[i].Password = old[ch.Label].Password
			}
		}
	}
	if err := c.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.SetNotifyConfig(c); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, c.Redacted())
}

func (s *Server) handleNotifyTest(w http.ResponseWriter, r *http.Request, a MonitorApp) {
	var req struct {
		Label string `json:"label"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	if err := a.NotifyTest(strings.TrimSpace(req.Label)); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleWeeklyPreview(w http.ResponseWriter, _ *http.Request, a MonitorApp) {
	subject, text, err := a.WeeklyPreview()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"subject": subject, "text": text})
}

type targetRequest struct {
	Target string `json:"target"`
	Device string `json:"device"`
	Name   string `json:"name"`
}

func (s *Server) handleSpeedTest(w http.ResponseWriter, r *http.Request, a MonitorApp) {
	var req targetRequest
	if !decodeBody(w, r, &req) {
		return
	}
	res, err := a.SpeedTest(strings.TrimSpace(req.Target))
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleSpeedHistory(w http.ResponseWriter, r *http.Request, a MonitorApp) {
	h := a.SpeedHistory(strings.TrimSpace(r.URL.Query().Get("target")))
	if h == nil {
		h = []healthmon.SpeedResult{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": h})
}

func (s *Server) handleG7Wake(w http.ResponseWriter, r *http.Request, a MonitorApp) {
	var req targetRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if err := a.Wake(strings.TrimSpace(req.Device)); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleDriveMap(w http.ResponseWriter, r *http.Request, a MonitorApp) {
	var req struct {
		Name  string `json:"name"`
		Unmap bool   `json:"unmap"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	var err error
	if req.Unmap {
		err = a.UnmapDrive(strings.TrimSpace(req.Name))
	} else {
		err = a.MapDrive(strings.TrimSpace(req.Name))
	}
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
