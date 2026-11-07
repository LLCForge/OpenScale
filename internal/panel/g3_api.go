package panel

import (
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/magicdns"
	"github.com/openscale/openscale/internal/trust"
)

// Network opsec endpoints and the signed panel name (ADR-0186..0191).
//
// The remote panel (ADR-0107) accepts, besides its tunnel address, the
// name "yonetim.<network domain>" when MagicDNS gives that name to this
// computer (magicdns.PanelHosts). The name comes from the signed document
// only: a DNS rebinding page cannot make the panel accept a name the
// owner did not sign, and the address the browser connected to must
// still be this computer's tunnel address.

// signedPanelHost reports whether host is the signed panel name with this
// server's port, and this server listens on an address the name resolves
// to.
func (s *Server) signedPanelHost(host string) bool {
	if s.host == "" {
		return false
	}
	name, port, err := net.SplitHostPort(host)
	if err != nil {
		return false
	}
	myHost, myPort, err := net.SplitHostPort(s.host)
	if err != nil || port != myPort {
		return false
	}
	addr, err := netip.ParseAddr(myHost)
	if err != nil || addr.IsLoopback() {
		return false
	}
	n := s.network()
	if n == nil {
		return false
	}
	doc, err := n.Document()
	if err != nil {
		return false
	}
	return panelNameMatches(doc, name, addr.Unmap())
}

// panelNameMatches is signedPanelHost's document check.
func panelNameMatches(doc *trust.Document, name string, addr netip.Addr) bool {
	want := magicdns.PanelName(doc)
	if want == "" || !strings.EqualFold(strings.TrimSuffix(name, "."), want) {
		return false
	}
	for _, d := range magicdns.PanelHosts(doc) {
		if d.IPv4 == addr || d.IPv6 == addr {
			return true
		}
	}
	return false
}

// PanelNameView is GET /api/g3/panel-name.
type PanelNameView struct {
	// Name is "yonetim.<domain>"; empty when no device serves the remote
	// panel or the label is taken.
	Name string `json:"name"`
	// URLs open the remote panel by name (one per serving device's port).
	URL   string   `json:"url,omitempty"`
	Hosts []string `json:"hosts"`
	// Note explains an empty name.
	Note string `json:"note,omitempty"`
}

func (s *Server) handlePanelName(w http.ResponseWriter, _ *http.Request) {
	doc, err := s.network().Document()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Belge okunamadı.")
		return
	}
	writeJSON(w, http.StatusOK, panelNameView(doc))
}

func panelNameView(doc *trust.Document) PanelNameView {
	v := PanelNameView{Name: magicdns.PanelName(doc), Hosts: []string{}}
	for _, d := range magicdns.PanelHosts(doc) {
		v.Hosts = append(v.Hosts, d.Name)
	}
	if v.Name == "" {
		v.Note = "Uzak panel kuralı olan cihaz yok veya 'yonetim' adı bir cihaz ya da kayıt tarafından kullanılıyor."
		return v
	}
	v.URL = "http://" + net.JoinHostPort(v.Name, strconv.Itoa(int(trust.PanelPort))) + "/"
	return v
}

// OpsecApp is what the desktop service offers the opsec screen. The
// service implements it (another group wires it, see panel-devir-G3.md);
// without it the endpoints answer 501.
type OpsecApp interface {
	Opsec() (OpsecView, error)
	// ReleaseQuarantine lifts a local quarantine of peer.
	ReleaseQuarantine(peer string) (bool, error)
}

// OpsecView is GET /api/app/opsec. Every part is optional.
type OpsecView struct {
	Obfs struct {
		Mode    string `json:"mode"`
		TLS     bool   `json:"tls"`
		Buckets []int  `json:"buckets,omitempty"`
		Jitter  string `json:"jitter,omitempty"`
		Wrapped uint64 `json:"wrapped"`
	} `json:"obfs"`
	Quarantine []OpsecQuarantine `json:"quarantine"`
	Alerts     []OpsecAlert      `json:"alerts"`
	Canary     []OpsecCanary     `json:"canary"`
	Chain      struct {
		Entry  string `json:"entry,omitempty"`
		Final  string `json:"final,omitempty"`
		Ready  bool   `json:"ready"`
		Reason string `json:"reason,omitempty"`
	} `json:"chain"`
	Lost struct {
		Lost  bool      `json:"lost"`
		Since time.Time `json:"since,omitzero"`
	} `json:"lost"`
}

// OpsecQuarantine is one quarantined device.
type OpsecQuarantine struct {
	Peer   string    `json:"peer"`
	Reason string    `json:"reason"`
	Since  time.Time `json:"since"`
	Until  time.Time `json:"until,omitzero"`
}

// OpsecAlert is one alarm.
type OpsecAlert struct {
	Kind string    `json:"kind"`
	Peer string    `json:"peer,omitempty"`
	Text string    `json:"text"`
	At   time.Time `json:"at"`
}

// OpsecCanary is one exit TLS canary result.
type OpsecCanary struct {
	Address string    `json:"address"`
	Status  string    `json:"status"`
	ViaExit string    `json:"via_exit,omitempty"`
	At      time.Time `json:"at"`
}

func (s *Server) opsecApp(w http.ResponseWriter) (OpsecApp, bool) {
	a, ok := s.app.(OpsecApp)
	if !ok {
		writeError(w, http.StatusNotImplemented, "Bu sürümde ağ gizliliği durumu yok.")
		return nil, false
	}
	return a, true
}

func (s *Server) handleOpsec(w http.ResponseWriter, _ *http.Request) {
	a, ok := s.opsecApp(w)
	if !ok {
		return
	}
	v, err := a.Opsec()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "Ağ gizliliği durumu alınamadı.")
		return
	}
	if v.Quarantine == nil {
		v.Quarantine = []OpsecQuarantine{}
	}
	if v.Alerts == nil {
		v.Alerts = []OpsecAlert{}
	}
	if v.Canary == nil {
		v.Canary = []OpsecCanary{}
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) handleReleaseQuarantine(w http.ResponseWriter, r *http.Request) {
	a, ok := s.opsecApp(w)
	if !ok {
		return
	}
	var req struct {
		Peer string `json:"peer"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	if req.Peer == "" || len(req.Peer) > 63 {
		writeError(w, http.StatusBadRequest, "Cihaz adı geçersiz.")
		return
	}
	released, err := a.ReleaseQuarantine(req.Peer)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "Karantina kaldırılamadı.")
		return
	}
	if !released {
		writeError(w, http.StatusNotFound, "Bu cihaz karantinada değil.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"released": true})
}

// g3Routes registers the G3 endpoints.
func (s *Server) g3Routes(mux *http.ServeMux) {
	owner := func(h http.HandlerFunc) http.HandlerFunc { return s.requireSession(s.requireNetwork(h)) }
	appRead := func(h http.HandlerFunc) http.HandlerFunc { return s.requireSession(s.requireApp(h)) }
	appWrite := func(h http.HandlerFunc) http.HandlerFunc {
		return s.requireSession(s.requireCSRF(s.requireWritable(s.requireApp(h))))
	}
	mux.HandleFunc("GET /api/g3/panel-name", owner(s.handlePanelName))
	mux.HandleFunc("GET /api/app/opsec", appRead(s.handleOpsec))
	mux.HandleFunc("POST /api/app/opsec/quarantine/release", appWrite(s.handleReleaseQuarantine))
}
