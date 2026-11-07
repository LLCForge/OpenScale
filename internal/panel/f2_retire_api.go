package panel

import (
	"net/http"
	"strings"

	"github.com/openscale/openscale/internal/admin"
)

// Device retirement wizard (#825): Cihazlar > menü > "Emekliye ayır". GET
// lists everything that names the device; POST signs the revocation and
// every clean-up in one version through the usual dry run and root
// signature (s.change).
//
// Route registration: server.go's routes() needs the line
//
//	s.f2RetireRoutes(mux) // #825: device retirement wizard (f2_retire_api.go)

// maxRetireName bounds the device name of a request.
const maxRetireName = 63

// F2RetireRequest retires one device.
type F2RetireRequest struct {
	signRequest
	Name string `json:"name"`
}

func (s *Server) f2RetireRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/f2/retire", s.requireSession(s.requireNetwork(s.handleF2RetirePreview)))
	mux.HandleFunc("POST /api/f2/retire", s.requireSession(s.requireCSRF(s.requireWritable(s.requireNetwork(s.handleF2Retire)))))
}

func retireName(raw string) (string, bool) {
	name := strings.TrimSpace(raw)
	if name == "" || len(name) > maxRetireName {
		return "", false
	}
	return name, true
}

func (s *Server) handleF2RetirePreview(w http.ResponseWriter, r *http.Request) {
	name, ok := retireName(r.URL.Query().Get("name"))
	if !ok {
		writeError(w, http.StatusBadRequest, "Cihaz adı geçersiz.")
		return
	}
	n := s.network()
	if err := n.Reload(); err != nil {
		s.fail(w, err)
		return
	}
	p, err := n.PreviewRetire(name, s.now())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) handleF2Retire(w http.ResponseWriter, r *http.Request) {
	var req F2RetireRequest
	if !decodeBody(w, r, &req) {
		return
	}
	name, ok := retireName(req.Name)
	if !ok {
		writeError(w, http.StatusBadRequest, "Cihaz adı geçersiz.")
		return
	}
	s.change(w, req.signRequest, admin.RetireChange(name, s.now()))
}
