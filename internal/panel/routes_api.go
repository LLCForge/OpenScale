package panel

import (
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/osnet"
	"github.com/openscale/openscale/internal/trust"
)

// Routes page endpoints (ADR-0133): approved subnet routes, route
// advertisements and their approval (#70, #258), route conflicts with this
// computer's networks (#165), plain WireGuard exit nodes (#264) and the
// address strategy (#267). Every change is a signed document change.

// maxRouteInput bounds the route list of one request.
const maxRouteInput = trust.MaxDeviceRoutes

func (s *Server) p10Routes(mux *http.ServeMux) {
	owner := func(h http.HandlerFunc) http.HandlerFunc { return s.requireSession(s.requireNetwork(h)) }
	ownerCheck := func(h http.HandlerFunc) http.HandlerFunc {
		return s.requireSession(s.requireCSRF(s.requireNetwork(h)))
	}
	ownerWrite := func(h http.HandlerFunc) http.HandlerFunc {
		return s.requireSession(s.requireCSRF(s.requireWritable(s.requireNetwork(h))))
	}
	mux.HandleFunc("GET /api/routes", owner(s.handleRoutes))
	mux.HandleFunc("POST /api/routes/inspect", ownerCheck(s.handleRouteInspect))
	mux.HandleFunc("POST /api/routes/approve", ownerWrite(s.handleRouteApprove))
	mux.HandleFunc("POST /api/routes/set", ownerWrite(s.handleRouteSet))
}

type routeDevice struct {
	Name   string   `json:"name"`
	IPv4   string   `json:"ipv4"`
	Routes []string `json:"routes"`
	// Clients are the devices a rule lets reach this router's routes.
	Clients []string `json:"clients"`
}

type routeExternalExit struct {
	Name        string `json:"name"`
	Endpoint    string `json:"endpoint"`
	DNS         string `json:"dns"`
	Description string `json:"description"`
}

type routeConflict struct {
	Kind    string `json:"kind"`
	Prefix  string `json:"prefix"`
	Message string `json:"message"`
}

type routesResponse struct {
	Devices         []routeDevice       `json:"devices"`
	ExternalExits   []routeExternalExit `json:"externalExits"`
	Strategy        string              `json:"strategy"`
	Reserved        []string            `json:"reserved"`
	Conflicts       []routeConflict     `json:"conflicts"`
	RouterSupported bool                `json:"routerSupported"`
}

func prefixStrings(ps []netip.Prefix) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return out
}

func (s *Server) handleRoutes(w http.ResponseWriter, r *http.Request) {
	doc, ok := s.currentDocument(w)
	if !ok {
		return
	}
	resp := routesResponse{Devices: []routeDevice{}, ExternalExits: []routeExternalExit{}, Reserved: []string{},
		Conflicts: []routeConflict{}, Strategy: "first", RouterSupported: osnet.RouterSupported()}
	routes := map[netip.Prefix]string{}
	for _, d := range doc.Devices {
		rd := routeDevice{Name: d.Name, IPv4: d.IPv4.String(), Routes: prefixStrings(d.Routes), Clients: []string{}}
		for _, c := range doc.Devices {
			if c.Name != d.Name && len(d.Routes) > 0 && doc.RouteVisible(c.Name, d.Name) {
				rd.Clients = append(rd.Clients, c.Name)
			}
		}
		for _, p := range d.Routes {
			routes[p] = d.Name
		}
		resp.Devices = append(resp.Devices, rd)
	}
	for _, x := range doc.ExternalExits {
		resp.ExternalExits = append(resp.ExternalExits, routeExternalExit{Name: x.Name, Endpoint: x.Endpoint, DNS: x.DNS.String(), Description: x.Description})
	}
	if a := doc.Addressing; a != nil {
		if a.Strategy != "" {
			resp.Strategy = a.Strategy
		}
		resp.Reserved = prefixStrings(a.Reserved)
	}
	// Overlaps with the networks of the computer running the panel (#165).
	if locals, err := osnet.LocalNetworks("OpenScale"); err == nil {
		// An interface holding exactly a network prefix is this computer's
		// own tunnel, whatever its name.
		kept := locals[:0]
		for _, l := range locals {
			if l.Prefix.Masked() != doc.IPv4Prefix && l.Prefix.Masked() != doc.IPv6Prefix {
				kept = append(kept, l)
			}
		}
		for _, c := range osnet.RouteConflicts([]netip.Prefix{doc.IPv4Prefix, doc.IPv6Prefix}, routes, kept) {
			resp.Conflicts = append(resp.Conflicts, routeConflict{Kind: c.Kind, Prefix: c.Prefix.String(), Message: c.Message})
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

type routeInspectRequest struct {
	Advertisement string `json:"advertisement"`
}

type routeInspectResponse struct {
	Device   string    `json:"device"`
	Routes   []string  `json:"routes"`
	Current  []string  `json:"current"`
	IssuedAt time.Time `json:"issuedAt"`
}

func (s *Server) handleRouteInspect(w http.ResponseWriter, r *http.Request) {
	var req routeInspectRequest
	if !decodeBody(w, r, &req) {
		return
	}
	doc, ok := s.currentDocument(w)
	if !ok {
		return
	}
	a, dev, err := doc.OpenRouteAdvertisement(req.Advertisement, s.now())
	if err != nil {
		writeError(w, http.StatusBadRequest, "Rota ilanı doğrulanamadı: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, routeInspectResponse{Device: dev.Name, Routes: prefixStrings(a.Routes), Current: prefixStrings(dev.Routes), IssuedAt: a.IssuedAt})
}

type routeApproveRequest struct {
	signRequest
	Advertisement string   `json:"advertisement"`
	Only          []string `json:"only"`
}

func parsePrefixes(w http.ResponseWriter, in []string) ([]netip.Prefix, bool) {
	if len(in) > maxRouteInput {
		writeError(w, http.StatusBadRequest, "Çok fazla rota.")
		return nil, false
	}
	out := make([]netip.Prefix, 0, len(in))
	for _, s := range in {
		p, err := netip.ParsePrefix(strings.TrimSpace(s))
		if err != nil || p != p.Masked() {
			writeError(w, http.StatusBadRequest, "Rota maskeli CIDR olmalı (ör. 192.168.1.0/24).")
			return nil, false
		}
		if err := trust.ValidateRoutePrefix(p); err != nil {
			writeError(w, http.StatusBadRequest, "Geçersiz rota: "+err.Error())
			return nil, false
		}
		out = append(out, p)
	}
	return out, true
}

func (s *Server) handleRouteApprove(w http.ResponseWriter, r *http.Request) {
	var req routeApproveRequest
	if !decodeBody(w, r, &req) {
		return
	}
	only, ok := parsePrefixes(w, req.Only)
	if !ok {
		return
	}
	now := s.now()
	s.change(w, req.signRequest, func(doc *trust.Document) error {
		_, _, err := doc.ApproveRouteAdvertisement(req.Advertisement, only, now)
		return err
	})
}

type routeSetRequest struct {
	signRequest
	Device string   `json:"device"`
	Routes []string `json:"routes"`
}

func (s *Server) handleRouteSet(w http.ResponseWriter, r *http.Request) {
	var req routeSetRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.Device == "" {
		writeError(w, http.StatusBadRequest, "Cihaz seçin.")
		return
	}
	routes, ok := parsePrefixes(w, req.Routes)
	if !ok {
		return
	}
	s.change(w, req.signRequest, func(doc *trust.Document) error { return doc.SetDeviceRoutes(req.Device, routes) })
}
