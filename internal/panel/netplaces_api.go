package panel

import (
	"net/http"

	"github.com/openscale/openscale/internal/sysinfo"
)

// Network locations (ADR-0226): the SMB shares other devices list in
// their detailed inventory are added to Windows Explorer's "Ağdaki
// konumlar" by the tray of an admin Windows device. The service keeps the
// owner's switch and gives the tray the devices and shares; the tray, in
// the user's session, writes the locations. No credential passes here.

// NetPlaceDevice is one device of the signed document and the shares its
// last detailed inventory listed.
type NetPlaceDevice struct {
	Name string `json:"name"`
	// Host is the device's MagicDNS name (device.domain).
	Host string `json:"host"`
	// Known is false while no inventory of the device is at hand; the
	// tray keeps that device's locations as they are.
	Known  bool            `json:"known"`
	Shares []sysinfo.Share `json:"shares"`
}

// NetPlacesStatus is the reply of the network location routes.
type NetPlacesStatus struct {
	// Supported is true where the tray can make network locations
	// (Windows).
	Supported bool `json:"supported"`
	// On is the owner's switch; on by default.
	On bool `json:"on"`
	// Admin is true when this device holds the admin role: only admins
	// receive the other devices' reports.
	Admin bool `json:"admin"`
	// Ready is true while the tunnel runs with a signed document; the
	// tray changes nothing otherwise.
	Ready   bool             `json:"ready"`
	Devices []NetPlaceDevice `json:"devices"`
	// Shares counts the shares of Devices.
	Shares int `json:"shares"`
}

// NetPlacesRequest turns the switch.
type NetPlacesRequest struct {
	On bool `json:"on"`
}

// NetPlacesControl is implemented by the desktop service.
type NetPlacesControl interface {
	NetPlacesStatus() (NetPlacesStatus, error)
	SetNetPlaces(on bool) (NetPlacesStatus, error)
}

func (s *Server) netPlacesRoutes(mux *http.ServeMux) {
	control := func(w http.ResponseWriter) (NetPlacesControl, bool) {
		c, ok := s.app.(NetPlacesControl)
		if s.app == nil || !ok {
			writeError(w, http.StatusNotFound, "Bu işlem yalnızca OpenScale servisinde var.")
			return nil, false
		}
		return c, true
	}
	reply := func(w http.ResponseWriter, st NetPlacesStatus, err error) {
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if st.Devices == nil {
			st.Devices = []NetPlaceDevice{}
		}
		writeJSON(w, http.StatusOK, st)
	}
	get := func(w http.ResponseWriter, _ *http.Request) {
		if c, ok := control(w); ok {
			st, err := c.NetPlacesStatus()
			reply(w, st, err)
		}
	}
	set := func(w http.ResponseWriter, r *http.Request) {
		c, ok := control(w)
		if !ok {
			return
		}
		var req NetPlacesRequest
		if !decodeBody(w, r, &req) {
			return
		}
		st, err := c.SetNetPlaces(req.On)
		if err == nil {
			s.logger.Info("network locations switch changed", "on", req.On)
		}
		reply(w, st, err)
	}
	token := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if s.trayAuthorized(w, r) {
				h(w, r)
			}
		}
	}
	// The tray and the command line use the app token.
	mux.HandleFunc("GET /api/app/tray/netplaces", token(get))
	mux.HandleFunc("GET "+LocalAPIPrefix+"/netplaces", token(get))
	mux.HandleFunc("POST "+LocalAPIPrefix+"/netplaces", token(set))
	// The panel's switch.
	mux.HandleFunc("GET /api/app/netplaces", s.requireSession(s.requireApp(get)))
	mux.HandleFunc("POST /api/app/netplaces", s.requireSession(s.requireCSRF(s.requireWritable(s.requireApp(set)))))
}
