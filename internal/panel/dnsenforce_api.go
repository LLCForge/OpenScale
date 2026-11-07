package panel

import "net/http"

// DNS enforcement switch (#717, ADR-0224): the owner turns on the
// operating system rules that keep DNS inside the tunnel while an exit
// node is in use.

// DNSEnforceStatus is the reply of GET and POST /api/app/dns-enforce.
type DNSEnforceStatus struct {
	// Supported is false where the service has no applier.
	Supported bool `json:"supported"`
	// On is the owner's switch; Active says whether the rules hold now.
	On     bool   `json:"on"`
	Active bool   `json:"active"`
	Reason string `json:"reason,omitempty"`
	Error  string `json:"error,omitempty"`
	// DoHList is the owner's DoH file; DoHRanges how many address ranges
	// it gave the last applied rule set.
	DoHList   string `json:"dohList,omitempty"`
	DoHRanges int    `json:"dohRanges"`
}

// DNSEnforceRequest turns the switch.
type DNSEnforceRequest struct {
	On bool `json:"on"`
}

// DNSEnforceControl is implemented by the desktop service.
type DNSEnforceControl interface {
	DNSEnforceStatus() (DNSEnforceStatus, error)
	SetDNSEnforce(on bool) (DNSEnforceStatus, error)
}

func (s *Server) dnsEnforceRoutes(mux *http.ServeMux) {
	read := func(h http.HandlerFunc) http.HandlerFunc { return s.requireSession(s.requireApp(h)) }
	write := func(h http.HandlerFunc) http.HandlerFunc {
		return s.requireSession(s.requireCSRF(s.requireWritable(s.requireApp(h))))
	}
	control := func(w http.ResponseWriter) (DNSEnforceControl, bool) {
		c, ok := s.app.(DNSEnforceControl)
		if !ok {
			writeError(w, http.StatusNotFound, "Bu işlem yalnızca OpenScale servisinde var.")
		}
		return c, ok
	}
	reply := func(w http.ResponseWriter, st DNSEnforceStatus, err error) {
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, st)
	}
	mux.HandleFunc("GET /api/app/dns-enforce", read(func(w http.ResponseWriter, _ *http.Request) {
		if c, ok := control(w); ok {
			st, err := c.DNSEnforceStatus()
			reply(w, st, err)
		}
	}))
	mux.HandleFunc("POST /api/app/dns-enforce", write(func(w http.ResponseWriter, r *http.Request) {
		c, ok := control(w)
		if !ok {
			return
		}
		var req DNSEnforceRequest
		if !decodeBody(w, r, &req) {
			return
		}
		st, err := c.SetDNSEnforce(req.On)
		reply(w, st, err)
	}))
}
