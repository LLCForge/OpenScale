package panel

import (
	"context"
	"net/http"
	"net/netip"
	"time"
)

// Dynamic DNS check (#448) and updater (#449), ADR-0160.

// DDNSCheckView is the last consistency check of the coordinator's name.
type DDNSCheckView struct {
	At       time.Time    `json:"at"`
	Host     string       `json:"host"`
	Resolved []netip.Addr `json:"resolved,omitempty"`
	Observed string       `json:"observed,omitempty"`
	// Status is ok, stale, unresolved or unknown.
	Status  string `json:"status"`
	Message string `json:"message"`
}

// DDNSUpdaterView is the RFC 2136 updater's settings and last result.
// The TSIG secret is never returned; KeySet says whether one is stored.
type DDNSUpdaterView struct {
	Enabled   bool   `json:"enabled"`
	Server    string `json:"server,omitempty"`
	Zone      string `json:"zone,omitempty"`
	Name      string `json:"name,omitempty"`
	TTL       uint32 `json:"ttl,omitempty"`
	KeyName   string `json:"key_name,omitempty"`
	Algorithm string `json:"algorithm,omitempty"`
	KeySet    bool   `json:"key_set"`
	// Published is the address last accepted by the server.
	Published   string     `json:"published,omitempty"`
	PublishedAt *time.Time `json:"published_at,omitempty"`
	LastTry     *time.Time `json:"last_try,omitempty"`
	LastError   string     `json:"last_error,omitempty"`
	// Current is the public address the coordinator reports for this
	// device, the one that would be published.
	Current string `json:"current,omitempty"`
}

// DDNSStatus is GET /api/app/ddns.
type DDNSStatus struct {
	Schema  int             `json:"schema"`
	Check   *DDNSCheckView  `json:"check,omitempty"`
	Updater DDNSUpdaterView `json:"updater"`
}

// DDNSConfigRequest changes the updater. Secret is the base64 TSIG secret;
// nil keeps the stored one, an empty string removes it.
type DDNSConfigRequest struct {
	Enabled   bool    `json:"enabled"`
	Server    string  `json:"server"`
	Zone      string  `json:"zone"`
	Name      string  `json:"name"`
	TTL       uint32  `json:"ttl,omitempty"`
	KeyName   string  `json:"key_name"`
	Algorithm string  `json:"algorithm,omitempty"`
	Secret    *string `json:"secret,omitempty"`
}

// DDNSControl is implemented by the service.
type DDNSControl interface {
	DDNSStatus() (DDNSStatus, error)
	SetDDNS(req DDNSConfigRequest) (DDNSStatus, error)
	DDNSCheckNow(ctx context.Context) (DDNSStatus, error)
	DDNSUpdateNow(ctx context.Context) (DDNSStatus, error)
}

const ddnsTimeout = 30 * time.Second

func (s *Server) p07NetRoutes(mux *http.ServeMux, read, write func(http.HandlerFunc) http.HandlerFunc) {
	ddns := func(h func(http.ResponseWriter, *http.Request, DDNSControl)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			c, ok := s.app.(DDNSControl)
			if !ok {
				writeError(w, http.StatusNotFound, "Bu işlem yalnızca OpenScale servisinde var.")
				return
			}
			h(w, r, c)
		}
	}
	mux.HandleFunc("GET /api/app/ddns", read(ddns(func(w http.ResponseWriter, _ *http.Request, c DDNSControl) {
		ddnsReply(w, c.DDNSStatus)
	})))
	mux.HandleFunc("POST /api/app/ddns", write(ddns(func(w http.ResponseWriter, r *http.Request, c DDNSControl) {
		var req DDNSConfigRequest
		if !decodeBody(w, r, &req) {
			return
		}
		if len(req.Server) > 64 || len(req.Zone) > 255 || len(req.Name) > 255 || len(req.KeyName) > 255 || len(req.Algorithm) > 32 ||
			(req.Secret != nil && len(*req.Secret) > 256) {
			writeError(w, http.StatusBadRequest, "Alanlardan biri çok uzun.")
			return
		}
		ddnsReply(w, func() (DDNSStatus, error) { return c.SetDDNS(req) })
	})))
	mux.HandleFunc("POST /api/app/ddns/check", write(ddns(func(w http.ResponseWriter, r *http.Request, c DDNSControl) {
		ctx, cancel := context.WithTimeout(r.Context(), ddnsTimeout)
		defer cancel()
		ddnsReply(w, func() (DDNSStatus, error) { return c.DDNSCheckNow(ctx) })
	})))
	mux.HandleFunc("POST /api/app/ddns/update", write(ddns(func(w http.ResponseWriter, r *http.Request, c DDNSControl) {
		ctx, cancel := context.WithTimeout(r.Context(), ddnsTimeout)
		defer cancel()
		ddnsReply(w, func() (DDNSStatus, error) { return c.DDNSUpdateNow(ctx) })
	})))
	s.p07FileRoutes(mux, read, write)
}

func ddnsReply(w http.ResponseWriter, fn func() (DDNSStatus, error)) {
	st, err := fn()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	st.Schema = P07Schema
	writeJSON(w, http.StatusOK, st)
}
