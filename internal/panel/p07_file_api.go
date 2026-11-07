package panel

import (
	"context"
	"net/http"
	"time"
)

// Time-limited file links (#460), antivirus scan of received files
// (#458) and the subnet device inventory (#442).

// FileLinkView is one live link (the secret is never listed).
type FileLinkView struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Path         string    `json:"path"`
	Device       string    `json:"device"`
	Size         int64     `json:"size"`
	Created      time.Time `json:"created"`
	Expires      time.Time `json:"expires"`
	MaxDownloads int       `json:"max_downloads"`
	Downloads    int       `json:"downloads"`
}

// FileLinksStatus is GET /api/app/files/links.
type FileLinksStatus struct {
	Schema int            `json:"schema"`
	Links  []FileLinkView `json:"links"`
	// Served is true when this device runs the serve port (a signed serve
	// rule names it); without it links cannot be downloaded.
	Served bool   `json:"served"`
	Note   string `json:"note,omitempty"`
}

// FileLinkRequest creates a link.
type FileLinkRequest struct {
	Path      string `json:"path"`
	Device    string `json:"device"`
	Hours     int    `json:"hours"`
	Downloads int    `json:"downloads"`
}

// FileLinkCreated is the answer to a new link; URL holds the secret and
// is shown only now.
type FileLinkCreated struct {
	Schema int          `json:"schema"`
	Link   FileLinkView `json:"link"`
	URL    string       `json:"url"`
}

// FileScanView is the scan result of one inbox file.
type FileScanView struct {
	Name    string    `json:"name"`
	Scanner string    `json:"scanner"`
	Verdict string    `json:"verdict"`
	Detail  string    `json:"detail,omitempty"`
	At      time.Time `json:"at"`
}

// FileScanStatus is GET /api/app/files/scan.
type FileScanStatus struct {
	Schema    int            `json:"schema"`
	Available bool           `json:"available"`
	Scanner   string         `json:"scanner,omitempty"`
	Enabled   bool           `json:"enabled"`
	CloudNote string         `json:"cloud_note,omitempty"`
	Results   []FileScanView `json:"results"`
}

// FileScanRequest turns scanning on or off.
type FileScanRequest struct {
	Enabled bool `json:"enabled"`
}

// FileNameRequest names an inbox file.
type FileNameRequest struct {
	Name string `json:"name"`
}

// SubnetDevice is one device seen on a subnet this device routes.
type SubnetDevice struct {
	Addr      string `json:"addr"`
	MAC       string `json:"mac"`
	Vendor    string `json:"vendor,omitempty"`
	RandomMAC bool   `json:"random_mac,omitempty"`
	Prefix    string `json:"prefix"`
	// Rule is a CIDR for a rule that names only this device.
	Rule string `json:"rule"`
}

// SubnetInventory is GET /api/app/routes/inventory.
type SubnetInventory struct {
	Schema  int            `json:"schema"`
	Routed  []string       `json:"routed"`
	Devices []SubnetDevice `json:"devices"`
	Note    string         `json:"note,omitempty"`
}

// ServeSuggestion is a container asking to be published (#441).
type ServeSuggestion struct {
	Container string `json:"container"`
	Image     string `json:"image,omitempty"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	Target    string `json:"target,omitempty"`
	Problem   string `json:"problem,omitempty"`
	// Published is true when serve.json already has a service of Name.
	Published bool `json:"published"`
}

// ServeSuggestions is GET /api/app/serve/suggestions.
type ServeSuggestions struct {
	Schema      int               `json:"schema"`
	Available   bool              `json:"available"`
	Socket      string            `json:"socket,omitempty"`
	Error       string            `json:"error,omitempty"`
	Suggestions []ServeSuggestion `json:"suggestions"`
}

// P07FileControl is implemented by the service.
type P07FileControl interface {
	FileLinks() (FileLinksStatus, error)
	CreateFileLink(req FileLinkRequest) (FileLinkCreated, error)
	RevokeFileLink(id string) (FileLinksStatus, error)
	FileScanStatus() (FileScanStatus, error)
	SetFileScan(req FileScanRequest) (FileScanStatus, error)
	ScanInboxFile(ctx context.Context, name string) (FileScanStatus, error)
	SubnetInventory() (SubnetInventory, error)
	ServeSuggestions(ctx context.Context) (ServeSuggestions, error)
}

const fileScanTimeout = 6 * time.Minute

func (s *Server) p07FileRoutes(mux *http.ServeMux, read, write func(http.HandlerFunc) http.HandlerFunc) {
	ctl := func(h func(http.ResponseWriter, *http.Request, P07FileControl)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			c, ok := s.app.(P07FileControl)
			if !ok {
				writeError(w, http.StatusNotFound, "Bu işlem yalnızca OpenScale servisinde var.")
				return
			}
			h(w, r, c)
		}
	}
	reply := func(w http.ResponseWriter, v any, err error) {
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, v)
	}
	mux.HandleFunc("GET /api/app/files/links", read(ctl(func(w http.ResponseWriter, _ *http.Request, c P07FileControl) {
		st, err := c.FileLinks()
		st.Schema = P07Schema
		reply(w, st, err)
	})))
	mux.HandleFunc("POST /api/app/files/links", write(ctl(func(w http.ResponseWriter, r *http.Request, c P07FileControl) {
		var req FileLinkRequest
		if !decodeBody(w, r, &req) {
			return
		}
		if len(req.Path) == 0 || len(req.Path) > 4096 || len(req.Device) > 63 {
			writeError(w, http.StatusBadRequest, "Dosya yolu veya cihaz adı geçersiz.")
			return
		}
		res, err := c.CreateFileLink(req)
		res.Schema = P07Schema
		reply(w, res, err)
	})))
	mux.HandleFunc("POST /api/app/files/links/revoke", write(ctl(func(w http.ResponseWriter, r *http.Request, c P07FileControl) {
		var req SyncFolderRequest
		if !decodeBody(w, r, &req) {
			return
		}
		if len(req.ID) == 0 || len(req.ID) > 32 {
			writeError(w, http.StatusBadRequest, "Bağlantı kimliği geçersiz.")
			return
		}
		st, err := c.RevokeFileLink(req.ID)
		st.Schema = P07Schema
		reply(w, st, err)
	})))
	mux.HandleFunc("GET /api/app/files/scan", read(ctl(func(w http.ResponseWriter, _ *http.Request, c P07FileControl) {
		st, err := c.FileScanStatus()
		st.Schema = P07Schema
		reply(w, st, err)
	})))
	mux.HandleFunc("POST /api/app/files/scan", write(ctl(func(w http.ResponseWriter, r *http.Request, c P07FileControl) {
		var req FileScanRequest
		if !decodeBody(w, r, &req) {
			return
		}
		st, err := c.SetFileScan(req)
		st.Schema = P07Schema
		reply(w, st, err)
	})))
	mux.HandleFunc("POST /api/app/files/scan/run", write(ctl(func(w http.ResponseWriter, r *http.Request, c P07FileControl) {
		var req FileNameRequest
		if !decodeBody(w, r, &req) {
			return
		}
		if len(req.Name) == 0 || len(req.Name) > 255 {
			writeError(w, http.StatusBadRequest, "Dosya adı geçersiz.")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), fileScanTimeout)
		defer cancel()
		st, err := c.ScanInboxFile(ctx, req.Name)
		st.Schema = P07Schema
		reply(w, st, err)
	})))
	mux.HandleFunc("GET /api/app/serve/suggestions", read(ctl(func(w http.ResponseWriter, r *http.Request, c P07FileControl) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		st, err := c.ServeSuggestions(ctx)
		st.Schema = P07Schema
		if st.Suggestions == nil {
			st.Suggestions = []ServeSuggestion{}
		}
		reply(w, st, err)
	})))
	mux.HandleFunc("GET /api/app/routes/inventory", read(ctl(func(w http.ResponseWriter, _ *http.Request, c P07FileControl) {
		inv, err := c.SubnetInventory()
		inv.Schema = P07Schema
		reply(w, inv, err)
	})))
}
