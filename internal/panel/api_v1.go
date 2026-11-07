package panel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/trust"
)

// Versioned, read-only management API (ADR-0107, F-176). Described in
// docs/api/openapi.yaml. It reads the owner's signed document; there is no
// write endpoint, and the root key's signature is never authorized
// through it. Callers sign in with a panel session or a read-only API key.

const (
	// APIv1Prefix is the versioned API's path prefix.
	APIv1Prefix = "/api/v1"
	// APISchema is the version of the documents below.
	APISchema = 1

	apiDefaultLimit = 50
	apiMaxLimit     = 100
	maxRequestID    = 64
	maxAPIName      = 253
)

// requestIDHeader carries the request id both ways.
const requestIDHeader = "X-Request-ID"

type apiCtxKey struct{}

// APIError is an error answer of the v1 API.
type APIError struct {
	Error     string `json:"error"`
	RequestID string `json:"request_id"`
}

// APIDevice is one device of the network.
type APIDevice struct {
	Name        string    `json:"name"`
	FQDN        string    `json:"fqdn"`
	IPv4        string    `json:"ipv4"`
	IPv6        string    `json:"ipv6"`
	Tags        []string  `json:"tags"`
	Groups      []string  `json:"groups"`
	Roles       []string  `json:"roles"`
	AddedAt     time.Time `json:"added_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Expired     bool      `json:"expired"`
	ExitNode    bool      `json:"exit_node"`
	Admin       bool      `json:"admin"`
	Ephemeral   bool      `json:"ephemeral"`
	Fingerprint string    `json:"fingerprint"`
}

// APIRule is one rule in document order; Index starts at 1 as in the
// command line.
type APIRule struct {
	Index           int      `json:"index"`
	Action          string   `json:"action"`
	From            []string `json:"from"`
	To              []string `json:"to"`
	Protocol        string   `json:"protocol,omitempty"`
	Ports           []string `json:"ports,omitempty"`
	Service         string   `json:"service,omitempty"`
	Disabled        bool     `json:"disabled"`
	Description     string   `json:"description,omitempty"`
	Users           []string `json:"users,omitempty"`
	AllowRoot       bool     `json:"allow_root,omitempty"`
	AllowForward    bool     `json:"allow_forward,omitempty"`
	Via             []string `json:"via,omitempty"`
	AllowControl    bool     `json:"allow_control,omitempty"`
	AllowUnattended bool     `json:"allow_unattended,omitempty"`
}

// APINetwork summarizes the signed document.
type APINetwork struct {
	Schema      int       `json:"schema"`
	NetworkID   string    `json:"network_id"`
	DisplayName string    `json:"display_name"`
	Version     uint64    `json:"version"`
	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	DNSDomain   string    `json:"dns_domain"`
	IPv4Prefix  string    `json:"ipv4_prefix"`
	IPv6Prefix  string    `json:"ipv6_prefix"`
	DeviceCount int       `json:"device_count"`
	RuleCount   int       `json:"rule_count"`
	GroupCount  int       `json:"group_count"`
}

// APIPage is a page of a list.
type APIPage[T any] struct {
	Schema     int    `json:"schema"`
	Items      []T    `json:"items"`
	Total      int    `json:"total"`
	NextCursor string `json:"next_cursor,omitempty"`
}

// APIDeviceReply is one device.
type APIDeviceReply struct {
	Schema int       `json:"schema"`
	Device APIDevice `json:"device"`
}

// APIWhoisReply answers a tunnel address lookup.
type APIWhoisReply struct {
	Schema int       `json:"schema"`
	IP     string    `json:"ip"`
	Device APIDevice `json:"device"`
}

// p17Routes adds the v1 API.
func (s *Server) p17Routes(mux *http.ServeMux) {
	read := func(h http.HandlerFunc) http.HandlerFunc {
		return s.withRequestID(s.requireReader(s.requireNetwork(h)))
	}
	mux.HandleFunc("GET "+APIv1Prefix+"/network", read(s.v1Network))
	mux.HandleFunc("GET "+APIv1Prefix+"/devices", read(s.v1Devices))
	mux.HandleFunc("GET "+APIv1Prefix+"/devices/{name}", read(s.v1Device))
	mux.HandleFunc("GET "+APIv1Prefix+"/devices/{name}/services", read(s.v1DeviceServices))
	mux.HandleFunc("GET "+APIv1Prefix+"/rules", read(s.v1Rules))
	mux.HandleFunc("GET "+APIv1Prefix+"/whois", read(s.v1Whois))
	mux.HandleFunc(APIv1Prefix+"/", s.withRequestID(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			v1Error(w, r, http.StatusMethodNotAllowed, "API salt okunurdur; değişiklikler yönetici bilgisayarda, kök anahtarla yapılır.")
			return
		}
		v1Error(w, r, http.StatusNotFound, "Bulunamadı.")
	}))
}

// validRequestID accepts short ids of letters, digits, '.', '_' and '-'.
func validRequestID(id string) bool {
	if id == "" || len(id) > maxRequestID {
		return false
	}
	for _, c := range id {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

// withRequestID echoes a valid X-Request-ID or makes one up.
func (s *Server) withRequestID(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(requestIDHeader)
		if !validRequestID(id) {
			var b [8]byte
			if _, err := io.ReadFull(s.random, b[:]); err != nil {
				writeError(w, http.StatusInternalServerError, "İstek kimliği üretilemedi.")
				return
			}
			id = hex.EncodeToString(b[:])
		}
		w.Header().Set(requestIDHeader, id)
		ctx := r.Context()
		next(w, r.WithContext(context.WithValue(ctx, apiCtxKey{}, id)))
	}
}

func requestIDOf(r *http.Request) string {
	id, _ := r.Context().Value(apiCtxKey{}).(string)
	return id
}

func v1Error(w http.ResponseWriter, r *http.Request, status int, msg string) {
	writeJSON(w, status, APIError{Error: msg, RequestID: requestIDOf(r)})
}

// requireReader accepts a panel session or a read-only API key. A key is
// refused from a browser (Origin set) and, over the tunnel, unless it was
// created for remote use.
func (s *Server) requireReader(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			s.requireSession(next)(w, r)
			return
		}
		secret, ok := strings.CutPrefix(auth, "Bearer ")
		n := s.network()
		if !ok || n == nil || r.Header.Get("Origin") != "" {
			v1Error(w, r, http.StatusUnauthorized, "İzin verilmedi.")
			return
		}
		key, found := lookupAPIKey(n.Dir(), secret)
		if !found {
			s.logger.Warn("API request with an unknown key")
			v1Error(w, r, http.StatusUnauthorized, "İzin verilmedi.")
			return
		}
		if dev, remote := remoteDevice(r); remote && !key.Remote {
			s.logger.Warn("local-only API key used over the tunnel", "key", key.ID, "device", dev)
			v1Error(w, r, http.StatusForbidden, "Bu API anahtarı yalnızca yönetici bilgisayarda geçerli.")
			return
		}
		next(w, r)
	}
}

// apiDocument loads the current document for a v1 handler.
func (s *Server) apiDocument(w http.ResponseWriter, r *http.Request) (*trust.Document, bool) {
	n := s.network()
	if err := n.Reload(); err != nil {
		s.logger.Warn("v1 API document load failed", "error", err.Error())
		v1Error(w, r, http.StatusInternalServerError, "Ağ belgesi okunamadı.")
		return nil, false
	}
	doc, err := n.Document()
	if err != nil {
		s.logger.Warn("v1 API document load failed", "error", err.Error())
		v1Error(w, r, http.StatusInternalServerError, "Ağ belgesi okunamadı.")
		return nil, false
	}
	return doc, true
}

// pageBounds reads limit and cursor for a list of total items.
func pageBounds(r *http.Request, total int) (start, end int, ok bool) {
	limit := apiDefaultLimit
	q := r.URL.Query()
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > apiMaxLimit {
			return 0, 0, false
		}
		limit = n
	}
	if v := q.Get("cursor"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > total || len(v) > 10 {
			return 0, 0, false
		}
		start = n
	}
	end = min(start+limit, total)
	return start, end, true
}

func nextCursor(end, total int) string {
	if end >= total {
		return ""
	}
	return strconv.Itoa(end)
}

// apiFingerprint is a short, stable label of a public key (the same as
// "openscale whois").
func apiFingerprint(k trust.Key) string {
	sum := sha256.Sum256(k[:])
	return hex.EncodeToString(sum[:6])
}

func apiDevice(doc *trust.Document, d trust.Device, now time.Time) APIDevice {
	out := APIDevice{
		Name: d.Name, FQDN: d.Name + "." + doc.DNSDomain, Tags: nonNil(d.Tags), Groups: []string{}, Roles: []string{},
		AddedAt: d.AddedAt, ExpiresAt: d.ExpiresAt, Expired: !now.Before(d.ExpiresAt),
		ExitNode: d.HasRole(trust.RoleExitNode), Admin: d.HasRole(trust.RoleAdmin), Ephemeral: d.Ephemeral,
		Fingerprint: apiFingerprint(d.WireGuardKey),
	}
	if d.IPv4.IsValid() {
		out.IPv4 = d.IPv4.String()
	}
	if d.IPv6.IsValid() {
		out.IPv6 = d.IPv6.String()
	}
	for _, r := range d.Roles {
		out.Roles = append(out.Roles, string(r))
	}
	for _, g := range doc.Groups {
		if slices.Contains(g.Members, d.Name) || slices.ContainsFunc(d.Tags, func(t string) bool { return slices.Contains(g.Members, "tag:"+t) }) {
			out.Groups = append(out.Groups, g.Name)
		}
	}
	return out
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return slices.Clone(s)
}

func (s *Server) v1Network(w http.ResponseWriter, r *http.Request) {
	doc, ok := s.apiDocument(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, APINetwork{
		Schema: APISchema, NetworkID: doc.NetworkID, DisplayName: doc.DisplayName, Version: doc.Version,
		IssuedAt: doc.IssuedAt, ExpiresAt: doc.ExpiresAt, DNSDomain: doc.DNSDomain,
		IPv4Prefix: doc.IPv4Prefix.String(), IPv6Prefix: doc.IPv6Prefix.String(),
		DeviceCount: len(doc.Devices), RuleCount: len(doc.Rules), GroupCount: len(doc.Groups),
	})
}

func (s *Server) v1Devices(w http.ResponseWriter, r *http.Request) {
	doc, ok := s.apiDocument(w, r)
	if !ok {
		return
	}
	start, end, ok := pageBounds(r, len(doc.Devices))
	if !ok {
		v1Error(w, r, http.StatusBadRequest, "limit 1-100, cursor önceki yanıtın next_cursor değeri olmalı.")
		return
	}
	now := s.now()
	page := APIPage[APIDevice]{Schema: APISchema, Items: []APIDevice{}, Total: len(doc.Devices), NextCursor: nextCursor(end, len(doc.Devices))}
	for _, d := range doc.Devices[start:end] {
		page.Items = append(page.Items, apiDevice(doc, d, now))
	}
	writeJSON(w, http.StatusOK, page)
}

// deviceFromPath resolves {name}.
func (s *Server) deviceFromPath(w http.ResponseWriter, r *http.Request) (*trust.Document, trust.Device, bool) {
	name := r.PathValue("name")
	if name == "" || len(name) > maxAPIName || !validDiagQuery(name) {
		v1Error(w, r, http.StatusBadRequest, "Cihaz adı geçersiz.")
		return nil, trust.Device{}, false
	}
	doc, ok := s.apiDocument(w, r)
	if !ok {
		return nil, trust.Device{}, false
	}
	d, found := doc.DeviceByName(name)
	if !found {
		v1Error(w, r, http.StatusNotFound, "Cihaz bulunamadı.")
		return nil, trust.Device{}, false
	}
	return doc, d, true
}

func (s *Server) v1Device(w http.ResponseWriter, r *http.Request) {
	doc, d, ok := s.deviceFromPath(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, APIDeviceReply{Schema: APISchema, Device: apiDevice(doc, d, s.now())})
}

func apiRule(i int, rl trust.Rule) APIRule {
	action := string(rl.Action)
	if action == "" {
		action = string(trust.RuleAllow)
	}
	return APIRule{
		Index: i + 1, Action: action, From: nonNil(rl.From), To: nonNil(rl.To), Protocol: string(rl.Protocol),
		Ports: rl.Ports, Service: string(rl.Service), Disabled: rl.Disabled, Description: rl.Description,
		Users: rl.Users, AllowRoot: rl.AllowRoot, AllowForward: rl.AllowForward, Via: rl.Via,
		AllowControl: rl.AllowControl, AllowUnattended: rl.AllowUnattended,
	}
}

func (s *Server) v1Rules(w http.ResponseWriter, r *http.Request) {
	doc, ok := s.apiDocument(w, r)
	if !ok {
		return
	}
	start, end, ok := pageBounds(r, len(doc.Rules))
	if !ok {
		v1Error(w, r, http.StatusBadRequest, "limit 1-100, cursor önceki yanıtın next_cursor değeri olmalı.")
		return
	}
	page := APIPage[APIRule]{Schema: APISchema, Items: []APIRule{}, Total: len(doc.Rules), NextCursor: nextCursor(end, len(doc.Rules))}
	for i := start; i < end; i++ {
		page.Items = append(page.Items, apiRule(i, doc.Rules[i]))
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) v1Whois(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimSpace(r.URL.Query().Get("ip"))
	ip, err := netip.ParseAddr(raw)
	if err != nil || len(raw) > 64 || ip.Zone() != "" {
		v1Error(w, r, http.StatusBadRequest, "ip bir IPv4 veya IPv6 adresi olmalı.")
		return
	}
	doc, ok := s.apiDocument(w, r)
	if !ok {
		return
	}
	d, found := doc.DeviceByAddr(ip.Unmap())
	if !found {
		v1Error(w, r, http.StatusNotFound, "Bu adres ağdaki bir cihazın tünel adresi değil.")
		return
	}
	writeJSON(w, http.StatusOK, APIWhoisReply{Schema: APISchema, IP: ip.Unmap().String(), Device: apiDevice(doc, d, s.now())})
}
