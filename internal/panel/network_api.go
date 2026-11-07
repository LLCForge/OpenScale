package panel

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/trust"
)

type coordinatorView struct {
	Endpoint     string `json:"endpoint"`
	WireGuardKey string `json:"wireguardKey"`
	Fingerprint  string `json:"fingerprint"`
	IPv4         string `json:"ipv4"`
	IPv6         string `json:"ipv6"`
}

type networkResponse struct {
	NetworkID       string           `json:"networkId"`
	Version         uint64           `json:"version"`
	DNSDomain       string           `json:"dnsDomain"`
	IPv4Prefix      string           `json:"ipv4Prefix"`
	IPv6Prefix      string           `json:"ipv6Prefix"`
	RootFingerprint string           `json:"rootFingerprint"`
	DNSResolver     string           `json:"dnsResolver"`
	Coordinator     *coordinatorView `json:"coordinator"`
	// Bundle lets new members pin the root key and fetch the document. It
	// holds only public data; its integrity comes from the root fingerprint
	// the owner types on the new device.
	Bundle string `json:"bundle"`
	// DisplayName is the network's name (F-160), "" when not set.
	DisplayName string `json:"displayName"`
	// DNS is the network-wide DNS section (ADR-0024), nil when absent.
	DNS *dnsView `json:"dns"`
	// DNSWarnings lists resolvers other devices cannot reach on port 53.
	DNSWarnings []string `json:"dnsWarnings"`
	// Resolvers are the devices whose tunnel addresses may be chosen as
	// resolvers.
	Resolvers []resolverChoice `json:"resolvers"`
	// ExitUsers is who may use exit nodes (ADR-0021).
	ExitUsers exitUsersView `json:"exitUsers"`
	// MagicDNS summarizes the document's magic_dns section (search
	// domains, extra records, device subdomains) for display; it is
	// changed with the "openscale network dns" commands.
	MagicDNS magicDNSView `json:"magicDns"`
}

type magicDNSView struct {
	Search           []string `json:"search"`
	Records          int      `json:"records"`
	DeviceSubdomains bool     `json:"deviceSubdomains"`
}

func magicDNSSummary(m *trust.MagicDNSSettings) magicDNSView {
	v := magicDNSView{Search: []string{}}
	if m == nil {
		return v
	}
	v.Search = append(v.Search, m.Search...)
	v.Records = len(m.Records)
	v.DeviceSubdomains = m.DeviceSubdomains
	return v
}

type resolverChoice struct {
	Name string `json:"name"`
	IPv4 string `json:"ipv4"`
	IPv6 string `json:"ipv6"`
}

type setCoordinatorRequest struct {
	signRequest
	Endpoint     string `json:"endpoint"`
	WireGuardKey string `json:"wireguardKey"`
	Fingerprint  string `json:"fingerprint"`
}

func (s *Server) handleNetwork(w http.ResponseWriter, r *http.Request) {
	doc, ok := s.currentDocument(w)
	if !ok {
		return
	}
	bundle, err := s.network().JoinBundle()
	if err != nil {
		s.fail(w, err)
		return
	}
	resp := networkResponse{
		NetworkID:       doc.NetworkID,
		Version:         doc.Version,
		DNSDomain:       doc.DNSDomain,
		IPv4Prefix:      doc.IPv4Prefix.String(),
		IPv6Prefix:      doc.IPv6Prefix.String(),
		RootFingerprint: s.network().RootFingerprint(),
		DNSResolver:     doc.DNSResolverIPv4().String(),
		Bundle:          bundle,
		DisplayName:     doc.DisplayName,
		DNS:             dnsSettingsView(doc.DNS),
		DNSWarnings:     dnsWarnings(doc),
		Resolvers:       make([]resolverChoice, 0, len(doc.Devices)),
		ExitUsers:       exitUsersView{Users: []string{}},
		MagicDNS:        magicDNSSummary(doc.MagicDNS),
	}
	for _, d := range doc.Devices {
		resp.Resolvers = append(resp.Resolvers, resolverChoice{Name: d.Name, IPv4: d.IPv4.String(), IPv6: d.IPv6.String()})
	}
	if users, set := doc.ExitUsersList(); set {
		resp.ExitUsers = exitUsersView{Restricted: true, Users: append([]string{}, users...)}
	}
	if c := doc.Coordinator; c != nil {
		resp.Coordinator = &coordinatorView{
			Endpoint:     c.Endpoint,
			WireGuardKey: c.WireGuardKey.String(),
			Fingerprint:  trust.CoordinatorFingerprint(c.WireGuardKey),
			IPv4:         c.IPv4.String(),
			IPv6:         c.IPv6.String(),
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleSetCoordinator pins the coordinator after the owner typed the
// fingerprint shown by `openscale coordinator keygen` on the server.
func (s *Server) handleSetCoordinator(w http.ResponseWriter, r *http.Request) {
	var req setCoordinatorRequest
	if !decodeBody(w, r, &req) {
		return
	}
	key, err := trust.ParseKey(strings.TrimSpace(req.WireGuardKey))
	if err != nil {
		writeError(w, http.StatusBadRequest, "WireGuard anahtarı geçersiz; koordinatördeki 'openscale coordinator keygen' çıktısını kullanın.")
		return
	}
	got := []byte(trust.NormalizeFingerprint(req.Fingerprint))
	want := []byte(trust.NormalizeFingerprint(trust.CoordinatorFingerprint(key)))
	if len(got) == 0 || subtle.ConstantTimeCompare(got, want) != 1 {
		s.fail(w, admin.ErrFingerprintMismatch)
		return
	}
	endpoint := strings.TrimSpace(req.Endpoint)
	s.change(w, req.signRequest, func(doc *trust.Document) error {
		return doc.SetCoordinator(endpoint, key)
	})
}
