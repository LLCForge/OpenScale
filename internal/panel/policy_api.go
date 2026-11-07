package panel

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/trust"
)

// Endpoints for the edits added by ADR-0019, ADR-0020, ADR-0021, ADR-0024
// and F-160. Every one goes through the shared dry-run and signing path
// (Server.change), so the owner sees the difference before typing the root
// key passphrase, and every one is refused while the panel is read-only.

// Input bounds checked before anything reaches the trust package. The
// trust package validates again; these keep oversized requests cheap.
const (
	maxNameLen       = 63
	maxReferenceLen  = len(trust.GroupPrefix) + maxNameLen
	maxTagsPerDevice = trust.MaxTags
	maxGroupMembers  = 256
	maxRuleEntries   = 64
	maxExitUsers     = 64
	maxDomainLen     = 253
	maxRotationLine  = 4096
	maxResolverText  = 45
)

// --- device edits (ADR-0019, ADR-0021) ---

type extendDeviceRequest struct {
	signRequest
	Name         string `json:"name"`
	LifetimeDays int    `json:"lifetimeDays"`
}

func (s *Server) handleExtendDevice(w http.ResponseWriter, r *http.Request) {
	var req extendDeviceRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if !validDeviceName(req.Name) {
		writeError(w, http.StatusBadRequest, "Cihaz adı geçersiz.")
		return
	}
	if req.LifetimeDays < 1 || req.LifetimeDays > maxDeviceLifeDay {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Üyelik süresi 1 ile %d gün arasında olmalı.", maxDeviceLifeDay))
		return
	}
	now := s.now()
	life := time.Duration(req.LifetimeDays) * 24 * time.Hour
	s.change(w, req.signRequest, func(doc *trust.Document) error {
		_, err := doc.ExtendDevice(req.Name, now, life)
		return err
	})
}

type deviceNameRequest struct {
	signRequest
	Name string `json:"name"`
}

func (s *Server) handleExpireDevice(w http.ResponseWriter, r *http.Request) {
	var req deviceNameRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if !validDeviceName(req.Name) {
		writeError(w, http.StatusBadRequest, "Cihaz adı geçersiz.")
		return
	}
	now := s.now()
	s.change(w, req.signRequest, func(doc *trust.Document) error {
		_, err := doc.ExpireDevice(req.Name, now)
		return err
	})
}

type renameDeviceRequest struct {
	signRequest
	Name    string `json:"name"`
	NewName string `json:"newName"`
}

func (s *Server) handleRenameDevice(w http.ResponseWriter, r *http.Request) {
	var req renameDeviceRequest
	if !decodeBody(w, r, &req) {
		return
	}
	newName := strings.TrimSpace(req.NewName)
	if !validDeviceName(req.Name) || newName == "" || len(newName) > maxNameLen {
		writeError(w, http.StatusBadRequest, admin.Describe(trust.ErrInvalidName))
		return
	}
	s.change(w, req.signRequest, func(doc *trust.Document) error {
		return doc.RenameDevice(req.Name, newName)
	})
}

type deviceTagsRequest struct {
	signRequest
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

func (s *Server) handleDeviceTags(w http.ResponseWriter, r *http.Request) {
	var req deviceTagsRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if !validDeviceName(req.Name) {
		writeError(w, http.StatusBadRequest, "Cihaz adı geçersiz.")
		return
	}
	tags, ok := cleanList(req.Tags, maxTagsPerDevice, maxReferenceLen)
	if !ok {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("En fazla %d etiket verilebilir; her biri küçük harf, rakam ve tire içerir.", maxTagsPerDevice))
		return
	}
	s.change(w, req.signRequest, func(doc *trust.Document) error {
		return doc.SetDeviceTags(req.Name, tags)
	})
}

// --- key rotation (ADR-0020) ---

type rotationInspectRequest struct {
	Request string `json:"request"`
}

type rotationInspectResponse struct {
	DeviceName string    `json:"deviceName"`
	DeviceID   string    `json:"deviceId"`
	CreatedAt  time.Time `json:"createdAt"`
}

// handleInspectRotation checks a rotation request against the current
// document. Like device enrollment, the fingerprint is not returned: the
// owner must read it from the device's own screen.
func (s *Server) handleInspectRotation(w http.ResponseWriter, r *http.Request) {
	var req rotationInspectRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.Request == "" || len(req.Request) > maxRotationLine {
		writeError(w, http.StatusBadRequest, "Anahtar yenileme isteği geçersiz.")
		return
	}
	if err := s.network().Reload(); err != nil {
		s.fail(w, err)
		return
	}
	pending, err := s.network().InspectKeyRotation(req.Request, s.now())
	if err != nil {
		s.fail(w, rotationError(err))
		return
	}
	writeJSON(w, http.StatusOK, rotationInspectResponse{
		DeviceName: pending.Device.Name,
		DeviceID:   pending.Device.ID[:8],
		CreatedAt:  pending.Request.CreatedAt,
	})
}

type applyRotationRequest struct {
	signRequest
	Request     string `json:"request"`
	Fingerprint string `json:"fingerprint"`
}

// handleApplyRotation installs a device's new keys. The request is opened
// against the very document being signed and the fingerprint the owner
// typed from the device is compared in constant time, also in the dry run,
// so a stolen old key alone cannot rotate a device (ADR-0020).
func (s *Server) handleApplyRotation(w http.ResponseWriter, r *http.Request) {
	var req applyRotationRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.Request == "" || len(req.Request) > maxRotationLine {
		writeError(w, http.StatusBadRequest, "Anahtar yenileme isteği geçersiz.")
		return
	}
	typed := trust.NormalizeFingerprint(req.Fingerprint)
	if typed == "" {
		writeError(w, http.StatusBadRequest, "Cihazda görünen parmak izini yazın.")
		return
	}
	signed, err := trust.DecodeKeyRotation(req.Request)
	if err != nil {
		s.fail(w, err)
		return
	}
	now := s.now()
	s.change(w, req.signRequest, func(doc *trust.Document) error {
		rot, err := trust.OpenKeyRotation(doc, signed, now)
		if err != nil {
			return rotationError(err)
		}
		want := trust.NormalizeFingerprint(rot.Fingerprint())
		if subtle.ConstantTimeCompare([]byte(typed), []byte(want)) != 1 {
			return admin.ErrFingerprintMismatch
		}
		_, err = doc.ApplyKeyRotation(signed, now)
		return err
	})
}

// rotationError reports a request whose old signature does not verify
// against the device's current key as stale: it was applied already or
// the keys changed. It is the request that is wrong, not the network
// document, so it must not be reported as a document failure.
func rotationError(err error) error {
	if errors.Is(err, trust.ErrBadSignature) {
		return trust.ErrRotationStale
	}
	return err
}

// --- groups and rules (ADR-0021) ---

type groupView struct {
	Name    string   `json:"name"`
	Members []string `json:"members"`
	// UsedBy counts the rules and exit user entries that refer to the
	// group; a used group cannot be removed.
	UsedBy int `json:"usedBy"`
}

type setGroupRequest struct {
	signRequest
	Name    string   `json:"name"`
	Members []string `json:"members"`
}

func (s *Server) handleSetGroup(w http.ResponseWriter, r *http.Request) {
	var req setGroupRequest
	if !decodeBody(w, r, &req) {
		return
	}
	name := strings.TrimSpace(req.Name)
	if !validDeviceName(name) {
		writeError(w, http.StatusBadRequest, "Grup adı yalnızca küçük harf, rakam ve tire içerebilir (en fazla 63 karakter).")
		return
	}
	members, ok := cleanList(req.Members, maxGroupMembers, maxReferenceLen)
	if !ok {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Bir grupta en fazla %d üye olabilir.", maxGroupMembers))
		return
	}
	normalizeAddrEntries(members) // "100.80.0.5" -> "100.80.0.5/32" (#277, f4a_api.go)
	s.change(w, req.signRequest, func(doc *trust.Document) error {
		return doc.SetGroup(name, members)
	})
}

type removeGroupRequest struct {
	signRequest
	Name string `json:"name"`
}

func (s *Server) handleRemoveGroup(w http.ResponseWriter, r *http.Request) {
	var req removeGroupRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if !validDeviceName(req.Name) {
		writeError(w, http.StatusBadRequest, "Grup adı geçersiz.")
		return
	}
	s.change(w, req.signRequest, func(doc *trust.Document) error {
		return doc.RemoveGroup(req.Name)
	})
}

type ruleStateRequest struct {
	signRequest
	Index    int  `json:"index"`
	Disabled bool `json:"disabled"`
}

func (s *Server) handleRuleState(w http.ResponseWriter, r *http.Request) {
	var req ruleStateRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.Index < 0 || req.Index >= trust.MaxRules {
		writeError(w, http.StatusBadRequest, "Kural bulunamadı.")
		return
	}
	s.change(w, req.signRequest, func(doc *trust.Document) error {
		return doc.SetRuleDisabled(req.Index, req.Disabled)
	})
}

// --- exit node users (ADR-0021, F-036) ---

type exitUsersView struct {
	// Restricted is false when every device may use exit nodes.
	Restricted bool     `json:"restricted"`
	Users      []string `json:"users"`
}

type exitUsersRequest struct {
	signRequest
	// Restricted false removes the restriction; true sets Users (an empty
	// list allows no device).
	Restricted bool     `json:"restricted"`
	Users      []string `json:"users"`
}

func (s *Server) handleExitUsers(w http.ResponseWriter, r *http.Request) {
	var req exitUsersRequest
	if !decodeBody(w, r, &req) {
		return
	}
	users, ok := cleanList(req.Users, maxExitUsers, maxReferenceLen)
	if !ok || (!req.Restricted && len(users) > 0) {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Çıkış düğümü kullanıcıları en fazla %d girdi olabilir.", maxExitUsers))
		return
	}
	normalizeAddrEntries(users) // #277, f4a_api.go
	s.change(w, req.signRequest, func(doc *trust.Document) error {
		if !req.Restricted {
			return doc.ClearExitUsers()
		}
		return doc.SetExitUsers(users)
	})
}

// --- network DNS (ADR-0024) ---

type splitDNSView struct {
	Domain      string   `json:"domain"`
	Nameservers []string `json:"nameservers"`
}

type dnsView struct {
	Nameservers []string       `json:"nameservers"`
	Split       []splitDNSView `json:"split"`
}

type dnsRequest struct {
	signRequest
	// Clear removes the dns section; Nameservers and Split are ignored.
	Clear       bool           `json:"clear"`
	Nameservers []string       `json:"nameservers"`
	Split       []splitDNSView `json:"split"`
}

func (s *Server) handleSetDNS(w http.ResponseWriter, r *http.Request) {
	var req dnsRequest
	if !decodeBody(w, r, &req) {
		return
	}
	var settings *trust.DNSSettings
	if !req.Clear {
		var msg string
		settings, msg = parseDNSRequest(req)
		if msg != "" {
			writeError(w, http.StatusBadRequest, msg)
			return
		}
	}
	s.change(w, req.signRequest, func(doc *trust.Document) error {
		return doc.SetDNS(settings)
	})
}

// parseDNSRequest turns the request into DNS settings, or returns a
// Turkish message. The trust package still checks that every address is a
// device's tunnel address.
func parseDNSRequest(req dnsRequest) (*trust.DNSSettings, string) {
	if len(req.Nameservers) > trust.MaxNameservers || len(req.Split) > trust.MaxSplitDomains {
		return nil, fmt.Sprintf("En fazla %d ağ geneli çözücü ve %d alan adı girilebilir.", trust.MaxNameservers, trust.MaxSplitDomains)
	}
	out := &trust.DNSSettings{}
	var ok bool
	if out.Nameservers, ok = parseResolvers(req.Nameservers); !ok {
		return nil, "Çözücü adresi geçersiz; ağdaki bir cihazın OpenScale adresini yazın."
	}
	for _, e := range req.Split {
		domain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(e.Domain)), ".")
		if domain == "" || len(domain) > maxDomainLen {
			return nil, "Alan adı geçersiz."
		}
		addrs, ok := parseResolvers(e.Nameservers)
		if !ok || len(addrs) == 0 || len(addrs) > trust.MaxNameservers {
			return nil, fmt.Sprintf("%s için 1-%d geçerli çözücü adresi girin.", domain, trust.MaxNameservers)
		}
		out.Split = append(out.Split, trust.SplitDNS{Domain: domain, Nameservers: addrs})
	}
	if len(out.Nameservers) == 0 && len(out.Split) == 0 {
		return nil, "En az bir çözücü veya alan adı girin; DNS ayarlarını kaldırmak için 'Kaldır'ı kullanın."
	}
	return out, ""
}

func parseResolvers(in []string) ([]netip.Addr, bool) {
	var out []netip.Addr
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if len(s) > maxResolverText {
			return nil, false
		}
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" {
			return nil, false
		}
		out = append(out, a.Unmap())
	}
	return out, true
}

func dnsSettingsView(d *trust.DNSSettings) *dnsView {
	if d == nil {
		return nil
	}
	v := &dnsView{Nameservers: addrStrings(d.Nameservers), Split: []splitDNSView{}}
	for _, e := range d.Split {
		v.Split = append(v.Split, splitDNSView{Domain: e.Domain, Nameservers: addrStrings(e.Nameservers)})
	}
	return v
}

func addrStrings(addrs []netip.Addr) []string {
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.String())
	}
	return out
}

// dnsWarnings lists resolver devices that other devices cannot reach on
// port 53 under the current rules: those devices' queries would time out
// (ADR-0024). The filter on the resolver is the security boundary, so
// this is advice, not a check.
func dnsWarnings(doc *trust.Document) []string {
	if doc.DNS == nil {
		return []string{}
	}
	byAddr := make(map[netip.Addr]string, 2*len(doc.Devices))
	for _, d := range doc.Devices {
		byAddr[d.IPv4], byAddr[d.IPv6] = d.Name, d.Name
	}
	var resolvers []string
	add := func(addrs []netip.Addr) {
		for _, a := range addrs {
			if name, ok := byAddr[a]; ok && !slices.Contains(resolvers, name) {
				resolvers = append(resolvers, name)
			}
		}
	}
	add(doc.DNS.Nameservers)
	for _, e := range doc.DNS.Split {
		add(e.Nameservers)
	}
	out := []string{}
	for _, res := range resolvers {
		var blocked []string
		for _, d := range doc.Devices {
			if d.Name == res {
				continue
			}
			if !doc.Allows(d.Name, res, trust.ProtocolUDP, 53) {
				blocked = append(blocked, d.Name)
			}
		}
		if len(blocked) == 0 {
			continue
		}
		const shown = 5
		list := strings.Join(blocked[:min(len(blocked), shown)], ", ")
		if len(blocked) > shown {
			list += fmt.Sprintf(" ve %d cihaz daha", len(blocked)-shown)
		}
		out = append(out, fmt.Sprintf("%s çözücüsüne 53/udp için erişim kuralı yok; şu cihazların DNS sorguları yanıtsız kalır: %s.", res, list))
	}
	return out
}

// --- network display name (F-160) ---

type displayNameRequest struct {
	signRequest
	DisplayName string `json:"displayName"`
}

func (s *Server) handleSetDisplayName(w http.ResponseWriter, r *http.Request) {
	var req displayNameRequest
	if !decodeBody(w, r, &req) {
		return
	}
	name := strings.TrimSpace(req.DisplayName)
	if len(name) > 4*trust.MaxDisplayNameLength {
		writeError(w, http.StatusBadRequest, admin.Describe(trust.ErrInvalidDisplayName))
		return
	}
	if name != "" {
		if err := trust.ValidateDisplayName(name); err != nil {
			writeError(w, http.StatusBadRequest, admin.Describe(err))
			return
		}
	}
	s.change(w, req.signRequest, func(doc *trust.Document) error {
		return doc.SetDisplayName(name)
	})
}

// --- helpers ---

// cleanList trims entries, drops empty ones and enforces a count and a
// per-entry length limit. Entries with control characters are refused.
func cleanList(in []string, maxCount, maxLen int) ([]string, bool) {
	if len(in) > maxCount {
		return nil, false
	}
	out := make([]string, 0, len(in))
	for _, e := range in {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if len(e) > maxLen || strings.IndexFunc(e, unicode.IsControl) >= 0 {
			return nil, false
		}
		out = append(out, e)
	}
	return out, true
}

// entryMatchesDevice reports whether a rule entry ("*", a name, "tag:x" or
// "group:x") covers device d. It mirrors the trust package's matching for
// display in the device detail page.
func entryMatchesDevice(doc *trust.Document, e string, d trust.Device) bool {
	if e == trust.RuleWildcard || e == d.Name {
		return true
	}
	if t, ok := strings.CutPrefix(e, trust.TagPrefix); ok {
		return slices.Contains(d.Tags, t)
	}
	if g, ok := strings.CutPrefix(e, trust.GroupPrefix); ok {
		group, found := doc.GroupByName(g)
		if !found {
			return false
		}
		for _, m := range group.Members {
			if m == d.Name {
				return true
			}
			if t, isTag := strings.CutPrefix(m, trust.TagPrefix); isTag && slices.Contains(d.Tags, t) {
				return true
			}
		}
	}
	return false
}

// groupUsage counts references to each group in rules and exit_users.
func groupUsage(doc *trust.Document) map[string]int {
	out := map[string]int{}
	count := func(entries []string) {
		for _, e := range entries {
			if g, ok := strings.CutPrefix(e, trust.GroupPrefix); ok {
				out[g]++
			}
		}
	}
	for _, r := range doc.Rules {
		count(r.From)
		count(r.To)
	}
	if users, set := doc.ExitUsersList(); set {
		count(users)
	}
	return out
}

// knownTags lists every tag carried by a device or a pending invite.
func knownTags(doc *trust.Document) []string {
	seen := map[string]bool{}
	out := []string{}
	add := func(tags []string) {
		for _, t := range tags {
			if !seen[t] {
				seen[t] = true
				out = append(out, t)
			}
		}
	}
	for _, d := range doc.Devices {
		add(d.Tags)
	}
	for _, inv := range doc.Invites {
		add(inv.Tags)
	}
	slices.Sort(out)
	return out
}
