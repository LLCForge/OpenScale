package panel

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/trust"
)

const (
	maxRequestBody   = 64 << 10
	maxDeviceLifeDay = 3650
)

// --- response types (JSON field names are what the panel consumes) ---

type overviewResponse struct {
	NetworkID string `json:"networkId"`
	// DisplayName is the network's name (F-160), "" when not set.
	DisplayName     string    `json:"displayName"`
	Version         uint64    `json:"version"`
	IssuedAt        time.Time `json:"issuedAt"`
	ExpiresAt       time.Time `json:"expiresAt"`
	DaysLeft        int       `json:"daysLeft"`
	DNSDomain       string    `json:"dnsDomain"`
	IPv4Prefix      string    `json:"ipv4Prefix"`
	IPv6Prefix      string    `json:"ipv6Prefix"`
	RootFingerprint string    `json:"rootFingerprint"`
	DeviceCount     int       `json:"deviceCount"`
	ExitNodeCount   int       `json:"exitNodeCount"`
	RuleCount       int       `json:"ruleCount"`
	RevokedCount    int       `json:"revokedCount"`
	BackupCount     int       `json:"backupCount"`
	LastBackupAt    *string   `json:"lastBackupAt"`
	Warnings        []warning `json:"warnings"`
}

// warning is an overview alert; it shares the coded alert type with the
// device health alerts (F-193).
type warning = HealthAlert

type deviceView struct {
	ID           string      `json:"id"`
	Name         string      `json:"name"`
	FQDN         string      `json:"fqdn"`
	IPv4         string      `json:"ipv4"`
	IPv6         string      `json:"ipv6"`
	ExitNode     bool        `json:"exitNode"`
	Admin        bool        `json:"admin"`
	ThisComputer bool        `json:"thisComputer"`
	Status       string      `json:"status"`
	LastSeen     *time.Time  `json:"lastSeen"`
	System       *systemView `json:"system"`
	AddedAt      time.Time   `json:"addedAt"`
	ExpiresAt    time.Time   `json:"expiresAt"`
	DaysLeft     int         `json:"daysLeft"`
	Tags         []string    `json:"tags"`
	// Icon is the signed device type (#233, ADR-0232); "" when none.
	Icon string `json:"icon"`
}

type revokedView struct {
	Name      string    `json:"name"`
	RevokedAt time.Time `json:"revokedAt"`
}

type ruleView struct {
	Index       int      `json:"index"`
	From        []string `json:"from"`
	To          []string `json:"to"`
	Protocol    string   `json:"protocol"`
	Ports       []string `json:"ports"`
	Description string   `json:"description"`
	// Action is "allow" or "deny" (ADR-0021).
	Action   string `json:"action"`
	Disabled bool   `json:"disabled"`
	Text     string `json:"text"`
	// Service rule fields (ADR-0030, ADR-0031); empty for traffic rules.
	Service      string   `json:"service"`
	Users        []string `json:"users"`
	AllowRoot    bool     `json:"allowRoot"`
	AllowForward bool     `json:"allowForward"`
	Via          []string `json:"via"`
	// rdesk (ADR-0055) and sync (ADR-0104, ADR-0110) fields.
	AllowControl    bool     `json:"allowControl"`
	AllowUnattended bool     `json:"allowUnattended"`
	Folders         []string `json:"folders"`
	Backup          bool     `json:"backup"`
	Quota           int64    `json:"quota"`
	AllowPrune      bool     `json:"allowPrune"`
	// Rule language fields the edit form shows (ADR-0120).
	Bidirectional bool `json:"bidirectional"`
	// NotAfter ends a one-time access window (RFC 3339), "" when none.
	NotAfter string `json:"notAfter,omitempty"`
	// Scheduled is true for a rule limited to some hours or a start time;
	// the edit form keeps those limits as they are.
	Scheduled bool `json:"scheduled"`
}

func newRuleView(i int, rule trust.Rule) ruleView {
	action := string(trust.RuleAllow)
	if rule.IsDeny() {
		action = string(trust.RuleDeny)
	}
	return ruleView{
		Index: i, From: rule.From, To: rule.To, Protocol: string(rule.Protocol),
		Ports: rule.Ports, Description: rule.Description, Action: action, Disabled: rule.Disabled,
		Text: admin.RuleString(rule), Service: string(rule.Service), Users: rule.Users,
		AllowRoot: rule.AllowRoot, AllowForward: rule.AllowForward, Via: rule.Via,
		AllowControl: rule.AllowControl, AllowUnattended: rule.AllowUnattended,
		Folders: rule.Folders, Backup: rule.Backup, Quota: rule.Quota, AllowPrune: rule.AllowPrune,
		Bidirectional: rule.Bidirectional, NotAfter: formatRuleTime(rule.NotAfter),
		Scheduled: rule.Schedule != nil || !rule.NotBefore.IsZero(),
	}
}

type changeResponse struct {
	DryRun  bool       `json:"dryRun"`
	Diff    admin.Diff `json:"diff"`
	Lines   []string   `json:"lines"`
	Version uint64     `json:"version"`
	// Risk is the G1 risk summary (ADR-0177, pa_api.go).
	Risk *admin.RiskReport `json:"risk,omitempty"`
}

// --- request types ---

type signRequest struct {
	Passphrase   string `json:"passphrase"`
	DryRun       bool   `json:"dryRun"`
	ValidityDays int    `json:"validityDays"`
	// Draft adds the change to the change draft instead of signing it
	// (#344, p01_api.go).
	Draft bool `json:"draft"`
	Token bool `json:"token,omitempty"` // ADR-0223: sign with the tray's YubiKey session (ym_admin_token.go)
}

type inspectRequest struct {
	Request string `json:"request"`
}

type addDeviceRequest struct {
	signRequest
	Request     string `json:"request"`
	Fingerprint string `json:"fingerprint"`
	// SAS is the short authentication string read from the new device,
	// an alternative to the fingerprint (ADR-0062).
	SAS          string `json:"sas"`
	Name         string `json:"name"`
	ExitNode     bool   `json:"exitNode"`
	LifetimeDays int    `json:"lifetimeDays"`
}

type revokeRequest struct {
	signRequest
	Name string `json:"name"`
}

type addRuleRequest struct {
	signRequest
	From        []string `json:"from"`
	To          []string `json:"to"`
	Protocol    string   `json:"protocol"`
	Ports       []string `json:"ports"`
	Description string   `json:"description"`
	// Action is "allow" (default) or "deny".
	Action string `json:"action"`
	// Service makes it a service rule (ssh, files, wake, speedtest).
	Service      string   `json:"service"`
	Users        []string `json:"users"`
	AllowRoot    bool     `json:"allowRoot"`
	AllowForward bool     `json:"allowForward"`
	Via          []string `json:"via"`
	// rdesk and sync rule fields.
	AllowControl    bool     `json:"allowControl"`
	AllowUnattended bool     `json:"allowUnattended"`
	Folders         []string `json:"folders"`
	Backup          bool     `json:"backup"`
	Quota           int64    `json:"quota"`
	AllowPrune      bool     `json:"allowPrune"`
	// Rule language fields (ADR-0120, policy_p09_api.go).
	Bidirectional bool     `json:"bidirectional"`
	ICMPTypes     []string `json:"icmpTypes"`
	// WindowMinutes makes a one-time access window (#104): the rule
	// closes by itself this many minutes after signing (0: no limit).
	WindowMinutes int `json:"windowMinutes"`
	// ConfirmBroad confirms an allow rule from every device to every
	// device on every port (#112).
	ConfirmBroad bool `json:"confirmBroad"`
}

type removeRuleRequest struct {
	signRequest
	Index int `json:"index"`
}

type passphraseRequest struct {
	Current string `json:"current"`
	Next    string `json:"next"`
}

type backupRequest struct {
	Current          string `json:"current"`
	BackupPassphrase string `json:"backupPassphrase"`
	Label            string `json:"label"`
}

// --- handlers ---

type sessionResponse struct {
	CSRFToken string `json:"csrfToken"`
	// ReadOnly: every change is refused; the panel hides its buttons.
	ReadOnly bool `json:"readOnly"`
	// Remote: the panel was opened from another device (ADR-0107); it is
	// always read-only there.
	Remote bool `json:"remote"`
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	sess, _ := r.Context().Value(ctxKey{}).(*session)
	_, remote := remoteDevice(r)
	writeJSON(w, http.StatusOK, sessionResponse{CSRFToken: sess.csrf, ReadOnly: s.isReadOnly() || remote, Remote: remote})
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	doc, ok := s.currentDocument(w)
	if !ok {
		return
	}
	backups, err := s.network().Backups()
	if err != nil {
		s.fail(w, err)
		return
	}
	now := s.now()
	resp := overviewResponse{
		NetworkID:       doc.NetworkID,
		DisplayName:     doc.DisplayName,
		Version:         doc.Version,
		IssuedAt:        doc.IssuedAt,
		ExpiresAt:       doc.ExpiresAt,
		DaysLeft:        daysUntil(now, doc.ExpiresAt),
		DNSDomain:       doc.DNSDomain,
		IPv4Prefix:      doc.IPv4Prefix.String(),
		IPv6Prefix:      doc.IPv6Prefix.String(),
		RootFingerprint: s.network().RootFingerprint(),
		DeviceCount:     len(doc.Devices),
		RuleCount:       len(doc.Rules),
		RevokedCount:    len(doc.Revoked),
		BackupCount:     len(backups),
		Warnings:        []warning{},
	}
	for _, d := range doc.Devices {
		if d.HasRole(trust.RoleExitNode) {
			resp.ExitNodeCount++
		}
		if left := daysUntil(now, d.ExpiresAt); left <= 14 {
			resp.Warnings = append(resp.Warnings, warning{Code: HealthMembershipExpiring, Level: LevelWarning, Message: fmt.Sprintf("%s cihazının üyeliği %d gün içinde bitiyor.", d.Name, max(left, 0))})
		}
	}
	if len(backups) > 0 {
		last := backups[len(backups)-1].CreatedAt.UTC().Format(time.RFC3339)
		resp.LastBackupAt = &last
	} else {
		resp.Warnings = append(resp.Warnings, warning{Code: HealthNoBackup, Level: LevelDanger, Message: "Kök anahtarın hiç yedeği yok. Ağ ayarlarından bir yedek al."})
	}
	switch {
	case resp.DaysLeft <= 0:
		resp.Warnings = append(resp.Warnings, warning{Code: HealthDocumentExpiring, Level: LevelDanger, Message: "Ağ belgesinin süresi dolmuş; cihazlar yeni bağlantı kurmaz. Belgeyi yenile."})
	case resp.DaysLeft <= 14:
		resp.Warnings = append(resp.Warnings, warning{Code: HealthDocumentExpiring, Level: LevelWarning, Message: fmt.Sprintf("Ağ belgesinin süresi %d gün içinde doluyor.", resp.DaysLeft)})
	}
	for _, t := range doc.TagUsage() {
		resp.Warnings = append(resp.Warnings, warning{Code: HealthUnusedTag, Level: LevelWarning, Message: fmt.Sprintf("tag:%s etiketine kurallarda başvuruluyor ama hiçbir cihazda yok; bu başvuru hiçbir şeyle eşleşmez.", t)})
	}
	for _, msg := range dnsWarnings(doc) {
		resp.Warnings = append(resp.Warnings, warning{Code: HealthDNSResolverBlocked, Level: LevelWarning, Message: msg})
	}
	if len(doc.Devices) > 0 && len(doc.Rules) == 0 {
		resp.Warnings = append(resp.Warnings, warning{Code: HealthNoRules, Level: LevelInfo, Message: "Hiç erişim kuralı yok: cihazlar arası tüm trafik reddedilir."})
	}
	resp.Warnings = append(resp.Warnings, s.p01Warnings(doc, now)...) // ADR-0151
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	doc, ok := s.currentDocument(w)
	if !ok {
		return
	}
	live := s.liveView()
	devices := make([]deviceView, 0, len(doc.Devices))
	for _, d := range doc.Devices {
		devices = append(devices, live.device(doc, d, s.now()))
	}
	coord := live.coordinator(doc, s.now())
	revoked := make([]revokedView, 0, len(doc.Revoked))
	for _, rv := range doc.Revoked {
		revoked = append(revoked, revokedView{Name: rv.Name, RevokedAt: rv.RevokedAt})
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": devices, "revoked": revoked, "dnsDomain": doc.DNSDomain, "coordinator": coord})
}

func (s *Server) handleInspectDevice(w http.ResponseWriter, r *http.Request) {
	var req inspectRequest
	if !decodeBody(w, r, &req) {
		return
	}
	pending, err := s.network().InspectRequest(req.Request, s.now())
	if err != nil {
		s.fail(w, err)
		return
	}
	// The fingerprint is deliberately not returned: the owner must read it
	// from the new device's screen.
	writeJSON(w, http.StatusOK, map[string]string{
		"suggestedName": pending.Request.Hostname,
		"deviceId":      pending.Request.DeviceID[:8],
		// The short code is compared, not typed from here: the owner
		// reads it on the new device and types it back (ADR-0062).
		"sas": pending.SAS(),
	})
}

func (s *Server) handleAddDevice(w http.ResponseWriter, r *http.Request) {
	var req addDeviceRequest
	if !decodeBody(w, r, &req) {
		return
	}
	lifetimeDays := req.LifetimeDays
	if lifetimeDays == 0 {
		lifetimeDays = int(trust.DefaultDeviceLife.Hours() / 24)
	}
	if lifetimeDays < 1 || lifetimeDays > maxDeviceLifeDay {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Üyelik süresi 1 ile %d gün arasında olmalı.", maxDeviceLifeDay))
		return
	}
	pending, err := s.network().InspectRequest(req.Request, s.now())
	if err != nil {
		s.fail(w, err)
		return
	}
	if req.Fingerprint == "" && req.SAS != "" {
		if err := pending.ConfirmSAS(req.SAS); err != nil {
			s.fail(w, err)
			return
		}
	} else if err := pending.ConfirmFingerprint(req.Fingerprint); err != nil {
		s.fail(w, err)
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = pending.Request.Hostname
	}
	var roles []trust.Role
	if req.ExitNode {
		roles = append(roles, trust.RoleExitNode)
	}
	now := s.now()
	lifetime := time.Duration(lifetimeDays) * 24 * time.Hour
	s.change(w, req.signRequest, func(doc *trust.Document) error {
		_, err := doc.AddDevice(pending.Request, name, roles, now, lifetime)
		return err
	})
}

func (s *Server) handleRevokeDevice(w http.ResponseWriter, r *http.Request) {
	var req revokeRequest
	if !decodeBody(w, r, &req) {
		return
	}
	now := s.now()
	s.change(w, req.signRequest, func(doc *trust.Document) error {
		_, err := doc.RevokeDevice(req.Name, now)
		return err
	})
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	doc, ok := s.currentDocument(w)
	if !ok {
		return
	}
	rules := make([]ruleView, 0, len(doc.Rules))
	for i, rule := range doc.Rules {
		rules = append(rules, newRuleView(i, rule))
	}
	names := make([]string, 0, len(doc.Devices))
	for _, d := range doc.Devices {
		names = append(names, d.Name)
	}
	usage := groupUsage(doc)
	groups := make([]groupView, 0, len(doc.Groups))
	for _, g := range doc.Groups {
		groups = append(groups, groupView{Name: g.Name, Members: append([]string{}, g.Members...), UsedBy: usage[g.Name]})
	}
	unused := doc.TagUsage()
	if unused == nil {
		unused = []string{}
	}
	writeJSON(w, http.StatusOK, rulesResponse{Rules: rules, Devices: names, Groups: groups, Tags: knownTags(doc), UnusedTags: unused})
}

type rulesResponse struct {
	Rules   []ruleView  `json:"rules"`
	Devices []string    `json:"devices"`
	Groups  []groupView `json:"groups"`
	// Tags are the tags carried by devices and pending invites.
	Tags []string `json:"tags"`
	// UnusedTags are referenced by rules, groups or exit users but carried
	// by no device or invite (Document.TagUsage).
	UnusedTags []string `json:"unusedTags"`
}

func (s *Server) handleAddRule(w http.ResponseWriter, r *http.Request) {
	var req addRuleRequest
	if !decodeBody(w, r, &req) {
		return
	}
	rule, ok := s.ruleFromRequest(w, req)
	if !ok {
		return
	}
	s.change(w, req.signRequest, func(doc *trust.Document) error { return doc.AddRule(rule) })
}

// ruleFromRequest checks and builds the rule of an add or edit request.
// It writes the error response itself and reports false on a bad request.
func (s *Server) ruleFromRequest(w http.ResponseWriter, req addRuleRequest) (trust.Rule, bool) {
	var action trust.RuleAction
	switch req.Action {
	case "", string(trust.RuleAllow):
	case string(trust.RuleDeny):
		action = trust.RuleDeny
	default:
		writeError(w, http.StatusBadRequest, "Kural eylemi izin veya reddet olmalı.")
		return trust.Rule{}, false
	}
	proto := strings.ToLower(strings.TrimSpace(req.Protocol))
	svc := strings.ToLower(strings.TrimSpace(req.Service))
	if len(proto) > 8 || len(svc) > 16 || len(req.From) > maxRuleEntries || len(req.To) > maxRuleEntries ||
		len(req.Via) > maxRuleEntries || len(req.Users) > maxRuleEntries || len(req.Folders) > maxRuleEntries {
		writeError(w, http.StatusBadRequest, "Kural geçersiz.")
		return trust.Rule{}, false
	}
	rule := trust.Rule{
		From: req.From, To: req.To, Protocol: trust.Protocol(proto),
		Ports: req.Ports, Description: strings.TrimSpace(req.Description), Action: action,
		Service: trust.RuleService(svc), Users: req.Users, AllowRoot: req.AllowRoot,
		AllowForward: req.AllowForward, Via: req.Via,
		AllowControl: req.AllowControl, AllowUnattended: req.AllowUnattended,
		Folders: req.Folders, Backup: req.Backup, Quota: req.Quota, AllowPrune: req.AllowPrune,
	}
	if rule.Service != "" {
		rule.Protocol, rule.Ports = "", nil
	}
	if !s.applyRuleExt(w, &rule, req) {
		return trust.Rule{}, false
	}
	return rule, true
}

func (s *Server) handleRemoveRule(w http.ResponseWriter, r *http.Request) {
	var req removeRuleRequest
	if !decodeBody(w, r, &req) {
		return
	}
	s.change(w, req.signRequest, func(doc *trust.Document) error {
		_, err := doc.RemoveRule(req.Index)
		return err
	})
}

func (s *Server) handleRenew(w http.ResponseWriter, r *http.Request) {
	var req signRequest
	if !decodeBody(w, r, &req) {
		return
	}
	s.change(w, req, func(*trust.Document) error { return nil })
}

func (s *Server) handleChangePassphrase(w http.ResponseWriter, r *http.Request) {
	var req passphraseRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if s.auth.passphraseLocked() {
		writeError(w, http.StatusTooManyRequests, "Çok fazla yanlış parola denemesi. 5 dakika sonra tekrar dene.")
		return
	}
	current, next := []byte(req.Current), []byte(req.Next)
	defer wipe(current)
	defer wipe(next)
	if err := s.network().ChangePassphrase(current, next); err != nil {
		s.failPassphrase(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleBackup(w http.ResponseWriter, r *http.Request) {
	var req backupRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if s.auth.passphraseLocked() {
		writeError(w, http.StatusTooManyRequests, "Çok fazla yanlış parola denemesi. 5 dakika sonra tekrar dene.")
		return
	}
	current, backupPass := []byte(req.Current), []byte(req.BackupPassphrase)
	defer wipe(current)
	defer wipe(backupPass)
	data, err := s.network().CreateBackup(current, backupPass, strings.TrimSpace(req.Label), s.now())
	if err != nil {
		s.failPassphrase(w, err)
		return
	}
	name := "openscale-yedek-" + s.now().UTC().Format("20060102-150405") + ".key"
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	if err := s.network().Reload(); err != nil {
		s.fail(w, err)
		return
	}
	report, err := s.network().VerifyHistory()
	if err != nil {
		s.fail(w, err)
		return
	}
	// Newest first for display.
	for i, j := 0, len(report.Entries)-1; i < j; i, j = i+1, j-1 {
		report.Entries[i], report.Entries[j] = report.Entries[j], report.Entries[i]
	}
	writeJSON(w, http.StatusOK, report)
}

// change runs the dry-run or signing path shared by every edit.
func (s *Server) change(w http.ResponseWriter, req signRequest, fn admin.Change) {
	validityDays := req.ValidityDays
	if validityDays == 0 {
		validityDays = int(trust.DefaultValidity.Hours() / 24)
	}
	maxDays := int(trust.MaxValidity.Hours() / 24)
	if validityDays < 1 || validityDays > maxDays {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Belge geçerliliği 1 ile %d gün arasında olmalı.", maxDays))
		return
	}
	if err := s.network().Reload(); err != nil {
		s.fail(w, err)
		return
	}
	if req.Draft { // #344, p01_api.go
		s.stageDraft(w, fn)
		return
	}
	plan, err := s.network().Prepare(s.now(), time.Duration(validityDays)*24*time.Hour, fn)
	if err != nil {
		s.fail(w, err)
		return
	}
	resp := changeResponse{DryRun: req.DryRun, Diff: plan.Diff, Lines: plan.Diff.Lines(), Version: plan.Next.Version, Risk: s.riskOf(plan)}
	if req.DryRun {
		writeJSON(w, http.StatusOK, resp)
		return
	}
	if req.Token { // ADR-0223, ym_admin_token.go
		s.tokenChange(w, plan, resp)
		return
	}
	if s.auth.passphraseLocked() {
		writeError(w, http.StatusTooManyRequests, "Çok fazla yanlış parola denemesi. 5 dakika sonra tekrar dene.")
		return
	}
	passphrase := []byte(req.Passphrase)
	defer wipe(passphrase)
	if err := s.network().Commit(plan, passphrase); err != nil {
		s.failPassphrase(w, err)
		return
	}
	s.logger.Info("network document signed", "version", plan.Next.Version)
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) currentDocument(w http.ResponseWriter) (*trust.Document, bool) {
	if err := s.network().Reload(); err != nil {
		s.fail(w, err)
		return nil, false
	}
	doc, err := s.network().Document()
	if err != nil {
		s.fail(w, err)
		return nil, false
	}
	return doc, true
}

func (s *Server) failPassphrase(w http.ResponseWriter, err error) {
	if errors.Is(err, trust.ErrWrongPassphrase) {
		s.auth.recordPassphraseFailure()
		s.logger.Warn("wrong root key passphrase in panel")
	}
	s.fail(w, err)
}

// fail maps errors to status codes. Messages come from admin.Describe and
// never include secrets.
func (s *Server) fail(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	switch {
	case errors.Is(err, trust.ErrWrongPassphrase):
		status = http.StatusUnauthorized
	case errors.Is(err, admin.ErrConcurrentChange), errors.Is(err, admin.ErrHistoryVersionUsed):
		status = http.StatusConflict
	case errors.Is(err, trust.ErrBadSignature):
		status = http.StatusInternalServerError
		s.logger.Error("network document failed verification", "error", err.Error())
	}
	writeErrorCode(w, status, admin.Describe(err), err) // #550, p12_api.go
}

func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, "İstek JSON olmalı.")
		return false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestBody))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "İstek çok büyük.")
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "İstek biçimi geçersiz.")
		return false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "İstek biçimi geçersiz.")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func daysUntil(now, t time.Time) int {
	d := t.Sub(now)
	if d <= 0 {
		return 0
	}
	return int(d.Hours()/24) + 1
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
