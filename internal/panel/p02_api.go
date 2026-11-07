package panel

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/enrollkit"
	"github.com/openscale/openscale/internal/qr"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

// Panel API of package P02: "like this device" (#357), nearby pairing
// (#358, ADR-0156), two-channel invite (#359, ADR-0157), invite launcher
// (#360), lost device (#367), guest wizard (#368), access requests from
// devices (#383, ADR-0158) and the connection card (#557). Document edits
// go through s.change (dry run, draft, passphrase lock, read-only mode).

const (
	// GuestTagPrefix marks the tags made by the guest wizard.
	GuestTagPrefix     = "konuk-"
	maxGuestHours      = 7 * 24
	maxLauncherHours   = 24
	maxInboxEntries    = 64
	maxRequestLine     = 2048
	inboxFile          = "p02-erisim-istekleri.json"
	maxInboxFile       = 512 << 10
	inboxKeepDecided   = trust.AccessRequestMaxAge + 24*time.Hour
	cardQRScale        = 6
	inboxStatusPending = "pending"
	inboxStatusOK      = "approved"
	inboxStatusNo      = "rejected"
)

// p02Runtime is the per-server state of P02 (nearby listener and inbox
// lock). It lives beside Server so the shared struct stays untouched.
type p02Runtime struct {
	mu         sync.Mutex
	nearby     *enrollkit.Listener
	stop       context.CancelFunc
	done       chan struct{}
	nearbyAddr string // test hook; empty means all IPv4 addresses
	inboxMu    sync.Mutex
}

var p02States sync.Map // *Server -> *p02Runtime

func (s *Server) p02() *p02Runtime {
	v, _ := p02States.LoadOrStore(s, &p02Runtime{})
	return v.(*p02Runtime)
}

func (s *Server) p02Routes(mux *http.ServeMux) {
	owner := func(h http.HandlerFunc) http.HandlerFunc { return s.requireSession(s.requireNetwork(h)) }
	ownerWrite := func(h http.HandlerFunc) http.HandlerFunc {
		return s.requireSession(s.requireCSRF(s.requireWritable(s.requireNetwork(h))))
	}
	mux.HandleFunc("GET /api/p02/devices/like", owner(s.handleLikeSuggest))
	mux.HandleFunc("POST /api/p02/devices/like", ownerWrite(s.handleLikeApply))
	mux.HandleFunc("GET /api/p02/devices/lost", owner(s.handleLostReport))
	mux.HandleFunc("POST /api/p02/devices/lost", ownerWrite(s.handleLostAct))
	mux.HandleFunc("GET /api/p02/devices/card", owner(s.handleCard))
	mux.HandleFunc("POST /api/p02/guest", ownerWrite(s.handleGuest))
	mux.HandleFunc("GET /api/p02/guests", owner(s.handleGuests))
	mux.HandleFunc("POST /api/p02/invites/split", ownerWrite(s.handleSplitInvite))
	mux.HandleFunc("POST /api/p02/invites/launcher", ownerWrite(s.handleLauncher))
	mux.HandleFunc("GET /api/p02/nearby", owner(s.handleNearby))
	mux.HandleFunc("POST /api/p02/nearby/listen", ownerWrite(s.handleNearbyListen))
	mux.HandleFunc("GET /api/p02/access-requests", owner(s.handleAccessInbox))
	mux.HandleFunc("POST /api/p02/access-requests", ownerWrite(s.handleInboxAdd))
	mux.HandleFunc("POST /api/p02/access-requests/approve", ownerWrite(s.handleInboxApprove))
	mux.HandleFunc("POST /api/p02/access-requests/reject", ownerWrite(s.handleInboxReject))
}

// statusWriter remembers the status s.change wrote.
type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(code int) {
	w.code = code
	w.ResponseWriter.WriteHeader(code)
}

// --- #357 "like this device" ---

func (s *Server) handleLikeSuggest(w http.ResponseWriter, r *http.Request) {
	source, target := r.URL.Query().Get("source"), r.URL.Query().Get("target")
	if !validDeviceName(source) || !validDeviceName(target) {
		writeError(w, http.StatusBadRequest, "Cihaz adı geçersiz.")
		return
	}
	doc, ok := s.currentDocument(w)
	if !ok {
		return
	}
	sug, err := doc.LikeDevice(source, target)
	if err != nil {
		s.fail(w, err)
		return
	}
	rules := make([]ruleView, 0, len(sug.Rules))
	for i, rule := range sug.Rules {
		rules = append(rules, newRuleView(i, rule))
	}
	writeJSON(w, http.StatusOK, map[string]any{"source": source, "target": target, "tags": sug.Tags, "groups": sug.Groups, "rules": rules, "exitUser": sug.ExitUser})
}

type likeRequest struct {
	signRequest
	Source   string   `json:"source"`
	Target   string   `json:"target"`
	Tags     []string `json:"tags"`
	Groups   []string `json:"groups"`
	Rules    []int    `json:"rules"`
	ExitUser bool     `json:"exitUser"`
}

func (s *Server) handleLikeApply(w http.ResponseWriter, r *http.Request) {
	var req likeRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if !validDeviceName(req.Source) || !validDeviceName(req.Target) {
		writeError(w, http.StatusBadRequest, "Cihaz adı geçersiz.")
		return
	}
	tags, ok := cleanList(req.Tags, maxTagsPerDevice, maxReferenceLen)
	groups, ok2 := cleanList(req.Groups, maxRuleEntries, maxReferenceLen)
	if !ok || !ok2 || len(req.Rules) > maxRuleEntries {
		writeError(w, http.StatusBadRequest, "Seçim geçersiz.")
		return
	}
	s.change(w, req.signRequest, func(doc *trust.Document) error {
		sug, err := doc.LikeDevice(req.Source, req.Target)
		if err != nil {
			return err
		}
		// The owner may drop parts of the suggestion and edit the tags;
		// rules and groups can only be chosen from the suggestion.
		picked := trust.LikeSuggestion{Source: sug.Source, Target: sug.Target, Tags: tags}
		for _, g := range groups {
			if !slices.Contains(sug.Groups, g) {
				return errors.New("group is not part of the suggestion")
			}
			picked.Groups = append(picked.Groups, g)
		}
		for _, i := range req.Rules {
			if i < 0 || i >= len(sug.Rules) {
				return errors.New("rule is not part of the suggestion")
			}
			picked.Rules = append(picked.Rules, sug.Rules[i])
		}
		return doc.ApplyLike(picked, req.ExitUser && sug.ExitUser)
	})
}

// --- #367 lost device ---

type lostReport struct {
	trust.DeviceExposure
	LastSeen  *time.Time `json:"lastSeen"`
	IPv4      string     `json:"ipv4"`
	Checklist []string   `json:"checklist"`
}

func lostChecklist(e trust.DeviceExposure) []string {
	out := []string{}
	seen := map[string]bool{}
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, r := range e.Outbound {
		targets := strings.Join(r.To, ", ")
		switch r.Service {
		case trust.ServiceSSH:
			add(fmt.Sprintf("%s: SSH ile girilen hesapların parolalarını değiştirin; bu cihazdaki SSH anahtarlarını authorized_keys dosyalarından çıkarın.", targets))
		case trust.ServiceRemoteDesktop:
			add(fmt.Sprintf("%s: uzak masaüstü oturumlarını kapatın ve oturum açılan hesapların parolalarını değiştirin.", targets))
		case trust.ServiceFiles, trust.ServiceSync:
			add(fmt.Sprintf("%s: bu cihazla paylaşılan klasörlerdeki gizli dosyaları gözden geçirin.", targets))
		case "":
			for _, p := range r.Ports {
				switch p {
				case "22":
					add(fmt.Sprintf("%s: SSH parolalarını ve yetkili anahtarları değiştirin.", targets))
				case "3389", "5900":
					add(fmt.Sprintf("%s: uzak masaüstü hesaplarının parolalarını değiştirin.", targets))
				case "445", "139":
					add(fmt.Sprintf("%s: dosya paylaşımı (SMB) hesaplarının parolalarını değiştirin.", targets))
				case "80", "443", "8080", "8443":
					add(fmt.Sprintf("%s: web arayüzlerinde kayıtlı oturumları kapatın ve parolaları değiştirin.", targets))
				}
			}
		}
	}
	if len(e.Routes) > 0 {
		add("Bu cihazın yönlendirdiği alt ağlardaki (" + strings.Join(e.Routes, ", ") + ") aygıtların parolalarını değiştirin.")
	}
	add("Cihazda kayıtlı tarayıcı parolalarını ve e-posta oturumlarını kapatın (bu adım OpenScale dışındadır).")
	return out
}

func (s *Server) handleLostReport(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if !validDeviceName(name) {
		writeError(w, http.StatusBadRequest, "Cihaz adı geçersiz.")
		return
	}
	doc, ok := s.currentDocument(w)
	if !ok {
		return
	}
	e, err := doc.DeviceExposure(name)
	if err != nil {
		s.fail(w, err)
		return
	}
	d, _ := doc.DeviceByName(name)
	rep := lostReport{DeviceExposure: e, IPv4: d.IPv4.String(), Checklist: lostChecklist(e)}
	if t, ok := s.liveView().seen(d.WireGuardKey); ok && !t.IsZero() {
		rep.LastSeen = &t
	}
	writeJSON(w, http.StatusOK, rep)
}

type lostRequest struct {
	signRequest
	Name string `json:"name"`
	// Action is "revoke" (permanent, cleans every reference) or "expire"
	// (ends the membership; the keys stay valid for a later extension).
	Action string `json:"action"`
	// DropRules removes rules left only for this device ("expire" only;
	// revoke always does it).
	DropRules bool `json:"dropRules"`
}

func (s *Server) handleLostAct(w http.ResponseWriter, r *http.Request) {
	var req lostRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if !validDeviceName(req.Name) {
		writeError(w, http.StatusBadRequest, "Cihaz adı geçersiz.")
		return
	}
	now := s.now()
	switch req.Action {
	case "revoke":
		s.change(w, req.signRequest, func(doc *trust.Document) error {
			_, err := doc.RevokeDevice(req.Name, now)
			return err
		})
	case "expire":
		s.change(w, req.signRequest, func(doc *trust.Document) error {
			if _, err := doc.ExpireDevice(req.Name, now); err != nil {
				return err
			}
			if req.DropRules {
				doc.DropRulesOnlyFor(req.Name)
			}
			return doc.Validate()
		})
	default:
		writeError(w, http.StatusBadRequest, "İşlem 'revoke' veya 'expire' olmalı.")
	}
}

// --- #368 guest wizard ---

type guestRequest struct {
	signRequest
	Label       string   `json:"label"`
	Target      string   `json:"target"`
	Service     string   `json:"service"`
	Protocol    string   `json:"protocol"`
	Port        string   `json:"port"`
	Users       []string `json:"users"`
	Hours       int      `json:"hours"`
	InviteHours int      `json:"inviteHours"`
}

type guestResponse struct {
	Code      string    `json:"code,omitempty"`
	Tag       string    `json:"tag"`
	ExpiresAt time.Time `json:"expiresAt"`
	RuleUntil time.Time `json:"ruleUntil"`
	DryRun    bool      `json:"dryRun"`
	Lines     []string  `json:"lines"`
	Version   uint64    `json:"version"`
}

func (s *Server) handleGuest(w http.ResponseWriter, r *http.Request) {
	var req guestRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.Draft {
		writeError(w, http.StatusBadRequest, "Konuk daveti taslağa eklenemez; tek imzayla yayımlanır.")
		return
	}
	if !validDeviceName(req.Target) {
		writeError(w, http.StatusBadRequest, "Hedef cihaz geçersiz.")
		return
	}
	if req.Hours < 1 || req.Hours > maxGuestHours {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Konuk erişimi 1 ile %d saat arasında olmalı.", maxGuestHours))
		return
	}
	inviteHours := req.InviteHours
	if inviteHours == 0 {
		inviteHours = 1
	}
	if inviteHours < 1 || inviteHours > req.Hours || inviteHours > maxInviteLifeHours {
		writeError(w, http.StatusBadRequest, "Davet süresi 1 saat ile konuk süresi arasında olmalı.")
		return
	}
	users, ok := cleanList(req.Users, 8, maxNameLen)
	if !ok || len(req.Label) > 60 {
		writeError(w, http.StatusBadRequest, "Konuk bilgileri geçersiz.")
		return
	}
	suffix := make([]byte, 3)
	if _, err := rand.Read(suffix); err != nil {
		writeError(w, http.StatusInternalServerError, "Rastgele etiket üretilemedi.")
		return
	}
	tag := GuestTagPrefix + hex.EncodeToString(suffix)
	now := s.now()
	until := now.UTC().Truncate(time.Second).Add(time.Duration(req.Hours) * time.Hour)
	rule := trust.Rule{
		From: []string{trust.TagPrefix + tag}, To: []string{req.Target}, Ports: []string{},
		Description: strings.TrimSpace("Konuk erişimi " + strings.TrimSpace(req.Label)), NotAfter: until,
	}
	if svc := strings.ToLower(strings.TrimSpace(req.Service)); svc != "" {
		rule.Service, rule.Users = trust.RuleService(svc), users
	} else {
		rule.Protocol = trust.Protocol(strings.ToLower(strings.TrimSpace(req.Protocol)))
		if rule.Protocol != trust.ProtocolTCP && rule.Protocol != trust.ProtocolUDP {
			writeError(w, http.StatusBadRequest, "Konuk için bir servis veya tcp/udp ve tek port seçin.")
			return
		}
		if p, err := strconv.Atoi(req.Port); err != nil || p < 1 || p > 65535 {
			writeError(w, http.StatusBadRequest, "Port 1 ile 65535 arasında olmalı.")
			return
		}
		rule.Ports = []string{req.Port}
	}
	if !req.DryRun && !s.checkLock(w) {
		return
	}
	if err := s.network().Reload(); err != nil {
		s.fail(w, err)
		return
	}
	passphrase := []byte(req.Passphrase)
	defer wipe(passphrase)
	note := "Konuk"
	if l := strings.TrimSpace(req.Label); l != "" {
		note += ": " + l
	}
	created, plan, err := s.network().CreateInviteWithChange(passphrase, now,
		admin.InviteRequest{Life: time.Duration(inviteHours) * time.Hour, Tags: []string{tag}, Note: note},
		func(doc *trust.Document, _ trust.Invite) error { return doc.AddRule(rule) }, req.DryRun)
	if err != nil {
		s.failPassphrase(w, err)
		return
	}
	resp := guestResponse{Code: created.Code, Tag: tag, ExpiresAt: created.Invite.ExpiresAt, RuleUntil: until,
		DryRun: req.DryRun, Lines: plan.Diff.Lines(), Version: plan.Next.Version}
	if !req.DryRun {
		s.logger.Info("guest invite created", "tag", tag)
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, resp)
}

type guestView struct {
	Tag      string     `json:"tag"`
	Invite   string     `json:"inviteId,omitempty"`
	InviteBy *time.Time `json:"inviteExpiresAt,omitempty"`
	Devices  []string   `json:"devices"`
	Rules    []ruleView `json:"rules"`
	Until    *time.Time `json:"until,omitempty"`
	Expired  bool       `json:"expired"`
}

func (s *Server) handleGuests(w http.ResponseWriter, r *http.Request) {
	doc, ok := s.currentDocument(w)
	if !ok {
		return
	}
	now := s.now()
	byTag := map[string]*guestView{}
	get := func(tag string) *guestView {
		if g, ok := byTag[tag]; ok {
			return g
		}
		g := &guestView{Tag: tag, Devices: []string{}, Rules: []ruleView{}}
		byTag[tag] = g
		return g
	}
	for _, inv := range doc.Invites {
		for _, t := range inv.Tags {
			if strings.HasPrefix(t, GuestTagPrefix) {
				g := get(t)
				g.Invite = inv.ID
				exp := inv.ExpiresAt
				g.InviteBy = &exp
			}
		}
	}
	for _, d := range doc.Devices {
		for _, t := range d.Tags {
			if strings.HasPrefix(t, GuestTagPrefix) {
				get(t).Devices = append(get(t).Devices, d.Name)
			}
		}
	}
	for i, rule := range doc.Rules {
		for _, f := range rule.From {
			t, ok := strings.CutPrefix(f, trust.TagPrefix)
			if !ok || !strings.HasPrefix(t, GuestTagPrefix) {
				continue
			}
			g := get(t)
			g.Rules = append(g.Rules, newRuleView(i, rule))
			if !rule.NotAfter.IsZero() {
				u := rule.NotAfter
				g.Until = &u
				g.Expired = !now.Before(u)
			}
		}
	}
	out := make([]*guestView, 0, len(byTag))
	for _, g := range byTag {
		out = append(out, g)
	}
	slices.SortFunc(out, func(a, b *guestView) int { return strings.Compare(a.Tag, b.Tag) })
	writeJSON(w, http.StatusOK, map[string]any{"guests": out})
}

// --- #359 two-channel invite and #360 launcher ---

type p02InviteRequest struct {
	Passphrase    string   `json:"passphrase"`
	LifetimeHours int      `json:"lifetimeHours"`
	Tags          []string `json:"tags"`
	Note          string   `json:"note"`
	// Platform picks the launcher: "windows" or "linux" (#360 only).
	Platform string `json:"platform"`
}

func (s *Server) createInviteFor(w http.ResponseWriter, req p02InviteRequest, maxHours int) (*admin.CreatedInvite, bool) {
	hours := req.LifetimeHours
	if hours == 0 {
		hours = int(trust.DefaultInviteLife / time.Hour)
	}
	if hours < 1 || hours > maxHours {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Davet süresi 1 ile %d saat arasında olmalı.", maxHours))
		return nil, false
	}
	tags, ok := cleanList(req.Tags, maxTagsPerDevice, maxReferenceLen)
	if !ok {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("En fazla %d etiket verilebilir.", maxTagsPerDevice))
		return nil, false
	}
	if !s.checkLock(w) {
		return nil, false
	}
	passphrase := []byte(req.Passphrase)
	defer wipe(passphrase)
	if err := s.network().Reload(); err != nil {
		s.fail(w, err)
		return nil, false
	}
	created, err := s.network().CreateInviteWith(passphrase, s.now(), admin.InviteRequest{Life: time.Duration(hours) * time.Hour, Tags: tags, Note: req.Note})
	if err != nil {
		s.failPassphrase(w, err)
		return nil, false
	}
	return created, true
}

func (s *Server) handleSplitInvite(w http.ResponseWriter, r *http.Request) {
	var req p02InviteRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.Platform != "" {
		writeError(w, http.StatusBadRequest, "İstek biçimi geçersiz.")
		return
	}
	created, ok := s.createInviteFor(w, req, maxInviteLifeHours)
	if !ok {
		return
	}
	code, err := trust.DecodeInviteCode(created.Code)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Davet kodu bölünemedi.")
		return
	}
	a, b, err := trust.SplitInviteCode(code, rand.Reader)
	clear(code.Seed)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Davet kodu bölünemedi.")
		return
	}
	s.logger.Info("two-part invite created")
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"partA": a, "partB": b, "expiresAt": created.Invite.ExpiresAt})
}

func (s *Server) handleLauncher(w http.ResponseWriter, r *http.Request) {
	var req p02InviteRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.Platform != enrollkit.PlatformWindows && req.Platform != enrollkit.PlatformLinux {
		writeError(w, http.StatusBadRequest, "Platform 'windows' veya 'linux' olmalı.")
		return
	}
	created, ok := s.createInviteFor(w, req, maxLauncherHours)
	if !ok {
		return
	}
	l, err := enrollkit.NewLauncher(req.Platform, created.Code, created.Invite.ExpiresAt)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Kurulum dosyası üretilemedi.")
		return
	}
	s.logger.Info("invite launcher created", "platform", req.Platform)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"fileName": l.FileName, "content": base64.StdEncoding.EncodeToString(l.Content), "expiresAt": created.Invite.ExpiresAt,
	})
}

// --- #358 nearby pairing ---

func (s *Server) handleNearby(w http.ResponseWriter, r *http.Request) {
	rt := s.p02()
	rt.mu.Lock()
	l := rt.nearby
	rt.mu.Unlock()
	resp := map[string]any{"listening": false, "requests": []enrollkit.NearbyRequest{}, "port": enrollkit.NearbyPort}
	if l != nil {
		if u := l.Until(); !u.IsZero() {
			resp["listening"], resp["until"] = true, u
		}
		resp["requests"] = l.Requests()
	}
	writeJSON(w, http.StatusOK, resp)
}

type nearbyListenRequest struct {
	On bool `json:"on"`
}

func (s *Server) handleNearbyListen(w http.ResponseWriter, r *http.Request) {
	var req nearbyListenRequest
	if !decodeBody(w, r, &req) {
		return
	}
	rt := s.p02()
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.stop != nil {
		rt.stop()
		select {
		case <-rt.done:
		case <-time.After(2 * time.Second):
		}
		rt.stop, rt.done = nil, nil
	}
	if !req.On {
		writeJSON(w, http.StatusOK, map[string]any{"listening": false})
		return
	}
	addr := rt.nearbyAddr
	if addr == "" {
		addr = net.JoinHostPort("0.0.0.0", strconv.Itoa(enrollkit.NearbyPort))
	}
	conn, err := net.ListenPacket("udp4", addr)
	if err != nil {
		writeError(w, http.StatusConflict, "Yerel ağ dinlenemedi; port başka bir program tarafından kullanılıyor olabilir.")
		return
	}
	if rt.nearby == nil {
		rt.nearby = enrollkit.NewListener(s.now)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	rt.stop, rt.done = cancel, done
	l := rt.nearby
	go func() {
		defer close(done)
		l.Serve(ctx, conn, enrollkit.NearbyWindow)
	}()
	s.logger.Info("nearby pairing listening", "window", enrollkit.NearbyWindow.String())
	writeJSON(w, http.StatusOK, map[string]any{"listening": true, "until": s.now().Add(enrollkit.NearbyWindow), "addr": conn.LocalAddr().String()})
}

// --- #383 access requests ---

type inboxEntry struct {
	ID         string     `json:"id"`
	Line       string     `json:"line"`
	ReceivedAt time.Time  `json:"receivedAt"`
	Status     string     `json:"status"`
	DecidedAt  *time.Time `json:"decidedAt,omitempty"`
}

func (s *Server) inboxPath() string { return filepath.Join(s.network().Dir(), inboxFile) }

func (s *Server) loadInbox() ([]inboxEntry, error) {
	data, err := securefile.ReadLimited(s.inboxPath(), maxInboxFile)
	if errors.Is(err, fs.ErrNotExist) {
		return []inboxEntry{}, nil
	}
	if err != nil {
		return nil, err
	}
	var out []inboxEntry
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, errors.New("erişim isteği kutusu bozuk")
	}
	return out, nil
}

func (s *Server) saveInbox(list []inboxEntry) error {
	now := s.now()
	kept := list[:0]
	for _, e := range list {
		if e.Status != inboxStatusPending && e.DecidedAt != nil && now.Sub(*e.DecidedAt) > inboxKeepDecided {
			continue
		}
		if e.Status == inboxStatusPending && now.Sub(e.ReceivedAt) > inboxKeepDecided {
			continue
		}
		kept = append(kept, e)
	}
	data, err := json.Marshal(kept)
	if err != nil {
		return err
	}
	if _, err := os.Stat(s.inboxPath()); errors.Is(err, fs.ErrNotExist) {
		return securefile.WriteNew(s.inboxPath(), data)
	}
	return securefile.Replace(s.inboxPath(), data)
}

type inboxView struct {
	ID         string               `json:"id"`
	Status     string               `json:"status"`
	ReceivedAt time.Time            `json:"receivedAt"`
	DecidedAt  *time.Time           `json:"decidedAt,omitempty"`
	Request    *trust.AccessRequest `json:"request,omitempty"`
	Error      string               `json:"error,omitempty"`
}

func (s *Server) handleAccessInbox(w http.ResponseWriter, r *http.Request) {
	doc, ok := s.currentDocument(w)
	if !ok {
		return
	}
	rt := s.p02()
	rt.inboxMu.Lock()
	list, err := s.loadInbox()
	rt.inboxMu.Unlock()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Erişim isteği kutusu okunamadı.")
		return
	}
	now := s.now()
	out := make([]inboxView, 0, len(list))
	for i := len(list) - 1; i >= 0; i-- {
		e := list[i]
		v := inboxView{ID: e.ID, Status: e.Status, ReceivedAt: e.ReceivedAt, DecidedAt: e.DecidedAt}
		req, _, err := trust.OpenAccessRequest(doc, e.Line, now)
		if err != nil {
			v.Error = admin.Describe(err)
		} else {
			req.Nonce = nil
			v.Request = req
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{"requests": out})
}

type inboxAddRequest struct {
	Request string `json:"request"`
}

func (s *Server) handleInboxAdd(w http.ResponseWriter, r *http.Request) {
	var req inboxAddRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if len(req.Request) > maxRequestLine {
		writeError(w, http.StatusBadRequest, "İstek çok uzun.")
		return
	}
	doc, ok := s.currentDocument(w)
	if !ok {
		return
	}
	now := s.now()
	ar, id, err := trust.OpenAccessRequest(doc, req.Request, now)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Erişim isteği doğrulanamadı: "+admin.Describe(err))
		return
	}
	// The rule it would create must be valid for the current document.
	rule, err := ar.Rule(now, 0)
	if err == nil {
		_, err = s.network().Prepare(now, trust.DefaultValidity, func(d *trust.Document) error { return d.AddRule(rule) })
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "İstenen erişim bu ağda kural olarak yazılamıyor: "+admin.Describe(err))
		return
	}
	rt := s.p02()
	rt.inboxMu.Lock()
	defer rt.inboxMu.Unlock()
	list, err := s.loadInbox()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Erişim isteği kutusu okunamadı.")
		return
	}
	if slices.ContainsFunc(list, func(e inboxEntry) bool { return e.ID == id }) {
		writeJSON(w, http.StatusOK, map[string]any{"id": id, "duplicate": true})
		return
	}
	pending := 0
	for _, e := range list {
		if e.Status == inboxStatusPending {
			pending++
		}
	}
	if len(list) >= maxInboxEntries || pending >= maxInboxEntries/2 {
		writeError(w, http.StatusTooManyRequests, "Erişim isteği kutusu dolu; bekleyen istekleri yanıtlayın.")
		return
	}
	list = append(list, inboxEntry{ID: id, Line: strings.Join(strings.Fields(req.Request), ""), ReceivedAt: now.UTC(), Status: inboxStatusPending})
	if err := s.saveInbox(list); err != nil {
		writeError(w, http.StatusInternalServerError, "Erişim isteği kaydedilemedi.")
		return
	}
	s.logger.Info("access request received", "from", ar.From, "to", ar.To)
	writeJSON(w, http.StatusOK, map[string]any{"id": id})
}

type inboxDecisionRequest struct {
	signRequest
	ID string `json:"id"`
	// Hours shortens the requested duration on approval (0 keeps it).
	Hours int `json:"hours"`
}

func (s *Server) findInbox(w http.ResponseWriter, id string) ([]inboxEntry, int, bool) {
	list, err := s.loadInbox()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Erişim isteği kutusu okunamadı.")
		return nil, 0, false
	}
	i := slices.IndexFunc(list, func(e inboxEntry) bool { return e.ID == id })
	if i < 0 {
		writeError(w, http.StatusNotFound, "Erişim isteği bulunamadı.")
		return nil, 0, false
	}
	if list[i].Status != inboxStatusPending {
		writeError(w, http.StatusConflict, "Bu istek zaten yanıtlandı.")
		return nil, 0, false
	}
	return list, i, true
}

func (s *Server) handleInboxApprove(w http.ResponseWriter, r *http.Request) {
	var req inboxDecisionRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.Draft {
		writeError(w, http.StatusBadRequest, "Erişim isteği onayı taslağa eklenemez.")
		return
	}
	rt := s.p02()
	rt.inboxMu.Lock()
	defer rt.inboxMu.Unlock()
	list, i, ok := s.findInbox(w, req.ID)
	if !ok {
		return
	}
	now := s.now()
	line := list[i].Line
	sw := &statusWriter{ResponseWriter: w, code: http.StatusOK}
	// The request is verified again inside the change, against the exact
	// document that is signed.
	s.change(sw, req.signRequest, func(doc *trust.Document) error {
		ar, _, err := trust.OpenAccessRequest(doc, line, now)
		if err != nil {
			return err
		}
		rule, err := ar.Rule(now, req.Hours)
		if err != nil {
			return err
		}
		return doc.AddRule(rule)
	})
	if req.DryRun || sw.code != http.StatusOK {
		return
	}
	t := now.UTC()
	list[i].Status, list[i].DecidedAt = inboxStatusOK, &t
	if err := s.saveInbox(list); err != nil {
		s.logger.Warn("access request approved but inbox not updated", "error", err.Error())
	}
}

func (s *Server) handleInboxReject(w http.ResponseWriter, r *http.Request) {
	var req inboxDecisionRequest
	if !decodeBody(w, r, &req) {
		return
	}
	rt := s.p02()
	rt.inboxMu.Lock()
	defer rt.inboxMu.Unlock()
	list, i, ok := s.findInbox(w, req.ID)
	if !ok {
		return
	}
	t := s.now().UTC()
	list[i].Status, list[i].DecidedAt = inboxStatusNo, &t
	if err := s.saveInbox(list); err != nil {
		writeError(w, http.StatusInternalServerError, "Erişim isteği güncellenemedi.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rejected": true})
}

// --- #557 connection card ---

type cardService struct {
	From     []string `json:"from"`
	Label    string   `json:"label"`
	Command  string   `json:"command,omitempty"`
	Until    string   `json:"until,omitempty"`
	Protocol string   `json:"protocol,omitempty"`
	Ports    []string `json:"ports,omitempty"`
}

type connectionCard struct {
	Name     string        `json:"name"`
	DNSName  string        `json:"dnsName"`
	IPv4     string        `json:"ipv4"`
	IPv6     string        `json:"ipv6"`
	Services []cardService `json:"services"`
	Text     string        `json:"text"`
	QR       string        `json:"qr,omitempty"`
}

func cardEntry(r trust.ExposureRule, rule trust.Rule, host string) cardService {
	c := cardService{From: r.From, Protocol: string(r.Protocol), Ports: r.Ports}
	if !rule.NotAfter.IsZero() {
		c.Until = rule.NotAfter.UTC().Format("2006-01-02 15:04 UTC")
	}
	switch r.Service {
	case trust.ServiceSSH:
		user := "kullanici"
		if len(rule.Users) > 0 {
			user = rule.Users[0]
		}
		c.Label, c.Command = "SSH", "ssh "+user+"@"+host
	case trust.ServiceRemoteDesktop:
		c.Label = "Uzak masaüstü (OpenScale)"
	case "":
		c.Label = strings.ToUpper(string(r.Protocol)) + " " + strings.Join(r.Ports, ", ")
		for _, p := range r.Ports {
			switch p {
			case "22":
				c.Label, c.Command = "SSH", "ssh "+host
			case "3389":
				c.Label, c.Command = "Uzak Masaüstü (RDP)", "mstsc /v:"+host
			case "5900":
				c.Label, c.Command = "VNC", "vncviewer "+host
			case "445":
				c.Label, c.Command = "Dosya paylaşımı (SMB)", `\\`+host
			}
		}
	default:
		c.Label = string(r.Service)
	}
	return c
}

func (s *Server) handleCard(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if !validDeviceName(name) {
		writeError(w, http.StatusBadRequest, "Cihaz adı geçersiz.")
		return
	}
	doc, ok := s.currentDocument(w)
	if !ok {
		return
	}
	d, found := doc.DeviceByName(name)
	if !found {
		s.fail(w, trust.ErrUnknownDevice)
		return
	}
	e, err := doc.DeviceExposure(name)
	if err != nil {
		s.fail(w, err)
		return
	}
	host := name + "." + doc.DNSDomain
	card := connectionCard{Name: name, DNSName: host, IPv4: d.IPv4.String(), IPv6: d.IPv6.String(), Services: []cardService{}}
	for _, in := range e.Inbound {
		card.Services = append(card.Services, cardEntry(in, doc.Rules[in.Index], host))
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "OpenScale bağlantı kartı\nCihaz: %s\nAd: %s\nIPv4: %s\n", name, host, card.IPv4)
	for _, c := range card.Services {
		fmt.Fprintf(&b, "- %s", c.Label)
		if c.Command != "" {
			fmt.Fprintf(&b, ": %s", c.Command)
		}
		if c.Until != "" {
			fmt.Fprintf(&b, " (%s tarihine kadar)", c.Until)
		}
		b.WriteByte('\n')
	}
	b.WriteString("Bağlanmak için cihazınızda OpenScale açık olmalı.\n")
	card.Text = b.String()
	if code, err := qr.EncodeText(card.Text, qr.M); err == nil {
		var png bytes.Buffer
		if err := code.PNG(&png, cardQRScale); err == nil {
			card.QR = "data:image/png;base64," + base64.StdEncoding.EncodeToString(png.Bytes())
		}
	}
	writeJSON(w, http.StatusOK, card)
}
