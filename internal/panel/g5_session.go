package panel

import (
	"context"
	"crypto/subtle"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/piv"
)

// Session hardening of G5 (ADR-0199):
//
//   - #675 a session is bound to the context it was opened in: the
//     source device (remote panel), the connection's source address and
//     the WebView identity header. A request from another context drops
//     the session.
//   - #673/#674 with a second factor enrolled, a password sign-in opens a
//     half-finished session that can only finish the second factor.
//   - #676 critical actions need a fresh proof (password, TOTP code or
//     security key) within the last two minutes, used once.
//   - #678 with the administrator mode on, changes are allowed only for
//     15 minutes after the last proof and, when asked, only while the
//     YubiKey is present; afterwards the session is read only until the
//     next proof.

const (
	// WebViewHeader carries the desktop window's identity (#675).
	WebViewHeader   = "X-OpenScale-WebView"
	maxWebViewID    = 128
	pendingLife     = 2 * time.Minute
	reauthLife      = 2 * time.Minute
	challengeLife   = 2 * time.Minute
	adminModeLife   = 15 * time.Minute
	tokenProbeCache = 2 * time.Second
	settingsCache   = 2 * time.Second
)

// g5Session is the per-session G5 state; guarded by its own mutex.
type g5Session struct {
	mu sync.Mutex
	// #675 context.
	bound   bool
	device  string
	addr    netip.Addr
	webview string
	// #673/#674: sign-in waiting for the second factor.
	pending      bool
	pendingUntil time.Time
	remote       bool
	kek          []byte // TOTP seed key derived from the password
	// WebAuthn challenge in flight.
	challenge      []byte
	challengeKind  string
	challengeUntil time.Time
	// #676 and #678.
	reauthUntil time.Time
	elevatedAt  time.Time
	// TOTP enrollment in progress.
	enroll *totpEnroll
	// viaTray: automatic sign-in with the tray's ticket; duress: opened
	// with the duress passphrase (desk_session.go).
	viaTray bool
	duress  bool
}

type totpEnroll struct {
	seed   []byte
	local  *SealedSeed
	remote *SealedSeed
	until  time.Time
}

func (e *totpEnroll) wipe() {
	if e != nil {
		wipe(e.seed)
	}
}

// clearSecrets wipes key material held by the session.
func (g *g5Session) clearSecretsLocked() {
	wipe(g.kek)
	g.kek = nil
	g.enroll.wipe()
	g.enroll = nil
	g.challenge = nil
}

// isPending reports a half-finished sign-in.
func (g *g5Session) isPending() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.pending
}

// requestContext is what a session is bound to.
type requestContext struct {
	device  string
	addr    netip.Addr
	webview string
}

func contextOf(r *http.Request) requestContext {
	var rc requestContext
	if dev, ok := remoteDevice(r); ok {
		rc.device = dev
	}
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		rc.addr = ap.Addr().Unmap()
	}
	if v := r.Header.Get(WebViewHeader); len(v) <= maxWebViewID {
		rc.webview = v
	} else {
		rc.webview = "\x00invalid"
	}
	return rc
}

// checkContext binds an unbound session to rc and otherwise compares.
func (g *g5Session) checkContext(rc requestContext) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.bound {
		g.bound, g.device, g.addr, g.webview = true, rc.device, rc.addr, rc.webview
		return true
	}
	return g.device == rc.device && g.addr == rc.addr &&
		subtle.ConstantTimeCompare([]byte(g.webview), []byte(rc.webview)) == 1
}

// g5State is the per-server G5 state (a field of Server).
type g5State struct {
	mu sync.Mutex
	// settings cache.
	cached   *PanelAuth
	cachedAt time.Time
	// token probe (#678) and its cache.
	probe      func(ctx context.Context) (bool, error)
	probeAt    time.Time
	probeValue bool
	// SSH terminal tickets (g5_ssh_api.go).
	tickets map[string]*sshTicket
	// sshResolve maps a device name to its tunnel address.
	sshResolve func(name string) (netip.Addr, bool)
	// webAuthnOrigins overrides the allowed origins (tests).
	origins []string
	// desk is the desktop window binding (#646, desk_session.go).
	desk deskState
}

// SetAdminTokenProbe replaces the YubiKey presence check of the
// administrator mode (#678). The default lists PC/SC readers whose name
// contains "yubico" (read only).
func (s *Server) SetAdminTokenProbe(probe func(ctx context.Context) (bool, error)) {
	s.g5.mu.Lock()
	s.g5.probe = probe
	s.g5.probeAt = time.Time{}
	s.g5.mu.Unlock()
}

func defaultTokenProbe(ctx context.Context) (bool, error) {
	res, err := piv.Presence(ctx, piv.PresenceOptions{})
	if err != nil {
		return false, err
	}
	return res.Present, nil
}

// panelDir returns the network directory, or "" without a network.
func (s *Server) panelDir() string {
	if n := s.network(); n != nil {
		return n.Dir()
	}
	return ""
}

// authSettings returns the cached settings (default when unavailable).
func (s *Server) authSettings() *PanelAuth {
	s.g5.mu.Lock()
	defer s.g5.mu.Unlock()
	now := s.now()
	if s.g5.cached != nil && now.Sub(s.g5.cachedAt) < settingsCache && !now.Before(s.g5.cachedAt) {
		return s.g5.cached
	}
	p := &PanelAuth{Version: panelAuthVersion}
	if dir := s.panelDir(); dir != "" {
		if loaded, err := LoadPanelAuth(dir); err == nil {
			p = loaded
		} else {
			s.logger.Warn("panel-auth settings unreadable; strictest defaults apply", "error", err.Error())
			// A broken file must not switch protections off.
			p = &PanelAuth{Version: panelAuthVersion, ReauthCritical: true, AdminMode: true}
		}
	}
	s.g5.cached, s.g5.cachedAt = p, now
	return p
}

func (s *Server) dropSettingsCache() {
	s.g5.mu.Lock()
	s.g5.cached = nil
	s.g5.mu.Unlock()
}

// tokenPresent asks the probe at most every tokenProbeCache.
func (s *Server) tokenPresent(ctx context.Context) bool {
	s.g5.mu.Lock()
	probe := s.g5.probe
	if probe == nil {
		probe = defaultTokenProbe
	}
	now := s.now()
	if !s.g5.probeAt.IsZero() && now.Sub(s.g5.probeAt) < tokenProbeCache && !now.Before(s.g5.probeAt) {
		v := s.g5.probeValue
		s.g5.mu.Unlock()
		return v
	}
	s.g5.mu.Unlock()
	pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	present, err := probe(pctx)
	cancel()
	if err != nil {
		present = false
	}
	s.g5.mu.Lock()
	s.g5.probeAt, s.g5.probeValue = now, present
	s.g5.mu.Unlock()
	if !present {
		s.auth.dropElevation()
	}
	return present
}

// dropElevation ends the administrator mode of every session: a removed
// key needs a new proof even after it is put back.
func (a *auth) dropElevation() {
	a.mu.Lock()
	list := make([]*session, 0, len(a.sessions))
	for _, s := range a.sessions {
		list = append(list, s)
	}
	a.mu.Unlock()
	for _, s := range list {
		s.g5.mu.Lock()
		s.g5.elevatedAt = time.Time{}
		s.g5.mu.Unlock()
	}
}

// lookupAny returns a session even while it waits for the second factor.
func (a *auth) lookupAny(id string) (*session, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pruneLocked()
	s, ok := a.sessions[id]
	if !ok {
		return nil, false
	}
	s.lastSeen = a.now()
	return s, true
}

// logoutSession removes a session and wipes its secrets.
func (a *auth) logoutSession(id string) {
	a.mu.Lock()
	s := a.sessions[id]
	delete(a.sessions, id)
	a.mu.Unlock()
	if s != nil {
		s.g5.mu.Lock()
		s.g5.clearSecretsLocked()
		s.g5.mu.Unlock()
	}
}

// adminActive reports whether sess may change things now (#678).
func (s *Server) adminActive(ctx context.Context, sess *session, set *PanelAuth) (bool, time.Duration) {
	if !set.AdminMode {
		return true, 0
	}
	if set.AdminToken && !s.tokenPresent(ctx) {
		return false, 0
	}
	sess.g5.mu.Lock()
	at := sess.g5.elevatedAt
	sess.g5.mu.Unlock()
	if at.IsZero() {
		return false, 0
	}
	left := adminModeLife - s.now().Sub(at)
	if left <= 0 {
		return false, 0
	}
	return true, left
}

// criticalPaths need a fresh proof when ReauthCritical is on (#676).
var criticalPaths = map[string]bool{
	"/api/invites":                true,
	"/api/p02/invites/split":      true,
	"/api/p02/invites/launcher":   true,
	"/api/membership/preauth":     true,
	"/api/security/backup":        true,
	"/api/security/paper-backup":  true,
	"/api/security/passphrase":    true,
	"/api/app/sync/backup/key":    true,
	"/api/ssh/hostkeys/forget":    true,
	"/api/auth/webauthn/remove":   true,
	"/api/auth/totp/remove":       true,
	"/api/auth/settings":          true,
	"/api/auth/webauthn/register": true,
}

// adminExempt are changes that never need the administrator mode: the
// sign-in itself and the proofs that start the mode.
func adminExempt(p string) bool {
	switch {
	case p == "/api/login", p == "/api/logout", p == "/api/app/ticket":
		return true
	case strings.HasPrefix(p, "/api/auth/mfa/"), strings.HasPrefix(p, "/api/auth/reauth"):
		return true
	case strings.HasPrefix(p, "/api/app/tray"):
		return true
	}
	return false
}

func isChange(m string) bool {
	return m != http.MethodGet && m != http.MethodHead && m != http.MethodOptions
}

// g5Gate enforces #676 and #678 before the panel's handlers. Requests
// without a session cookie are left to the handlers' own checks.
func (s *Server) g5Gate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isChange(r.Method) || !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		c, err := r.Cookie(sessionCookie)
		if err != nil || c.Value == "" {
			next.ServeHTTP(w, r)
			return
		}
		sess, ok := s.auth.lookup(c.Value)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}
		path := r.URL.Path
		if sess.g5.isDuress() && path != "/api/logout" { // #592, desk_session.go
			writeError(w, http.StatusForbidden, duressReadOnlyMessage)
			return
		}
		set := s.authSettings()
		if set.AdminMode && !adminExempt(path) {
			if ok, _ := s.adminActive(r.Context(), sess, set); !ok {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "Yönetici kipi kapandı; panel salt okunur. Devam etmek için parola, kod veya güvenlik anahtarıyla yeniden doğrulayın.", "code": "admin_mode_required"})
				return
			}
		}
		if set.ReauthCritical && criticalPaths[path] {
			// The key fits the stricter check only after the CSRF and
			// Origin checks of the handler; a forged request cannot use
			// the proof because it never passes requireCSRF. The proof is
			// still spent here so it works once.
			if !s.sameOrigin(r) || !sess.g5.takeReauth(s.now()) {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "Bu işlem için kimliğinizi yeniden doğrulayın.", "code": "reauth_required"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// takeReauth spends a fresh proof.
func (g *g5Session) takeReauth(now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.reauthUntil.IsZero() || !now.Before(g.reauthUntil) {
		return false
	}
	g.reauthUntil = time.Time{}
	return true
}

// proved records a successful proof: it opens the reauth window and
// (re)starts the administrator mode.
func (g *g5Session) proved(now time.Time) {
	g.mu.Lock()
	g.reauthUntil = now.Add(reauthLife)
	g.elevatedAt = now
	g.mu.Unlock()
}

// g5Check runs the context check of #675 for a full or pending session.
func (s *Server) g5Check(r *http.Request, id string, sess *session) bool {
	if sess.g5.checkContext(contextOf(r)) {
		if s.windowCheck(r, id) { // #646, desk_session.go
			return true
		}
		s.auth.logoutSession(id)
		return false
	}
	s.logger.Warn("panel session dropped: context changed")
	s.auth.logoutSession(id)
	return false
}

// newSession creates a session for a finished password check. pending
// marks a sign-in that still needs the second factor; kek is the TOTP
// seed key derived from the password (kept only while pending).
func (s *Server) newSession(w http.ResponseWriter, r *http.Request, pending, remote bool, kek []byte) bool {
	id, err := s.auth.create()
	if err != nil {
		wipe(kek)
		writeError(w, http.StatusInternalServerError, "Oturum açılamadı.")
		return false
	}
	s.auth.mu.Lock()
	sess := s.auth.sessions[id]
	s.auth.mu.Unlock()
	if sess == nil {
		wipe(kek)
		writeError(w, http.StatusInternalServerError, "Oturum açılamadı.")
		return false
	}
	now := s.now()
	rc := contextOf(r)
	sess.g5.mu.Lock()
	sess.g5.bound, sess.g5.device, sess.g5.addr, sess.g5.webview = true, rc.device, rc.addr, rc.webview
	sess.g5.remote = remote
	if pending {
		sess.g5.pending, sess.g5.pendingUntil, sess.g5.kek = true, now.Add(pendingLife), kek
	} else {
		wipe(kek)
		sess.g5.elevatedAt = now
	}
	sess.g5.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: id, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
	return true
}

type loginResponse struct {
	OK          bool     `json:"ok"`
	MFARequired bool     `json:"mfa_required,omitempty"`
	Methods     []string `json:"methods,omitempty"`
}

// mfaMethods lists what can finish a sign-in from this panel.
func mfaMethods(set *PanelAuth, remote bool) []string {
	var m []string
	if len(set.WebAuthn) > 0 {
		m = append(m, "webauthn")
	}
	if set.TOTP != nil && (!remote || set.TOTP.Remote != nil) {
		m = append(m, "totp")
	}
	return m
}

// finishPasswordLogin opens the session after a correct password: a
// full one, or a pending one when a second factor is due (#673, #674).
// password is the root passphrase (local) or remote password (remote);
// the caller wipes it.
func (s *Server) finishPasswordLogin(w http.ResponseWriter, r *http.Request, password []byte, remote bool) {
	set := s.authSettings()
	methods := mfaMethods(set, remote)
	need := len(methods) > 0 && (remote || set.LocalMFA)
	var kek []byte
	if need && set.TOTP != nil {
		sealed := set.TOTP.Local
		if remote {
			sealed = set.TOTP.Remote
		}
		if sealed != nil {
			kek = deriveSealKey(password, sealed.Salt)
		}
	}
	if !s.newSession(w, r, need, remote, kek) {
		return
	}
	writeJSON(w, http.StatusOK, loginResponse{OK: true, MFARequired: need, Methods: methodsIf(need, methods)})
}

func methodsIf(ok bool, m []string) []string {
	if ok {
		return m
	}
	return nil
}

// pendingExpired reports a half-finished sign-in that took too long.
func (g *g5Session) pendingExpired(now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.pending && !now.Before(g.pendingUntil)
}

// wipe clears the session's secrets (called when it is removed).
func (g *g5Session) wipe() {
	g.mu.Lock()
	g.clearSecretsLocked()
	g.mu.Unlock()
}

// hasFreshProof reports a proof within reauthLife without spending it.
func (g *g5Session) hasFreshProof(now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return !g.reauthUntil.IsZero() && now.Before(g.reauthUntil)
}
