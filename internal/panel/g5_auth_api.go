package panel

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"
)

// Second factor, re-authentication and administrator mode endpoints
// (ADR-0199). The panel agent builds the screens (panel-devir-G5.md).

// g5RemotePost lists the G5 changes the remote panel may make: only the
// sign-in steps; everything else stays local.
func g5RemotePost(p string) bool {
	return strings.HasPrefix(p, "/api/auth/mfa/") || p == "/api/auth/reauth" ||
		p == "/api/auth/reauth/webauthn/begin" || p == "/api/auth/reauth/webauthn/finish"
}

// g5RemoteRead lists the G5 reads open to the remote panel.
func g5RemoteRead(p string) bool { return p == "/api/auth/status" }

func (s *Server) g5Routes(mux *http.ServeMux) {
	write := func(h http.HandlerFunc) http.HandlerFunc { return s.requireSession(s.requireCSRF(h)) }
	mux.HandleFunc("GET /api/auth/status", s.handleAuthStatus)
	// Second step of the sign-in (pending session, Origin checked).
	mux.HandleFunc("POST /api/auth/mfa/totp", s.pendingOnly(s.handleMFATOTP))
	mux.HandleFunc("POST /api/auth/mfa/webauthn/begin", s.pendingOnly(s.handleMFAWebAuthnBegin))
	mux.HandleFunc("POST /api/auth/mfa/webauthn/finish", s.pendingOnly(s.handleMFAWebAuthnFinish))
	// Fresh proof for critical actions and the administrator mode.
	mux.HandleFunc("POST /api/auth/reauth", write(s.handleReauth))
	mux.HandleFunc("POST /api/auth/reauth/webauthn/begin", write(s.handleReauthWebAuthnBegin))
	mux.HandleFunc("POST /api/auth/reauth/webauthn/finish", write(s.handleReauthWebAuthnFinish))
	// Enrolment and settings (local panel; critical paths need reauth).
	mux.HandleFunc("POST /api/auth/webauthn/register/begin", write(s.localOnly(s.handleWebAuthnRegisterBegin)))
	mux.HandleFunc("POST /api/auth/webauthn/register", write(s.localOnly(s.handleWebAuthnRegister)))
	mux.HandleFunc("POST /api/auth/webauthn/remove", write(s.localOnly(s.handleWebAuthnRemove)))
	mux.HandleFunc("POST /api/auth/totp/enroll/begin", write(s.localOnly(s.handleTOTPEnrollBegin)))
	mux.HandleFunc("POST /api/auth/totp/enroll/finish", write(s.localOnly(s.handleTOTPEnrollFinish)))
	mux.HandleFunc("POST /api/auth/totp/remove", write(s.localOnly(s.handleTOTPRemove)))
	mux.HandleFunc("POST /api/auth/settings", write(s.localOnly(s.handleAuthSettings)))
	s.g5SSHRoutes(mux)
}

// localOnly refuses the remote panel.
func (s *Server) localOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, remote := remoteDevice(r); remote {
			writeError(w, http.StatusForbidden, "Bu işlem uzaktan yapılamaz; yönetici bilgisayarda yapın.")
			return
		}
		if s.panelDir() == "" {
			writeError(w, http.StatusConflict, "Bu bilgisayarda yönetilen bir ağ yok.")
			return
		}
		next(w, r)
	}
}

type pendingCtxKey struct{}

// pendingOnly serves a sign-in that waits for its second factor.
func (s *Server) pendingOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.sameOrigin(r) {
			writeError(w, http.StatusForbidden, "İstek kaynağı doğrulanamadı.")
			return
		}
		c, err := r.Cookie(sessionCookie)
		if err != nil || c.Value == "" {
			writeError(w, http.StatusUnauthorized, "Oturum yok veya süresi doldu. Yeniden giriş yapın.")
			return
		}
		sess, ok := s.auth.lookupAny(c.Value)
		if !ok || !sess.g5.isPending() || !s.g5Check(r, c.Value, sess) {
			writeError(w, http.StatusUnauthorized, "Oturum yok veya süresi doldu. Yeniden giriş yapın.")
			return
		}
		if s.auth.passphraseLocked() {
			writeError(w, http.StatusTooManyRequests, "Çok fazla yanlış deneme. 5 dakika sonra tekrar dene.")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), pendingCtxKey{}, sess)))
	}
}

func sessionOf(r *http.Request) *session {
	if s, ok := r.Context().Value(pendingCtxKey{}).(*session); ok {
		return s
	}
	s, _ := r.Context().Value(ctxKey{}).(*session)
	return s
}

// --- status ---

type authFactor struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	LastUsed  time.Time `json:"last_used,omitzero"`
}

type authStatus struct {
	SignedIn       bool         `json:"signed_in"`
	Pending        bool         `json:"pending"`
	Methods        []string     `json:"methods,omitempty"`
	Remote         bool         `json:"remote"`
	WebAuthn       []authFactor `json:"webauthn"`
	TOTP           bool         `json:"totp"`
	TOTPRemote     bool         `json:"totp_remote"`
	ReauthCritical bool         `json:"reauth_critical"`
	ReauthValid    int          `json:"reauth_valid_sec"`
	AdminMode      bool         `json:"admin_mode"`
	AdminActive    bool         `json:"admin_active"`
	AdminLeft      int          `json:"admin_left_sec"`
	AdminToken     bool         `json:"admin_token"`
	LocalMFA       bool         `json:"local_mfa"`
	RPID           string       `json:"rp_id"`
}

func (s *Server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	set := s.authSettings()
	_, remote := remoteDevice(r)
	// Without a full session the answer says only whether a sign-in is
	// waiting for its second factor: the configured factors and the names
	// of the security keys are not shown to whoever reaches the port.
	st := authStatus{Remote: remote, WebAuthn: []authFactor{}}
	if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
		if sess, ok := s.auth.lookupAny(c.Value); ok && s.g5Check(r, c.Value, sess) {
			if sess.g5.isPending() {
				st.Pending, st.Methods = true, mfaMethods(set, remote)
			} else {
				st.SignedIn = true
				st.TOTP, st.TOTPRemote = set.TOTP != nil, set.TOTP != nil && set.TOTP.Remote != nil
				st.ReauthCritical, st.AdminMode, st.AdminToken, st.LocalMFA = set.ReauthCritical, set.AdminMode, set.AdminToken, set.LocalMFA
				st.RPID = set.rpID()
				for _, c := range set.WebAuthn {
					st.WebAuthn = append(st.WebAuthn, authFactor{ID: c.ID, Name: c.Name, CreatedAt: c.CreatedAt, LastUsed: c.LastUsed})
				}
				now := s.now()
				sess.g5.mu.Lock()
				if left := sess.g5.reauthUntil.Sub(now); left > 0 {
					st.ReauthValid = int(left / time.Second)
				}
				sess.g5.mu.Unlock()
				active, left := s.adminActive(r.Context(), sess, set)
				st.AdminActive, st.AdminLeft = active, int(left/time.Second)
			}
		}
	}
	writeJSON(w, http.StatusOK, st)
}

// --- origins and challenges ---

// webAuthnOrigins are the origins accepted in client data: this panel's
// own address by name (WebAuthn refuses IP addresses) and the extra
// origins of the settings.
func (s *Server) webAuthnOrigins(set *PanelAuth) []string {
	s.g5.mu.Lock()
	if s.g5.origins != nil {
		o := slices.Clone(s.g5.origins)
		s.g5.mu.Unlock()
		return o
	}
	s.g5.mu.Unlock()
	var out []string
	if _, port, err := net.SplitHostPort(s.host); err == nil {
		out = append(out, "http://localhost:"+port)
	}
	return append(out, set.ExtraOrigins...)
}

type challengeResponse struct {
	Challenge string   `json:"challenge"`
	RPID      string   `json:"rp_id"`
	Allow     []string `json:"allow_credentials,omitempty"`
	Timeout   int      `json:"timeout_ms"`
	// Registration only.
	UserID      string   `json:"user_id,omitempty"`
	UserName    string   `json:"user_name,omitempty"`
	Exclude     []string `json:"exclude_credentials,omitempty"`
	Attestation string   `json:"attestation,omitempty"`
}

func (s *Server) newChallenge(sess *session, kind string) ([]byte, error) {
	ch := make([]byte, 32)
	if _, err := io.ReadFull(s.random, ch); err != nil {
		return nil, err
	}
	sess.g5.mu.Lock()
	sess.g5.challenge, sess.g5.challengeKind, sess.g5.challengeUntil = ch, kind, s.now().Add(challengeLife)
	sess.g5.mu.Unlock()
	return ch, nil
}

// takeChallenge returns and forgets the challenge of kind.
func (s *Server) takeChallenge(sess *session, kind string) []byte {
	sess.g5.mu.Lock()
	defer sess.g5.mu.Unlock()
	ch := sess.g5.challenge
	ok := ch != nil && sess.g5.challengeKind == kind && s.now().Before(sess.g5.challengeUntil)
	sess.g5.challenge = nil
	if !ok {
		return nil
	}
	return ch
}

func credIDs(creds []WebAuthnCredential) []string {
	out := make([]string, len(creds))
	for i, c := range creds {
		out[i] = c.ID
	}
	return out
}

func (s *Server) assertionBegin(w http.ResponseWriter, sess *session, kind string) {
	set := s.authSettings()
	if len(set.WebAuthn) == 0 {
		writeError(w, http.StatusConflict, "Kayıtlı güvenlik anahtarı yok.")
		return
	}
	ch, err := s.newChallenge(sess, kind)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Doğrulama başlatılamadı.")
		return
	}
	writeJSON(w, http.StatusOK, challengeResponse{Challenge: b64url.EncodeToString(ch), RPID: set.rpID(), Allow: credIDs(set.WebAuthn), Timeout: int(challengeLife / time.Millisecond)})
}

// assertionFinish verifies an assertion and stores the new counter.
func (s *Server) assertionFinish(w http.ResponseWriter, r *http.Request, sess *session, kind string) bool {
	var req AssertionResponse
	if !decodeBody(w, r, &req) {
		return false
	}
	ch := s.takeChallenge(sess, kind)
	if ch == nil {
		writeError(w, http.StatusBadRequest, "Doğrulama isteğinin süresi doldu; yeniden deneyin.")
		return false
	}
	set := s.authSettings()
	idx, count, err := verifyAssertion(req, set.WebAuthn, ch, set.rpID(), s.webAuthnOrigins(set))
	if err != nil {
		s.auth.recordPassphraseFailure()
		s.logger.Warn("panel security key check failed")
		writeError(w, http.StatusUnauthorized, "Güvenlik anahtarı doğrulanamadı.")
		return false
	}
	id := set.WebAuthn[idx].ID
	if dir := s.panelDir(); dir != "" {
		_, err := UpdatePanelAuth(dir, func(p *PanelAuth) error {
			for i := range p.WebAuthn {
				if p.WebAuthn[i].ID == id {
					if count != 0 && count <= p.WebAuthn[i].SignCount {
						return errors.New("counter")
					}
					p.WebAuthn[i].SignCount, p.WebAuthn[i].LastUsed = count, s.now().UTC()
				}
			}
			return nil
		})
		s.dropSettingsCache()
		if err != nil {
			writeError(w, http.StatusUnauthorized, "Güvenlik anahtarı doğrulanamadı.")
			return false
		}
	}
	return true
}

// --- second factor at sign-in ---

type codeRequest struct {
	Code string `json:"code"`
}

// completeMFA turns the pending session into a full one.
func (s *Server) completeMFA(w http.ResponseWriter, sess *session) {
	now := s.now()
	sess.g5.mu.Lock()
	sess.g5.pending = false
	sess.g5.clearSecretsLocked()
	sess.g5.elevatedAt = now
	sess.g5.mu.Unlock()
	s.logger.Info("panel second factor accepted")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleMFATOTP(w http.ResponseWriter, r *http.Request) {
	sess := sessionOf(r)
	var req codeRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if !s.checkTOTPWithKEK(sess, req.Code) {
		s.auth.recordPassphraseFailure()
		s.logger.Warn("panel TOTP code rejected")
		writeError(w, http.StatusUnauthorized, "Kod yanlış veya süresi geçmiş.")
		return
	}
	s.completeMFA(w, sess)
}

// checkTOTPWithKEK opens the seed with the session's key and checks code.
func (s *Server) checkTOTPWithKEK(sess *session, code string) bool {
	set := s.authSettings()
	if set.TOTP == nil {
		return false
	}
	sess.g5.mu.Lock()
	kek := sess.g5.kek
	remote := sess.g5.remote
	sess.g5.mu.Unlock()
	sealed := set.TOTP.Local
	if remote {
		sealed = set.TOTP.Remote
	}
	seed, err := sealed.open(kek)
	if err != nil {
		return false
	}
	defer wipe(seed)
	return s.acceptTOTP(seed, code)
}

// acceptTOTP checks code and records its step so it is never reused.
func (s *Server) acceptTOTP(seed []byte, code string) bool {
	dir := s.panelDir()
	if dir == "" {
		return false
	}
	ok := false
	_, err := UpdatePanelAuth(dir, func(p *PanelAuth) error {
		if p.TOTP == nil {
			return errors.New("no totp")
		}
		step, match := totpCheck(seed, code, s.now(), p.TOTP.LastStep)
		if !match {
			return errors.New("mismatch")
		}
		p.TOTP.LastStep, ok = step, true
		return nil
	})
	s.dropSettingsCache()
	return err == nil && ok
}

func (s *Server) handleMFAWebAuthnBegin(w http.ResponseWriter, r *http.Request) {
	s.assertionBegin(w, sessionOf(r), "mfa")
}

func (s *Server) handleMFAWebAuthnFinish(w http.ResponseWriter, r *http.Request) {
	sess := sessionOf(r)
	if s.assertionFinish(w, r, sess, "mfa") {
		s.completeMFA(w, sess)
	}
}

// --- re-authentication (#676, #678) ---

type reauthRequest struct {
	Passphrase string `json:"passphrase,omitempty"`
	Code       string `json:"code,omitempty"`
}

func (s *Server) handleReauth(w http.ResponseWriter, r *http.Request) {
	sess := sessionOf(r)
	if s.auth.passphraseLocked() {
		writeError(w, http.StatusTooManyRequests, "Çok fazla yanlış deneme. 5 dakika sonra tekrar dene.")
		return
	}
	var req reauthRequest
	if !decodeBody(w, r, &req) {
		return
	}
	pw := []byte(req.Passphrase)
	defer wipe(pw)
	_, remote := remoteDevice(r)
	ok := false
	switch {
	case len(pw) > 0 && remote:
		set, err := LoadRemoteSettings(s.panelDir())
		ok = err == nil && set.Ready() && set.Password.Verify(pw)
	case len(pw) > 0:
		n := s.network()
		ok = n != nil && n.CheckPassphrase(pw) == nil
		if ok && req.Code != "" {
			// A code together with the passphrase also checks TOTP.
			ok = s.checkTOTPWithPassword(pw, req.Code, false)
		}
	case req.Code != "":
		writeError(w, http.StatusBadRequest, "Kod, parolayla birlikte gönderilmeli.")
		return
	default:
		writeError(w, http.StatusBadRequest, "Parola veya kod gerekli.")
		return
	}
	if !ok {
		s.auth.recordPassphraseFailure()
		s.logger.Warn("panel re-authentication failed")
		writeError(w, http.StatusUnauthorized, "Doğrulama başarısız.")
		return
	}
	sess.g5.proved(s.now())
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "valid_sec": int(reauthLife / time.Second), "admin_sec": int(adminModeLife / time.Second)})
}

// checkTOTPWithPassword opens the seed with a password.
func (s *Server) checkTOTPWithPassword(pw []byte, code string, remote bool) bool {
	set := s.authSettings()
	if set.TOTP == nil {
		return false
	}
	sealed := set.TOTP.Local
	if remote {
		sealed = set.TOTP.Remote
	}
	if sealed == nil {
		return false
	}
	kek := deriveSealKey(pw, sealed.Salt)
	defer wipe(kek)
	seed, err := sealed.open(kek)
	if err != nil {
		return false
	}
	defer wipe(seed)
	return s.acceptTOTP(seed, code)
}

func (s *Server) handleReauthWebAuthnBegin(w http.ResponseWriter, r *http.Request) {
	s.assertionBegin(w, sessionOf(r), "reauth")
}

func (s *Server) handleReauthWebAuthnFinish(w http.ResponseWriter, r *http.Request) {
	sess := sessionOf(r)
	if s.assertionFinish(w, r, sess, "reauth") {
		sess.g5.proved(s.now())
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "valid_sec": int(reauthLife / time.Second), "admin_sec": int(adminModeLife / time.Second)})
	}
}

// --- WebAuthn registration ---

func (s *Server) handleWebAuthnRegisterBegin(w http.ResponseWriter, r *http.Request) {
	sess := sessionOf(r)
	if !sess.g5.hasFreshProof(s.now()) {
		// Adding a factor always needs a fresh proof, whatever the settings.
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "Anahtar eklemek için kimliğinizi yeniden doğrulayın.", "code": "reauth_required"})
		return
	}
	set := s.authSettings()
	if len(set.WebAuthn) >= maxWebAuthnCreds {
		writeError(w, http.StatusConflict, "En çok 10 güvenlik anahtarı kaydedilebilir.")
		return
	}
	ch, err := s.newChallenge(sess, "register")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Kayıt başlatılamadı.")
		return
	}
	uid := make([]byte, 16)
	_, _ = io.ReadFull(rand.Reader, uid)
	writeJSON(w, http.StatusOK, challengeResponse{Challenge: b64url.EncodeToString(ch), RPID: set.rpID(), Timeout: int(challengeLife / time.Millisecond),
		UserID: b64url.EncodeToString(uid), UserName: "openscale-" + totpAccountSuffix, Exclude: credIDs(set.WebAuthn), Attestation: "none"})
}

func (s *Server) handleWebAuthnRegister(w http.ResponseWriter, r *http.Request) {
	sess := sessionOf(r)
	var req RegistrationResponse
	if !decodeBody(w, r, &req) {
		return
	}
	ch := s.takeChallenge(sess, "register")
	if ch == nil {
		writeError(w, http.StatusBadRequest, "Kayıt isteğinin süresi doldu; yeniden deneyin.")
		return
	}
	set := s.authSettings()
	cred, err := verifyRegistration(req, ch, set.rpID(), s.webAuthnOrigins(set), s.now())
	if err != nil {
		writeError(w, http.StatusBadRequest, "Güvenlik anahtarı kaydedilemedi: "+err.Error())
		return
	}
	_, err = UpdatePanelAuth(s.panelDir(), func(p *PanelAuth) error {
		if slices.ContainsFunc(p.WebAuthn, func(c WebAuthnCredential) bool { return c.ID == cred.ID }) {
			return errors.New("bu anahtar zaten kayıtlı")
		}
		p.WebAuthn = append(p.WebAuthn, cred)
		return nil
	})
	s.dropSettingsCache()
	if err != nil {
		writeError(w, http.StatusConflict, "Güvenlik anahtarı kaydedilemedi: "+err.Error())
		return
	}
	s.logger.Info("panel security key registered")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": cred.ID})
}

type idRequest struct {
	ID string `json:"id"`
}

func (s *Server) handleWebAuthnRemove(w http.ResponseWriter, r *http.Request) {
	var req idRequest
	if !decodeBody(w, r, &req) {
		return
	}
	removed := false
	_, err := UpdatePanelAuth(s.panelDir(), func(p *PanelAuth) error {
		n := len(p.WebAuthn)
		p.WebAuthn = slices.DeleteFunc(p.WebAuthn, func(c WebAuthnCredential) bool { return c.ID == req.ID })
		removed = len(p.WebAuthn) != n
		return nil
	})
	s.dropSettingsCache()
	if err != nil || !removed {
		writeError(w, http.StatusNotFound, "Güvenlik anahtarı bulunamadı.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// --- TOTP enrolment ---

type totpEnrollRequest struct {
	Passphrase     string `json:"passphrase"`
	RemotePassword string `json:"remote_password,omitempty"`
}

type totpEnrollResponse struct {
	URI    string `json:"uri"`
	Secret string `json:"secret"`
	Remote bool   `json:"remote"`
}

func (s *Server) handleTOTPEnrollBegin(w http.ResponseWriter, r *http.Request) {
	sess := sessionOf(r)
	if s.auth.passphraseLocked() {
		writeError(w, http.StatusTooManyRequests, "Çok fazla yanlış deneme. 5 dakika sonra tekrar dene.")
		return
	}
	var req totpEnrollRequest
	if !decodeBody(w, r, &req) {
		return
	}
	pw, rpw := []byte(req.Passphrase), []byte(req.RemotePassword)
	defer wipe(pw)
	defer wipe(rpw)
	n := s.network()
	if n == nil || n.CheckPassphrase(pw) != nil {
		s.auth.recordPassphraseFailure()
		writeError(w, http.StatusUnauthorized, "Kök anahtar parolası yanlış.")
		return
	}
	var remoteSealed *SealedSeed
	seed := make([]byte, totpSeedBytes)
	if _, err := io.ReadFull(s.random, seed); err != nil {
		writeError(w, http.StatusInternalServerError, "Tohum üretilemedi.")
		return
	}
	local, err := sealSeedWithPassword(seed, pw, s.random)
	if err != nil {
		wipe(seed)
		writeError(w, http.StatusInternalServerError, "Tohum mühürlenemedi.")
		return
	}
	if len(rpw) > 0 {
		set, err := LoadRemoteSettings(s.panelDir())
		if err != nil || set.Password == nil || !set.Password.Verify(rpw) {
			wipe(seed)
			s.auth.recordPassphraseFailure()
			writeError(w, http.StatusUnauthorized, "Uzak erişim parolası yanlış.")
			return
		}
		if remoteSealed, err = sealSeedWithPassword(seed, rpw, s.random); err != nil {
			wipe(seed)
			writeError(w, http.StatusInternalServerError, "Tohum mühürlenemedi.")
			return
		}
	}
	uri := totpURI(seed, totpAccountSuffix)
	secret := uri[strings.Index(uri, "secret=")+len("secret="):]
	if i := strings.IndexByte(secret, '&'); i >= 0 {
		secret = secret[:i]
	}
	sess.g5.mu.Lock()
	sess.g5.enroll.wipe()
	sess.g5.enroll = &totpEnroll{seed: seed, local: local, remote: remoteSealed, until: s.now().Add(5 * time.Minute)}
	sess.g5.mu.Unlock()
	writeJSON(w, http.StatusOK, totpEnrollResponse{URI: uri, Secret: secret, Remote: remoteSealed != nil})
}

func (s *Server) handleTOTPEnrollFinish(w http.ResponseWriter, r *http.Request) {
	sess := sessionOf(r)
	var req codeRequest
	if !decodeBody(w, r, &req) {
		return
	}
	sess.g5.mu.Lock()
	en := sess.g5.enroll
	sess.g5.enroll = nil
	sess.g5.mu.Unlock()
	if en == nil || !s.now().Before(en.until) {
		en.wipe()
		writeError(w, http.StatusBadRequest, "Kayıt süresi doldu; yeniden başlatın.")
		return
	}
	defer en.wipe()
	step, ok := totpCheck(en.seed, req.Code, s.now(), 0)
	if !ok {
		writeError(w, http.StatusUnauthorized, "Kod yanlış; uygulamadaki güncel kodu girin ve kaydı yeniden başlatın.")
		return
	}
	_, err := UpdatePanelAuth(s.panelDir(), func(p *PanelAuth) error {
		p.TOTP = &TOTPState{Local: en.local, Remote: en.remote, LastStep: step, CreatedAt: s.now().UTC()}
		return nil
	})
	s.dropSettingsCache()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "TOTP kaydedilemedi.")
		return
	}
	s.logger.Info("panel TOTP enrolled")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleTOTPRemove(w http.ResponseWriter, r *http.Request) {
	_, err := UpdatePanelAuth(s.panelDir(), func(p *PanelAuth) error {
		p.TOTP = nil
		return nil
	})
	s.dropSettingsCache()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "TOTP kaldırılamadı.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// --- settings ---

type authSettingsRequest struct {
	ReauthCritical *bool    `json:"reauth_critical,omitempty"`
	AdminMode      *bool    `json:"admin_mode,omitempty"`
	AdminToken     *bool    `json:"admin_token,omitempty"`
	LocalMFA       *bool    `json:"local_mfa,omitempty"`
	RPID           *string  `json:"rp_id,omitempty"`
	ExtraOrigins   []string `json:"extra_origins,omitempty"`
}

func (s *Server) handleAuthSettings(w http.ResponseWriter, r *http.Request) {
	var req authSettingsRequest
	if !decodeBody(w, r, &req) {
		return
	}
	_, err := UpdatePanelAuth(s.panelDir(), func(p *PanelAuth) error {
		applyBool(&p.ReauthCritical, req.ReauthCritical)
		applyBool(&p.AdminMode, req.AdminMode)
		applyBool(&p.AdminToken, req.AdminToken)
		applyBool(&p.LocalMFA, req.LocalMFA)
		if req.RPID != nil {
			p.RPID = *req.RPID
		}
		if req.ExtraOrigins != nil {
			p.ExtraOrigins = req.ExtraOrigins
		}
		if p.LocalMFA && !p.HasFactor() {
			return errors.New("önce bir güvenlik anahtarı veya TOTP kaydedin")
		}
		return p.Validate()
	})
	s.dropSettingsCache()
	if err != nil {
		writeError(w, http.StatusBadRequest, "Ayarlar kaydedilemedi: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func applyBool(dst *bool, v *bool) {
	if v != nil {
		*dst = *v
	}
}
