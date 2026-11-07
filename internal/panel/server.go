// Package panel serves the local web administration panel (ADR-0012). It
// listens on loopback only, signs in with the root key passphrase, and
// performs every change through the admin package, so the panel is never a
// separate path to the root key.
package panel

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/panel/web"
)

// Config configures the panel server.
type Config struct {
	// Network is the owner's network directory. It may be nil when App is
	// set: the desktop app creates or joins a network at runtime.
	Network *admin.Network
	// App is the desktop service (ADR-0014); nil for the CLI panel.
	App App
	// AppToken lets the tray exchange a one-time sign-in ticket. Empty
	// disables ticket sign-in.
	AppToken string
	// Files overrides the embedded panel build (development only).
	Files  fs.FS
	Logger *slog.Logger
	Now    func() time.Time
	Random io.Reader
	// ReadOnly, when it reports true, refuses every change made through
	// the panel (F-180). It is asked on each request, so switching it from
	// the command line needs no restart. Nil means never read-only.
	ReadOnly func() bool
	// PeerCheck, when set, must also accept the process behind every
	// request that carries the app token (ADR-0050): it gets the client's
	// and the server's address of the connection.
	PeerCheck func(remote, local string) error
}

// Server is the panel HTTP server.
type Server struct {
	netw   atomic.Pointer[admin.Network]
	app    App
	token  string
	site   *site
	auth   *auth
	logger *slog.Logger
	now    func() time.Time
	random io.Reader
	host   string
	// readOnly is Config.ReadOnly.
	readOnly func() bool
	// peerCheck is Config.PeerCheck.
	peerCheck func(remote, local string) error
	// hist is this computer's connection history (#190, history.go).
	hist connHistory
	// g5 is the G5 sign-in and terminal state (g5_session.go).
	g5 g5State
	w1 w1State // W1: remote desktop viewer (w1_rdesk_viewer.go)
}

// New creates a server. Call Serve with a loopback listener.
func New(cfg Config) (*Server, error) {
	if cfg.Network == nil && cfg.App == nil {
		return nil, errors.New("panel needs a network or the desktop app")
	}
	if cfg.AppToken != "" && len(cfg.AppToken) < 32 {
		return nil, errors.New("app token is too short")
	}
	files := cfg.Files
	if files == nil {
		files = web.FS()
	}
	st, err := newSite(files)
	if err != nil {
		return nil, fmt.Errorf("load panel files: %w", err)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Random == nil {
		cfg.Random = defaultRandom
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	a := newAuth(cfg.Random, cfg.Now)
	s := &Server{app: cfg.App, token: cfg.AppToken, site: st, auth: a, logger: cfg.Logger, now: cfg.Now, random: cfg.Random, readOnly: cfg.ReadOnly,
		peerCheck: cfg.PeerCheck}
	if cfg.Network != nil {
		s.netw.Store(cfg.Network)
	}
	return s, nil
}

// network returns the owner's network, or nil on a member-only device.
func (s *Server) network() *admin.Network { return s.netw.Load() }

// SetNetwork makes the panel manage n (after the app created a network).
func (s *Server) SetNetwork(n *admin.Network) { s.netw.Store(n) }

// requireNetwork answers 409 on devices that do not hold the root key.
func (s *Server) requireNetwork(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.network() == nil {
			writeError(w, http.StatusConflict, "Bu bilgisayar ağın yöneticisi değil; yönetim işlemleri yönetici bilgisayardan yapılır.")
			return
		}
		next(w, r)
	}
}

// Built reports whether the Next.js panel was built into the binary.
func (s *Server) Built() bool { return s.site.built }

// Listen opens a loopback listener on port (0 picks a free port). Binding
// anywhere other than loopback is refused.
func Listen(port int) (net.Listener, error) {
	if port < 0 || port > 65535 {
		return nil, errors.New("port must be 0-65535")
	}
	return net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
}

// URL returns the panel address for a listener.
func (s *Server) URL(addr net.Addr) string {
	return fmt.Sprintf("http://%s/", addr.String())
}

// Serve runs until ctx is cancelled.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	tcp, ok := ln.Addr().(*net.TCPAddr)
	if !ok || !tcp.IP.IsLoopback() {
		return errors.New("panel must listen on a loopback address")
	}
	s.host = ln.Addr().String()
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	go s.runHistory(ctx)
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		return nil
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// Handler returns the full HTTP handler with security middleware.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	s.routes(mux)
	return s.securityHeaders(s.checkHost(s.recoverPanics(s.lockGate(s.g5Gate(mux))))) // lockGate: #661 (g6_lock.go); g5Gate: #676, #678 (g5_session.go)
}

func (s *Server) routes(mux *http.ServeMux) {
	// Admin routes need the root key's network directory on this computer.
	owner := func(h http.HandlerFunc) http.HandlerFunc { return s.requireSession(s.requireNetwork(h)) }
	// ownerCheck is a POST that changes nothing (parsing a request).
	ownerCheck := func(h http.HandlerFunc) http.HandlerFunc {
		return s.requireSession(s.requireCSRF(s.requireNetwork(h)))
	}
	ownerWrite := func(h http.HandlerFunc) http.HandlerFunc {
		return s.requireSession(s.requireCSRF(s.requireWritable(s.requireNetwork(h))))
	}
	// appWrite changes this computer through the desktop service.
	appWrite := func(h http.HandlerFunc) http.HandlerFunc {
		return s.requireSession(s.requireCSRF(s.requireWritable(s.requireApp(h))))
	}
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.requireSession(s.requireCSRF(s.handleLogout)))
	mux.HandleFunc("GET /api/session", s.requireSession(s.handleSession))
	mux.HandleFunc("GET /api/network", owner(s.handleNetwork))
	mux.HandleFunc("POST /api/network/coordinator", ownerWrite(s.handleSetCoordinator))
	mux.HandleFunc("GET /api/overview", owner(s.handleOverview))
	mux.HandleFunc("GET /api/devices", owner(s.handleDevices))
	mux.HandleFunc("POST /api/devices/inspect", ownerCheck(s.handleInspectDevice))
	mux.HandleFunc("POST /api/devices", ownerWrite(s.handleAddDevice))
	mux.HandleFunc("POST /api/devices/revoke", ownerWrite(s.handleRevokeDevice))
	mux.HandleFunc("GET /api/devices/detail", owner(s.handleDeviceDetail))
	mux.HandleFunc("POST /api/devices/exit-node", ownerWrite(s.handleSetExitNode))
	mux.HandleFunc("POST /api/devices/extend", ownerWrite(s.handleExtendDevice))
	mux.HandleFunc("POST /api/devices/expire", ownerWrite(s.handleExpireDevice))
	mux.HandleFunc("POST /api/devices/rename", ownerWrite(s.handleRenameDevice))
	mux.HandleFunc("POST /api/devices/tags", ownerWrite(s.handleDeviceTags))
	mux.HandleFunc("POST /api/devices/rotation/inspect", ownerCheck(s.handleInspectRotation))
	mux.HandleFunc("POST /api/devices/rotation", ownerWrite(s.handleApplyRotation))
	mux.HandleFunc("POST /api/groups", ownerWrite(s.handleSetGroup))
	mux.HandleFunc("POST /api/groups/remove", ownerWrite(s.handleRemoveGroup))
	mux.HandleFunc("POST /api/rules/state", ownerWrite(s.handleRuleState))
	mux.HandleFunc("POST /api/network/exit-users", ownerWrite(s.handleExitUsers))
	mux.HandleFunc("POST /api/network/dns", ownerWrite(s.handleSetDNS))
	mux.HandleFunc("POST /api/network/name", ownerWrite(s.handleSetDisplayName))
	mux.HandleFunc("GET /api/rules", owner(s.handleRules))
	mux.HandleFunc("POST /api/rules", ownerWrite(s.handleAddRule))
	mux.HandleFunc("POST /api/rules/remove", ownerWrite(s.handleRemoveRule))
	mux.HandleFunc("POST /api/rules/edit", ownerWrite(s.handleEditRule))
	mux.HandleFunc("POST /api/network/renew", ownerWrite(s.handleRenew))
	mux.HandleFunc("POST /api/security/passphrase", ownerWrite(s.handleChangePassphrase))
	mux.HandleFunc("POST /api/security/backup", ownerWrite(s.handleBackup))
	mux.HandleFunc("GET /api/history", owner(s.handleHistory))
	mux.HandleFunc("GET /api/invites", owner(s.handleInvites))
	mux.HandleFunc("POST /api/invites", ownerWrite(s.handleCreateInvite))
	mux.HandleFunc("POST /api/invites/approve", ownerWrite(s.handleApproveInvite))
	mux.HandleFunc("POST /api/invites/revoke", ownerWrite(s.handleRevokeInvite))
	mux.HandleFunc("GET /api/app/info", s.handleAppInfo)
	mux.HandleFunc("POST /api/app/ticket", s.handleTicket)
	mux.HandleFunc("GET /api/app/tray", s.handleTrayStatus)
	mux.HandleFunc("POST /api/app/tray/connect", s.handleTrayConnect)
	mux.HandleFunc("POST /api/app/tray/exit", s.handleTrayExit)
	mux.HandleFunc("POST /api/app/tray/exit/options", s.handleTrayExitOptions)
	mux.HandleFunc("POST /api/app/tray/disconnect", s.handleTrayDisconnect)
	mux.HandleFunc("POST /api/app/tray/release-on-stop", s.handleTrayReleaseOnStop)
	mux.HandleFunc("POST /api/app/pin", appWrite(s.handleAppPin))
	mux.HandleFunc("POST /api/app/reset", appWrite(s.handleAppReset))
	mux.HandleFunc("POST /api/app/exit", appWrite(s.handleAppExit))
	mux.HandleFunc("POST /api/app/exit/options", appWrite(s.handleAppExitOptions))
	mux.HandleFunc("POST /api/app/exit/leak-test", s.requireSession(s.requireCSRF(s.requireApp(s.handleAppLeakTest))))
	mux.HandleFunc("POST /api/app/exit/captive", appWrite(s.handleAppCaptive))
	mux.HandleFunc("POST /api/app/shields", appWrite(s.handleAppShields))
	mux.HandleFunc("POST /api/app/dns", appWrite(s.handleAppNetworkDNS))
	mux.HandleFunc("POST /api/app/advanced", appWrite(s.handleAppAdvanced))
	mux.HandleFunc("GET /api/app/security", s.requireSession(s.requireApp(s.handleLocalSecurity)))
	mux.HandleFunc("POST /api/app/security", appWrite(s.handleSetRemoteAccess))
	mux.HandleFunc("POST /api/app/connect", appWrite(s.handleAppConnect))
	mux.HandleFunc("GET /auth/ticket", s.handleTicketSignIn)
	mux.HandleFunc("GET /api/app/status", s.requireSession(s.requireApp(s.handleAppStatus)))
	mux.HandleFunc("POST /api/app/create", appWrite(s.handleAppCreate))
	mux.HandleFunc("POST /api/app/join", appWrite(s.handleAppJoin))
	mux.HandleFunc("POST /api/app/join/cancel", appWrite(s.handleAppCancelJoin))
	s.diagRoutes(mux)
	s.remoteRoutes(mux)
	s.membershipRoutes(mux) // ADR-0027, ADR-0028
	s.p16Routes(mux)
	s.wave2Routes(mux) // ADR-0110
	s.p17Routes(mux)   // ADR-0107: /api/v1
	s.p09Routes(mux)   // ADR-0120: rule language
	s.p10Routes(mux)   // ADR-0133: subnet routes
	s.wave3Routes(mux) // connection wave 3 (wave3_api.go)
	s.p01Routes(mux)   // ADR-0151: ledger, draft, lock (p01_api.go)
	s.p02Routes(mux)   // ADR-0156..0158: enrollment and access flows (p02_api.go)
	s.p11Routes(mux)   // ADR-0154: edge modes and hardening (p11_api.go)
	s.p12Routes(mux)   // ADR-0165: error codes, network report (p12_api.go)
	s.p07Routes(mux)   // ADR-0159, ADR-0160: sync guard, backup probe, DDNS (p07_api.go)
	// P10 platform: OS update repair, memory, limits (platform_api.go).
	s.platformRoutes(mux)
	s.w1Routes(mux)       // W1: remote desktop viewer from the panel (w1_rdesk_viewer.go)
	s.g5Routes(mux)       // ADR-0199, ADR-0203: second factor, re-authentication, SSH terminal (g5_*.go)
	s.g3Routes(mux)       // ADR-0186..0191: opsec, signed panel name (g3_api.go)
	s.g6Routes(mux)       // ADR-0204..0208: e2e files, idle lock, screen share (g6_api.go, g6_lock.go)
	s.w5Routes(mux)       // ADR-0204: drag and drop staging for e2e sending (w5_e2e_upload.go)
	s.g7Routes(mux)       // ADR-0220: blocking, plugins, monitoring (g7_api.go)
	s.g2Routes(mux)       // ADR-0180, ADR-0183: canary, sealed blob, coordinator cross-check (g2_api.go)
	s.paRoutes(mux)       // Panel-A: about, autostart, discreet name (pa_api.go)
	s.deskRoutes(mux)     // W2: tray panic (desk_session.go)
	s.g1Routes(mux)       // ADR-0172..0179: admin grants, risk, PII, sensitive, emergency (g1_api.go)
	s.f1Routes(mux)       // #629, ADR-0178: members-only documents switch (f1_members_only_api.go)
	s.f2RetireRoutes(mux) // #825: device retirement wizard (f2_retire_api.go)
	// ADR-0223: YubiKey administrator mode through the tray (ym_admin_token.go)
	s.trayAdminRoutes(mux)
	s.dnsEnforceRoutes(mux) // #717, ADR-0224: DNS zorlama anahtarı (dnsenforce_api.go)
	s.autoUpdateRoutes(mux) // ADR-0225: otomatik güncelleme kartı (autoupdate_api.go)
	s.netPlacesRoutes(mux)  // ADR-0226: ağ konumları (netplaces_api.go)
	s.p2DiagRoutes(mux)     // #835, #836, #799: arıza ayıklayıcı, uçuş kaydedici (p2_diag_api.go)
	s.f3Routes(mux)         // #855, #803, #813: SFTP gezgini, tepsi dosya istekleri (f3_sftp_api.go, f3_tray_api.go)
	s.f4aRoutes(mux)        // ADR-0232: simge, şablon, destek araçları (f4a_api.go)
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "Bulunamadı.")
	})
	mux.HandleFunc("/", s.handleStatic)
}

// isReadOnly reports whether the panel refuses changes now.
func (s *Server) isReadOnly() bool { return s.readOnly != nil && s.readOnly() }

// requireWritable refuses a change while the panel is read-only (F-180).
// The tray's own endpoints (app token, administrators only) are not
// panel changes and stay available.
func (s *Server) requireWritable(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.isReadOnly() {
			writeError(w, http.StatusForbidden, "Panel salt okunur modda; değişiklik yapılamaz. Kapatmak için yönetici olarak: openscale panel readonly off")
			return
		}
		next(w, r)
	}
}

// checkHost rejects requests whose Host header is not the panel's own
// loopback address, which defeats DNS rebinding.
func (s *Server) checkHost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.allowedHost(r.Host) {
			http.Error(w, "Geçersiz Host başlığı", http.StatusMisdirectedRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) allowedHost(host string) bool {
	if s.host == "" {
		return false
	}
	_, port, err := net.SplitHostPort(s.host)
	if err != nil {
		return false
	}
	return host == s.host || host == net.JoinHostPort("localhost", port) ||
		s.signedPanelHost(host) // ADR-0191: signed "yonetim.<domain>" name
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) recoverPanics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				s.logger.Error("panel handler panic", "path", r.URL.Path, "panic", fmt.Sprint(v))
				writeError(w, http.StatusInternalServerError, "Beklenmeyen bir hata oluştu.")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type ctxKey struct{}

func (s *Server) requireSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := s.sessionFrom(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "Oturum yok veya süresi doldu. Yeniden giriş yapın.")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, sess)))
	}
}

func (s *Server) sessionFrom(r *http.Request) (*session, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return nil, false
	}
	sess, ok := s.auth.lookup(c.Value)
	if !ok || !s.g5Check(r, c.Value, sess) { // #675, g5_session.go
		return nil, false
	}
	return sess, true
}

// requireCSRF checks the synchronizer token and the Origin header on every
// state-changing request.
func (s *Server) requireCSRF(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, _ := r.Context().Value(ctxKey{}).(*session)
		if !s.sameOrigin(r) {
			writeError(w, http.StatusForbidden, "İstek kaynağı doğrulanamadı.")
			return
		}
		token := r.Header.Get("X-CSRF-Token")
		if sess == nil || token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(sess.csrf)) != 1 {
			writeError(w, http.StatusForbidden, "Güvenlik belirteci geçersiz. Sayfayı yenile.")
			return
		}
		next(w, r)
	}
}

// sameOrigin requires the browser's Origin header to be the panel itself.
func (s *Server) sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	u, err := url.Parse(origin)
	return origin != "" && err == nil && u.Scheme == "http" && s.allowedHost(u.Host)
}

type loginRequest struct {
	Passphrase string `json:"passphrase"`
}

// handleLogin signs in with the root key passphrase. This path needs no
// session, so any local process can send wrong passphrases: failures count
// against the requesting source only (lockout.go). That process is limited
// without locking out the owner's window, signing or the tray.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		writeError(w, http.StatusForbidden, "İstek kaynağı doğrulanamadı.")
		return
	}
	source := s.loginSource(r)
	release, ok := s.auth.reserveLoginAttempt(source)
	if !ok {
		writeError(w, http.StatusTooManyRequests, "Çok fazla yanlış parola denemesi. 5 dakika sonra tekrar dene.")
		return
	}
	defer release()
	var req loginRequest
	if !decodeBody(w, r, &req) {
		return
	}
	passphrase := []byte(req.Passphrase)
	defer wipe(passphrase)
	n := s.network()
	if n == nil {
		writeError(w, http.StatusConflict, "Bu bilgisayarda yönetilen bir ağ yok. OpenScale'i tepsi simgesinden açın.")
		return
	}
	switch kind, err := signInKind(n, passphrase); { // #592 duress passphrase, desk_session.go
	case kind == admin.LoginDuress:
		s.duressSignIn(w, r, n)
		return
	case err != nil:
		s.failLogin(w, source, err)
		return
	}
	s.logger.Info("panel sign-in")
	s.finishPasswordLogin(w, r, passphrase, false) // second factor: g5_session.go
}

// startSession creates a session and sets its cookie.
func (s *Server) startSession(w http.ResponseWriter) bool {
	id, err := s.auth.create()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Oturum açılamadı.")
		return false
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	return true
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.auth.logout(c.Value)
		s.forgetWindow(c.Value) // #646
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "Yöntem desteklenmiyor", http.StatusMethodNotAllowed)
		return
	}
	if !s.site.built {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, messagePage("Panel derlenmemiş",
			"Bu openscale ikilisine panel gömülmemiş. Proje klasöründe 'pnpm --dir panel build' çalıştırıp 'go build' ile yeniden derle."))
		return
	}
	name, ok := s.site.resolve(r.URL.Path)
	if !ok {
		if nf, found := s.site.resolve("404.html"); found {
			s.site.serve(w, r, nf, http.StatusNotFound)
			return
		}
		http.NotFound(w, r)
		return
	}
	if strings.HasSuffix(name, ".html") {
		_, signedIn := s.sessionFrom(r)
		isLogin := name == loginPage
		switch {
		case !signedIn && !isLogin:
			http.Redirect(w, r, "/login/", http.StatusSeeOther)
			return
		case signedIn && isLogin:
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
	}
	s.site.serve(w, r, name, http.StatusOK)
}

// loginPage is the only HTML page served without a session.
const loginPage = "login/index.html"

// messagePage renders a minimal static page. Arguments are constant strings
// from this package, never user input.
func messagePage(title, body string) string {
	return `<!doctype html><html lang="tr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">` +
		`<title>OpenScale</title><style>body{font-family:system-ui,sans-serif;background:#f6f7f6;color:#18201d;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0;padding:16px}` +
		`main{max-width:28rem;background:#fff;border:1px solid #dfe3e1;border-radius:12px;padding:24px;line-height:1.5}h1{font-size:1.125rem;margin:0 0 8px}p{margin:0;color:#4b5752}</style></head>` +
		`<body><main><h1>` + title + `</h1><p>` + body + `</p></main></body></html>`
}
