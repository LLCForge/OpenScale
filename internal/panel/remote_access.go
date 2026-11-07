package panel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/trust"
)

// Remote panel access (ADR-0107, F-179).
//
// The owner may open the panel from another device of the network. The
// panel then also listens on this computer's tunnel address, port
// trust.PanelPort, but only while all of these hold: this computer holds
// the root key, the owner turned remote access on here (RemoteSettings),
// and the signed document has an enabled panel rule naming this device.
// Every request is checked again: the source address must be a device the
// panel rule allows. Signing in takes a separate remote password, never the
// root key passphrase, and the remote panel only reads: nothing that needs
// the root key's signature can be done from another device.

// remoteInterval is how often the conditions are checked again.
const remoteInterval = 5 * time.Second

// RemoteConfig connects the remote listener to its surroundings.
type RemoteConfig struct {
	// Dir holds RemoteSettingsFile and APIKeysFile; "" uses the network
	// directory.
	Dir string
	// Document returns the current signed document; nil uses the
	// network's.
	Document func() *trust.Document
	// Self finds this computer in doc; nil matches the local interface
	// addresses with the devices' tunnel addresses.
	Self func(doc *trust.Document) (trust.Device, bool)
	// Listen opens the tunnel listener; nil listens with TCP on addr.
	Listen func(ctx context.Context, addr netip.AddrPort) (net.Listener, error)
	// MapSource maps a connection's source address before the device
	// lookup; tests use it to stand in for tunnel addresses.
	MapSource func(netip.Addr) netip.Addr
	// Interval overrides remoteInterval.
	Interval time.Duration
}

// remoteCtxKey marks requests that came over the tunnel; the value is the
// source device's name.
type remoteCtxKey struct{}

// remoteDevice returns the source device of a remote request.
func remoteDevice(r *http.Request) (string, bool) {
	name, ok := r.Context().Value(remoteCtxKey{}).(string)
	return name, ok
}

// remoteReadPaths are the panel's API reads open to another device. The
// rest (invites with their codes, the join bundle, this computer's own
// settings, inbox and diagnostics, the tray and command line endpoints) is
// refused. /api/v1/ is added by prefix.
var remoteReadPaths = map[string]bool{
	"/api/session":        true,
	"/api/login-info":     true,
	"/api/overview":       true,
	"/api/devices":        true,
	"/api/devices/detail": true,
	"/api/rules":          true,
	"/api/map":            true,
	"/api/security/score": true,
	"/api/membership":     true,
}

// remoteAllowed reports whether a remote request may reach the panel.
func remoteAllowed(r *http.Request) bool {
	p := r.URL.Path
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		if strings.HasPrefix(p, "/api/v1/") {
			return true
		}
		if strings.HasPrefix(p, "/api/") || strings.HasPrefix(p, "/auth/") {
			return remoteReadPaths[p] || g5RemoteRead(p)
		}
		return true
	case http.MethodPost:
		return p == "/api/login" || p == "/api/logout" || g5RemotePost(p)
	}
	return false
}

// remoteInstance is one running tunnel listener.
type remoteInstance struct {
	addr   netip.AddrPort
	srv    *http.Server
	inner  *Server
	done   chan struct{}
	cancel context.CancelFunc
}

// remoteState is the listener's view of the conditions.
type remoteState struct {
	cfg RemoteConfig
	dir func() string
	// verifyMu serializes Argon2id checks (64 MiB each).
	verifyMu sync.Mutex
}

// SelfByInterfaces finds this computer in doc by its tunnel address on a
// local interface.
func SelfByInterfaces(doc *trust.Document) (trust.Device, bool) {
	addrs, err := net.InterfaceAddrs()
	if err != nil || doc == nil {
		return trust.Device{}, false
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipn.IP)
		if !ok {
			continue
		}
		if d, found := doc.DeviceByAddr(ip.Unmap()); found {
			return d, true
		}
	}
	return trust.Device{}, false
}

// ServeRemote runs the tunnel listener whenever its conditions hold, until
// ctx ends. It returns nil at once on a computer without the root key.
func (s *Server) ServeRemote(ctx context.Context, cfg RemoteConfig) error {
	if cfg.Interval <= 0 {
		cfg.Interval = remoteInterval
	}
	if cfg.Listen == nil {
		cfg.Listen = func(ctx context.Context, addr netip.AddrPort) (net.Listener, error) {
			var lc net.ListenConfig
			return lc.Listen(ctx, "tcp4", addr.String())
		}
	}
	if cfg.Self == nil {
		cfg.Self = SelfByInterfaces
	}
	st := &remoteState{cfg: cfg, dir: func() string {
		if cfg.Dir != "" {
			return cfg.Dir
		}
		if n := s.network(); n != nil {
			return n.Dir()
		}
		return ""
	}}
	var cur *remoteInstance
	lastReason := ""
	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()
	for {
		addr, reason := s.remoteWanted(st)
		if cur != nil && (reason != "" || cur.addr != addr) {
			s.stopRemote(cur)
			cur = nil
		}
		if cur == nil && reason == "" {
			inst, err := s.startRemote(ctx, st, addr)
			if err != nil {
				reason = "listen: " + err.Error()
			} else {
				cur = inst
				s.logger.Info("remote panel listening on the tunnel", "port", addr.Port())
			}
		}
		if reason != lastReason && reason != "" {
			s.logger.Debug("remote panel off", "reason", reason)
		}
		lastReason = reason
		select {
		case <-ctx.Done():
			if cur != nil {
				s.stopRemote(cur)
			}
			return nil
		case <-ticker.C:
		}
	}
}

// remoteWanted returns the listen address, or why the listener is off.
func (s *Server) remoteWanted(st *remoteState) (netip.AddrPort, string) {
	n := s.network()
	if n == nil {
		return netip.AddrPort{}, "not the admin computer"
	}
	dir := st.dir()
	if dir == "" {
		return netip.AddrPort{}, "no network directory"
	}
	set, err := LoadRemoteSettings(dir)
	if err != nil {
		return netip.AddrPort{}, err.Error()
	}
	if !set.Ready() {
		return netip.AddrPort{}, "remote access is off"
	}
	doc := st.document(s)
	if doc == nil {
		return netip.AddrPort{}, "no document"
	}
	self, ok := st.cfg.Self(doc)
	if !ok || !self.IPv4.IsValid() {
		return netip.AddrPort{}, "this computer is not in the document or the tunnel is down"
	}
	if !doc.HostsService(self.Name, trust.ServicePanel) {
		return netip.AddrPort{}, "no panel rule for this device"
	}
	return netip.AddrPortFrom(self.IPv4, trust.PanelPort), ""
}

func (st *remoteState) document(s *Server) *trust.Document {
	if st.cfg.Document != nil {
		return st.cfg.Document()
	}
	n := s.network()
	if n == nil {
		return nil
	}
	if err := n.Reload(); err != nil {
		return nil
	}
	doc, err := n.Document()
	if err != nil {
		return nil
	}
	return doc
}

// startRemote opens the listener and its own, always read-only server
// with a separate session store and failure counter.
func (s *Server) startRemote(ctx context.Context, st *remoteState, addr netip.AddrPort) (*remoteInstance, error) {
	lctx, cancel := context.WithCancel(ctx)
	ln, err := st.cfg.Listen(lctx, addr)
	if err != nil {
		cancel()
		return nil, err
	}
	inner := &Server{app: s.app, site: s.site, auth: newAuth(s.random, s.now), logger: s.logger.With("panel", "remote"),
		now: s.now, random: s.random, readOnly: func() bool { return true }}
	inner.netw.Store(s.network())
	// Host and Origin must name the tunnel address the browser used.
	inner.host = addr.String()
	mux := http.NewServeMux()
	inner.routes(mux)
	gate := &remoteGate{s: inner, st: st, outer: s, next: mux}
	srv := &http.Server{
		Handler:           inner.securityHeaders(inner.checkHost(inner.recoverPanics(gate))),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
		BaseContext:       func(net.Listener) context.Context { return lctx },
	}
	inst := &remoteInstance{addr: addr, srv: srv, inner: inner, done: make(chan struct{}), cancel: cancel}
	go func() {
		defer close(inst.done)
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.Warn("remote panel stopped", "error", err.Error())
		}
	}()
	return inst, nil
}

func (s *Server) stopRemote(inst *remoteInstance) {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = inst.srv.Shutdown(shutdownCtx)
	inst.cancel()
	<-inst.done
	s.logger.Info("remote panel stopped listening")
}

// remoteGate checks the source device and the allowed requests before the
// panel's own handlers.
type remoteGate struct {
	s     *Server // the remote, read-only server
	outer *Server
	st    *remoteState
	next  http.Handler
}

func (g *remoteGate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	dev, ok := g.source(r)
	if !ok {
		writeError(w, http.StatusForbidden, "Bu cihazın panele erişim kuralı yok.")
		return
	}
	if !remoteAllowed(r) {
		writeError(w, http.StatusForbidden, "Bu işlem uzaktan yapılamaz; yönetici bilgisayarda yapın.")
		return
	}
	r = r.WithContext(context.WithValue(r.Context(), remoteCtxKey{}, dev))
	if r.Method == http.MethodPost && r.URL.Path == "/api/login" {
		g.login(w, r, dev)
		return
	}
	g.next.ServeHTTP(w, r)
}

// source maps the connection to a device the panel rule allows.
func (g *remoteGate) source(r *http.Request) (string, bool) {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return "", false
	}
	src := ap.Addr().Unmap()
	if g.st.cfg.MapSource != nil {
		src = g.st.cfg.MapSource(src)
	}
	doc := g.st.document(g.outer)
	if doc == nil {
		return "", false
	}
	self, ok := g.st.cfg.Self(doc)
	if !ok {
		return "", false
	}
	dev, ok := doc.DeviceByAddr(src)
	if !ok || dev.Name == self.Name || !g.s.now().Before(dev.ExpiresAt) || !doc.AllowsPanel(dev.Name, self.Name) {
		g.s.logger.Warn("remote panel request refused", "source", deviceLabel(dev, ok))
		return "", false
	}
	return dev.Name, true
}

func deviceLabel(d trust.Device, ok bool) string {
	if !ok {
		return "unknown"
	}
	return d.Name
}

// login signs in with the remote password (never the root passphrase).
func (g *remoteGate) login(w http.ResponseWriter, r *http.Request, dev string) {
	s := g.s
	if !s.sameOrigin(r) {
		writeError(w, http.StatusForbidden, "İstek kaynağı doğrulanamadı.")
		return
	}
	if s.auth.passphraseLocked() {
		writeError(w, http.StatusTooManyRequests, "Çok fazla yanlış parola denemesi. 5 dakika sonra tekrar dene.")
		return
	}
	var req loginRequest
	if !decodeBody(w, r, &req) {
		return
	}
	pw := []byte(req.Passphrase)
	defer wipe(pw)
	set, err := LoadRemoteSettings(g.st.dir())
	if err != nil || !set.Ready() {
		writeError(w, http.StatusForbidden, "Uzaktan erişim kapalı.")
		return
	}
	g.st.verifyMu.Lock()
	if s.auth.passphraseLocked() {
		// Requests queued behind a failure must not keep guessing.
		g.st.verifyMu.Unlock()
		writeError(w, http.StatusTooManyRequests, "Çok fazla yanlış parola denemesi. 5 dakika sonra tekrar dene.")
		return
	}
	ok := set.Password.Verify(pw)
	g.st.verifyMu.Unlock()
	if !ok {
		s.auth.recordPassphraseFailure()
		s.logger.Warn("remote panel sign-in failed", "device", dev)
		writeError(w, http.StatusUnauthorized, "Uzak erişim parolası yanlış.")
		return
	}
	s.logger.Info("remote panel sign-in", "device", dev)
	s.finishPasswordLogin(w, r, pw, true) // second factor and context binding: g5_session.go
}

// RemoteStatus describes the remote listener's conditions for
// "openscale panel-remote status".
type RemoteStatus struct {
	Schema    int    `json:"schema"`
	Enabled   bool   `json:"enabled"`
	Password  bool   `json:"password"`
	Rule      bool   `json:"rule"`
	Device    string `json:"device,omitempty"`
	Address   string `json:"address,omitempty"`
	Reason    string `json:"reason,omitempty"`
	APIKeys   int    `json:"api_keys"`
	ChangedAt string `json:"changed_at,omitempty"`
}

// DescribeRemote reports what the listener would do with these inputs.
func DescribeRemote(dir string, doc *trust.Document, self func(*trust.Document) (trust.Device, bool)) (RemoteStatus, error) {
	set, err := LoadRemoteSettings(dir)
	if err != nil {
		return RemoteStatus{}, err
	}
	keys, err := LoadAPIKeys(dir)
	if err != nil {
		return RemoteStatus{}, err
	}
	out := RemoteStatus{Schema: 1, Enabled: set.Enabled, Password: set.Password != nil, APIKeys: len(keys)}
	if !set.ChangedAt.IsZero() {
		out.ChangedAt = set.ChangedAt.UTC().Format(time.RFC3339)
	}
	if self == nil {
		self = SelfByInterfaces
	}
	switch {
	case !set.Enabled:
		out.Reason = "uzaktan erişim kapalı (openscale panel-remote on)"
	case set.Password == nil:
		out.Reason = "uzak erişim parolası yok (openscale panel-remote password)"
	}
	if doc == nil {
		return out, nil
	}
	if d, ok := self(doc); ok {
		out.Device = d.Name
		out.Rule = doc.HostsService(d.Name, trust.ServicePanel)
		out.Address = fmt.Sprintf("http://%s/", netip.AddrPortFrom(d.IPv4, trust.PanelPort))
		if out.Reason == "" && !out.Rule {
			out.Reason = fmt.Sprintf("belgede %s cihazına panel kuralı yok (openscale rule add --from <cihaz> --to %s --service panel)", d.Name, d.Name)
		}
	} else if out.Reason == "" {
		out.Reason = "bu bilgisayar belgede bulunamadı veya tünel kapalı"
	}
	return out, nil
}
