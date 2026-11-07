package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"errors"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/openscale/openscale/internal/oidc"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/pkg/client"
)

// Timeouts and limits of the published services.
const (
	readHeaderTimeout = 10 * time.Second
	idleTimeout       = 2 * time.Minute
	maxHeaderBytes    = 64 << 10
	maxConns          = 256
	dialTimeout       = 10 * time.Second
	sniffTimeout      = 10 * time.Second
)

// Env is what the server needs from the running tunnel.
type Env struct {
	// Current returns the signed document and this device while the
	// tunnel runs.
	Current func() (*trust.Document, trust.Device, bool)
	// MapPeer maps a connection's source address to a tunnel address
	// (tests); nil keeps it.
	MapPeer func(netip.Addr) netip.Addr
	// Certificate returns the TLS certificate of this device from the
	// internal CA, or nil while there is none.
	Certificate func() *tls.Certificate
	// OIDCKey returns the signing key of an oidc service.
	OIDCKey func(service string) (*ecdsa.PrivateKey, error)
	// Links, when set, serves time-limited single file links (#460) on the
	// shared port at /l/; the peer is the requesting device's name.
	Links  LinkServer
	Logger *slog.Logger
	Now    func() time.Time
}

// LinkServer serves one link request of an identified device.
type LinkServer interface {
	ServeLink(w http.ResponseWriter, r *http.Request, peer string)
}

// linkPrefix is the path of single file links on the shared port.
const linkPrefix = "/l/"

// Server publishes the services of one configuration.
type Server struct {
	env  Env
	cfg  Config
	byNm map[string]*published

	mu    sync.Mutex
	conns map[net.Conn]func(netip.Addr) bool
}

type published struct {
	svc     Service
	handler http.Handler
	root    *os.Root
	tcpHost string
	tcpPort uint16
}

type ctxKey struct{}

// peerInfo is the authorized source of a request.
type peerInfo struct {
	doc  *trust.Document
	self trust.Device
	peer trust.Device
}

// New prepares the services of cfg. Directories are opened now; a
// missing directory is an error.
func New(cfg Config, env Env) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if env.Current == nil {
		return nil, errors.New("proxy: Current required")
	}
	if env.Logger == nil {
		env.Logger = slog.New(slog.DiscardHandler)
	}
	if env.Now == nil {
		env.Now = time.Now
	}
	if env.Certificate == nil {
		env.Certificate = func() *tls.Certificate { return nil }
	}
	s := &Server{env: env, cfg: cfg, byNm: map[string]*published{}, conns: map[net.Conn]func(netip.Addr) bool{}}
	for _, svc := range cfg.Services {
		p := &published{svc: svc}
		var err error
		switch svc.Type {
		case TypeHTTP:
			p.handler, err = s.httpProxy(svc)
		case TypeFiles:
			p.root, err = os.OpenRoot(svc.Root)
			if err == nil {
				p.handler = fileHandler(p.root, svc.Listing)
			}
		case TypeTCP:
			p.tcpHost, p.tcpPort, err = ParseTCPTarget(svc.Target)
		case TypeOIDC:
			p.handler, err = s.oidcProvider(svc)
		}
		if err != nil {
			s.Close()
			return nil, fmt.Errorf("servis %q: %w", svc.Name, err)
		}
		s.byNm[svc.Name] = p
	}
	return s, nil
}

// Close releases opened directories.
func (s *Server) Close() {
	for _, p := range s.byNm {
		if p.root != nil {
			_ = p.root.Close()
		}
	}
}

// Config returns the configuration the server publishes.
func (s *Server) Config() Config { return s.cfg }

// NeedsTLS reports whether some service wants HTTPS.
func (s *Server) NeedsTLS() bool {
	return slices.ContainsFunc(s.cfg.Services, func(v Service) bool { return v.TLS })
}

// HasShared reports whether some service (or the link server) uses the
// shared serve port.
func (s *Server) HasShared() bool {
	return s.env.Links != nil || slices.ContainsFunc(s.cfg.Services, Service.Shared)
}

// OwnPorts returns the services with their own port.
func (s *Server) OwnPorts() []Service {
	var out []Service
	for _, v := range s.cfg.Services {
		if !v.Shared() {
			out = append(out, v)
		}
	}
	return out
}

func (s *Server) mapPeer(a netip.Addr) netip.Addr {
	a = a.Unmap()
	if s.env.MapPeer != nil {
		return s.env.MapPeer(a)
	}
	return a
}

// identify maps a remote address to a current, unexpired device other
// than this one.
func (s *Server) identify(remote string) (peerInfo, bool) {
	ap, err := netip.ParseAddrPort(remote)
	if err != nil {
		return peerInfo{}, false
	}
	return s.identifyAddr(ap.Addr())
}

func (s *Server) identifyAddr(a netip.Addr) (peerInfo, bool) {
	doc, self, ok := s.env.Current()
	if !ok {
		return peerInfo{}, false
	}
	dev, ok := doc.DeviceByAddr(s.mapPeer(a))
	if !ok || dev.Name == self.Name || !s.env.Now().Before(dev.ExpiresAt) {
		return peerInfo{}, false
	}
	return peerInfo{doc: doc, self: self, peer: dev}, true
}

// reachable reports whether the rules let pi.peer reach svc at all.
func reachable(pi peerInfo, svc Service) bool {
	if svc.Shared() {
		if !pi.doc.AllowsServe(pi.peer.Name, pi.self.Name) {
			return false
		}
	} else if !pi.doc.Allows(pi.peer.Name, pi.self.Name, trust.ProtocolTCP, svc.Port) {
		return false
	}
	return len(svc.Allow) == 0 || pi.doc.MatchesEntries(svc.Allow, pi.peer.Name)
}

// Revalidate closes connections whose source lost its permission, for
// example after a rule was removed. It returns how many it closed.
func (s *Server) Revalidate() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for c, still := range s.conns {
		ap, err := netip.ParseAddrPort(c.RemoteAddr().String())
		if err != nil || !still(ap.Addr()) {
			_ = c.Close()
			delete(s.conns, c)
			n++
		}
	}
	return n
}

func (s *Server) track(c net.Conn, still func(netip.Addr) bool) {
	s.mu.Lock()
	s.conns[c] = still
	s.mu.Unlock()
}

func (s *Server) untrack(c net.Conn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
}

// dialGuard refuses backend connections to the network's own address
// ranges: a published service must never let a peer reach another
// device with this device's identity (as ADR-0030 for SSH forwarding).
func (s *Server) dialGuard(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("proxy: hedef adresi okunamadı: %w", err)
	}
	a := ap.Addr().Unmap()
	if a.IsUnspecified() || a.IsMulticast() {
		return errors.New("proxy: hedef adresi kullanılamaz")
	}
	if doc, _, ok := s.env.Current(); ok && ipInPrefixes(a, doc.IPv4Prefix, doc.IPv6Prefix) {
		return errors.New("proxy: hedef OpenScale ağının içinde olamaz")
	}
	return nil
}

func (s *Server) dialer() *net.Dialer {
	return &net.Dialer{Timeout: dialTimeout, Control: s.dialGuard}
}

// --- HTTP ---

func (s *Server) httpProxy(svc Service) (http.Handler, error) {
	target, err := ParseHTTPTarget(svc.Target)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           s.dialer().DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          32,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 2 * time.Minute,
	}
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.SetXForwarded()
			stripIdentity(pr.Out.Header)
			if pi, ok := pr.In.Context().Value(ctxKey{}).(peerInfo); ok {
				pr.Out.Header.Set(client.HeaderDevice, pi.peer.Name)
				pr.Out.Header.Set(client.HeaderFQDN, pi.peer.Name+"."+pi.doc.DNSDomain)
				pr.Out.Header.Set(client.HeaderTags, strings.Join(pi.peer.Tags, ","))
			}
		},
		Transport: tr,
		ErrorLog:  slog.NewLogLogger(slog.DiscardHandler, slog.LevelError),
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			s.env.Logger.Warn("published service backend failed", "service", svc.Name, "error", err.Error())
			http.Error(w, "Yayınlanan servise ulaşılamadı", http.StatusBadGateway)
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := cleanRequestPath(r.URL)
		if !ok {
			http.Error(w, "Geçersiz yol", http.StatusBadRequest)
			return
		}
		if !pathAllowed(svc.Paths, p) {
			http.Error(w, "Bu yola izin verilmiyor", http.StatusForbidden)
			return
		}
		if svc.ReadOnly {
			switch r.Method {
			case http.MethodGet, http.MethodHead, http.MethodOptions:
			default:
				w.Header().Set("Allow", "GET, HEAD, OPTIONS")
				http.Error(w, "Bu servis salt okunur", http.StatusMethodNotAllowed)
				return
			}
			if r.Header.Get("Upgrade") != "" {
				http.Error(w, "Bu servis salt okunur", http.StatusForbidden)
				return
			}
		}
		rp.ServeHTTP(w, r)
	}), nil
}

// stripIdentity removes every OpenScale-* header a client sent.
func stripIdentity(h http.Header) {
	for k := range h {
		if strings.HasPrefix(strings.ToLower(k), "openscale-") {
			delete(h, k)
		}
	}
}

func fileHandler(root *os.Root, listing bool) http.Handler {
	fsys := root.FS()
	fs := http.FileServerFS(fsys)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "Yalnızca okuma", http.StatusMethodNotAllowed)
			return
		}
		p, ok := cleanRequestPath(r.URL)
		if !ok {
			http.Error(w, "Geçersiz yol", http.StatusBadRequest)
			return
		}
		for _, seg := range strings.Split(p, "/") {
			if strings.HasPrefix(seg, ".") {
				http.NotFound(w, r) // hidden files (.git, .env) stay hidden
				return
			}
		}
		if !listing {
			name := strings.Trim(p, "/")
			if name == "" {
				name = "."
			}
			if st, err := root.Stat(name); err == nil && st.IsDir() {
				if _, err := root.Stat(path.Join(name, "index.html")); err != nil {
					http.NotFound(w, r)
					return
				}
			}
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		fs.ServeHTTP(w, r)
	})
}

func (s *Server) oidcProvider(svc Service) (http.Handler, error) {
	if s.env.OIDCKey == nil {
		return nil, errors.New("kimlik sağlayıcı anahtarı yok")
	}
	key, err := s.env.OIDCKey(svc.Name)
	if err != nil {
		return nil, err
	}
	clients := make([]oidc.Client, 0, len(svc.Clients))
	for _, c := range svc.Clients {
		clients = append(clients, oidc.Client{ID: c.ID, SecretSHA256: c.SecretSHA256, RedirectURIs: slices.Clone(c.RedirectURIs)})
	}
	return oidc.New(oidc.Config{
		Issuer:  func() string { return s.IssuerURL(svc) },
		Clients: clients,
		Key:     key,
		Identity: func(r *http.Request) (oidc.Subject, bool) {
			pi, ok := r.Context().Value(ctxKey{}).(peerInfo)
			if !ok {
				return oidc.Subject{}, false
			}
			return oidc.Subject{ID: pi.peer.ID, Name: pi.peer.Name, FQDN: pi.peer.Name + "." + pi.doc.DNSDomain, Tags: slices.Clone(pi.peer.Tags)}, true
		},
		Now:    s.env.Now,
		Logger: s.env.Logger.With("service", svc.Name),
	})
}

// ServiceHost returns the MagicDNS name of a service.
func ServiceHost(svc Service, self trust.Device, domain string) string {
	return svc.Name + "." + self.Name + "." + domain
}

// URL returns the address of a service as other devices open it.
func URL(svc Service, self trust.Device, domain string) string {
	scheme := "http"
	if svc.TLS {
		scheme = "https"
	}
	port := trust.ServePort
	if !svc.Shared() {
		port = svc.Port
	}
	return scheme + "://" + net.JoinHostPort(ServiceHost(svc, self, domain), strconv.Itoa(int(port)))
}

// IssuerURL is the issuer of an oidc service.
func (s *Server) IssuerURL(svc Service) string {
	doc, self, ok := s.env.Current()
	if !ok {
		return ""
	}
	return URL(svc, self, doc.DNSDomain)
}

// hostName returns the lowercase host of a Host header without port and
// trailing dot.
func hostName(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.TrimSuffix(strings.ToLower(strings.Trim(h, "[]")), ".")
	return h
}

// selfLabels are the MagicDNS labels of this device.
func selfLabels(self trust.Device) []string { return append([]string{self.Name}, self.Aliases...) }

// isSelfHost reports whether host names this device itself.
func isSelfHost(host string, doc *trust.Document, self trust.Device) bool {
	for _, l := range selfLabels(self) {
		if host == l+"."+doc.DNSDomain {
			return true
		}
	}
	if a, err := netip.ParseAddr(host); err == nil {
		a = a.Unmap()
		return a == self.IPv4 || a == self.IPv6
	}
	return false
}

// serviceForHost returns the service named by host on this device.
func serviceForHost(host string, doc *trust.Document, self trust.Device) (string, bool) {
	for _, l := range selfLabels(self) {
		if name, ok := strings.CutSuffix(host, "."+l+"."+doc.DNSDomain); ok && ValidName(name) {
			return name, true
		}
	}
	return "", false
}

// serveService authorizes and serves one request of p.
func (s *Server) serveService(w http.ResponseWriter, r *http.Request, p *published) {
	pi, ok := s.identify(r.RemoteAddr)
	if !ok || !reachable(pi, p.svc) {
		http.Error(w, "Bu cihazın bu servise erişim izni yok", http.StatusForbidden)
		return
	}
	if p.svc.TLS && r.TLS == nil {
		if s.env.Certificate() == nil {
			http.Error(w, "Servis HTTPS ister ama iç CA sertifikası henüz yok", http.StatusServiceUnavailable)
			return
		}
		u := url.URL{Scheme: "https", Host: r.Host, Path: r.URL.Path, RawPath: r.URL.RawPath, RawQuery: r.URL.RawQuery}
		http.Redirect(w, r, u.String(), http.StatusPermanentRedirect)
		return
	}
	p.handler.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, pi)))
}

// sharedHandler routes the shared serve port by Host.
func (s *Server) sharedHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc, self, ok := s.env.Current()
		if !ok {
			http.Error(w, "Tünel kapalı", http.StatusServiceUnavailable)
			return
		}
		host := hostName(r.Host)
		if name, ok := serviceForHost(host, doc, self); ok {
			if p := s.byNm[name]; p != nil && p.svc.Shared() && p.svc.HTTPLike() {
				s.serveService(w, r, p)
				return
			}
			http.Error(w, "Bu adla yayınlanan bir servis yok", http.StatusNotFound)
			return
		}
		if isSelfHost(host, doc, self) && r.URL.Path == "/" {
			s.index(w, r)
			return
		}
		if isSelfHost(host, doc, self) && s.env.Links != nil && strings.HasPrefix(r.URL.Path, linkPrefix) {
			pi, ok := s.identify(r.RemoteAddr)
			if !ok || !pi.doc.AllowsServe(pi.peer.Name, pi.self.Name) {
				http.Error(w, "Bu cihazın bu servise erişim izni yok", http.StatusForbidden)
				return
			}
			s.env.Links.ServeLink(w, r, pi.peer.Name)
			return
		}
		// Any other Host (DNS rebinding) is refused.
		http.Error(w, "Bilinmeyen ad", http.StatusMisdirectedRequest)
	})
}

// ownHandler serves one service on its own port.
func (s *Server) ownHandler(p *published) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc, self, ok := s.env.Current()
		if !ok {
			http.Error(w, "Tünel kapalı", http.StatusServiceUnavailable)
			return
		}
		host := hostName(r.Host)
		name, isSvc := serviceForHost(host, doc, self)
		if !(isSvc && name == p.svc.Name) && !isSelfHost(host, doc, self) {
			http.Error(w, "Bilinmeyen ad", http.StatusMisdirectedRequest)
			return
		}
		s.serveService(w, r, p)
	})
}

// index lists the services the caller may use on the shared port.
func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	pi, ok := s.identify(r.RemoteAddr)
	if !ok || !pi.doc.AllowsServe(pi.peer.Name, pi.self.Name) {
		http.Error(w, "Bu cihazın bu servise erişim izni yok", http.StatusForbidden)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", "default-src 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
	var b strings.Builder
	b.WriteString("<!doctype html><meta charset=utf-8><title>OpenScale servisleri</title><h1>")
	b.WriteString(html.EscapeString(pi.self.Name))
	b.WriteString("</h1><ul>")
	for _, v := range s.cfg.Services {
		if !v.HTTPLike() || !reachable(pi, v) {
			continue
		}
		u := URL(v, pi.self, pi.doc.DNSDomain)
		b.WriteString(`<li><a href="` + html.EscapeString(u) + `">` + html.EscapeString(v.Name) + "</a> (" + html.EscapeString(v.Type) + ")</li>")
	}
	b.WriteString("</ul>")
	_, _ = io.WriteString(w, b.String())
}

func (s *Server) httpServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(slog.DiscardHandler, slog.LevelError),
	}
}

func (s *Server) tlsConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			if c := s.env.Certificate(); c != nil {
				return c, nil
			}
			return nil, errors.New("iç CA sertifikası yok")
		},
	}
}

// serveHTTP runs an HTTP server on ln, accepting TLS and plain HTTP on
// the same port; still decides whether an open connection may stay.
func (s *Server) serveHTTP(ctx context.Context, ln net.Listener, h http.Handler, still func(netip.Addr) bool) error {
	sl := newSniffListener(ctx, ln, s.tlsConfig(), func() bool { return s.env.Certificate() != nil }, func(c net.Conn) bool {
		ap, err := netip.ParseAddrPort(c.RemoteAddr().String())
		return err == nil && still(ap.Addr())
	})
	srv := s.httpServer(h)
	srv.ConnState = func(c net.Conn, st http.ConnState) {
		switch st {
		case http.StateNew:
			s.track(c, still)
		case http.StateClosed, http.StateHijacked:
			s.untrack(c)
		}
	}
	stop := context.AfterFunc(ctx, func() { _ = srv.Close() })
	defer stop()
	err := srv.Serve(sl)
	if errors.Is(err, http.ErrServerClosed) || ctx.Err() != nil {
		return nil
	}
	return err
}

// ServeShared serves the shared serve port on ln.
func (s *Server) ServeShared(ctx context.Context, ln net.Listener) error {
	return s.serveHTTP(ctx, ln, s.sharedHandler(), func(a netip.Addr) bool {
		pi, ok := s.identifyAddr(a)
		return ok && pi.doc.AllowsServe(pi.peer.Name, pi.self.Name)
	})
}

// ServeOwn serves the named service on its own port.
func (s *Server) ServeOwn(ctx context.Context, ln net.Listener, name string) error {
	p := s.byNm[name]
	if p == nil || p.svc.Shared() {
		return fmt.Errorf("proxy: %q kendi portunda yayınlanan bir servis değil", name)
	}
	still := func(a netip.Addr) bool {
		pi, ok := s.identifyAddr(a)
		return ok && reachable(pi, p.svc)
	}
	if p.svc.Type == TypeTCP {
		return s.serveTCP(ctx, ln, p, still)
	}
	return s.serveHTTP(ctx, ln, s.ownHandler(p), still)
}

func (s *Server) serveTCP(ctx context.Context, ln net.Listener, p *published, still func(netip.Addr) bool) error {
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()
	sem := make(chan struct{}, maxConns)
	var wg sync.WaitGroup
	defer wg.Wait()
	target := net.JoinHostPort(p.tcpHost, strconv.Itoa(int(p.tcpPort)))
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		ap, err := netip.ParseAddrPort(c.RemoteAddr().String())
		if err != nil || !still(ap.Addr()) {
			_ = c.Close()
			continue
		}
		select {
		case sem <- struct{}{}:
		default:
			_ = c.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			s.track(c, still)
			defer s.untrack(c)
			s.pipe(ctx, c, target, p.svc.Name)
		}()
	}
}

func (s *Server) pipe(ctx context.Context, c net.Conn, target, name string) {
	defer c.Close()
	up, err := s.dialer().DialContext(ctx, "tcp", target)
	if err != nil {
		s.env.Logger.Warn("published tcp backend failed", "service", name, "error", err.Error())
		return
	}
	defer up.Close()
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if tc, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite()
		} else {
			_ = dst.Close()
		}
		done <- struct{}{}
	}
	go cp(up, c)
	go cp(c, up)
	select {
	case <-done:
		<-done
	case <-ctx.Done():
	}
}
