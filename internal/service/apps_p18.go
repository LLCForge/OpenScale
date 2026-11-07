//go:build !openscale_noservices

package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/pki"
	"github.com/openscale/openscale/internal/proxy"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

// Tunnel services (Faz 6): publishing local services inside the tunnel
// (ADR-0139), the internal CA's issuer and TLS certificates (ADR-0138)
// and the identity provider (ADR-0140). Like the other services they
// listen only on this device's tunnel address and only while the signed
// document has a rule for them.

// Files under the apps directory.
const (
	ServeDir      = "serve"
	InternalCADir = "internal-ca"
	CAKeyFile     = "ca.key"
	CACertFile    = "ca.crt"
	tlsKeyFile    = "tls.key"
	tlsCertFile   = "tls.crt"
	oidcKeyFile   = "oidc.key"
	maxKeyFile    = 64 << 10
	certRetryMin  = time.Minute
	certRetryMax  = 30 * time.Minute
	runnerShared  = "serve"
	runnerIssuer  = "cert"
	runnerOwnPfx  = "serve:"
)

// p18State is the tunnel services' part of Apps.
type p18State struct {
	mu       sync.Mutex
	loaded   bool
	stamp    string
	gen      uint64
	srv      *proxy.Server
	cfgErr   string
	runners  map[string]*p18Runner
	version  uint64
	cert     *tls.Certificate
	certKey  string
	certTry  time.Time
	certWait time.Duration
	certErr  string
	ca       *pki.CA
	caDER    []byte
}

type p18Runner struct {
	addr    netip.AddrPort
	bound   netip.AddrPort
	gen     uint64
	cancel  context.CancelFunc
	done    chan struct{}
	retryAt time.Time
	err     string
}

// ServeConfigPath is the publishing configuration of a data or state
// directory.
func ServeConfigPath(dir string) string {
	return filepath.Join(dir, AppsDir, proxy.ConfigFile)
}

// LoadServeConfig reads the publishing configuration; a missing file is an
// empty configuration.
func LoadServeConfig(dir string) (proxy.Config, error) {
	b, err := securefile.ReadLimited(ServeConfigPath(dir), proxy.MaxConfigSize)
	if errors.Is(err, fs.ErrNotExist) {
		return proxy.Config{Schema: proxy.ConfigSchema, Services: []proxy.Service{}}, nil
	}
	if err != nil {
		return proxy.Config{}, err
	}
	return proxy.ParseConfig(b)
}

// SaveServeConfig writes the publishing configuration; the running
// service picks it up within seconds.
func SaveServeConfig(dir string, c proxy.Config) error {
	b, err := c.Encode()
	if err != nil {
		return err
	}
	return securefile.Replace(ServeConfigPath(dir), b)
}

// CAKeyPath and CACertPath are the internal CA's files on its issuer.
func CAKeyPath(dir string) string  { return filepath.Join(dir, AppsDir, InternalCADir, CAKeyFile) }
func CACertPath(dir string) string { return filepath.Join(dir, AppsDir, InternalCADir, CACertFile) }

func (a *Apps) p18() *p18State {
	s := &a.p18State
	s.mu.Lock()
	if s.runners == nil {
		s.runners = map[string]*p18Runner{}
	}
	s.mu.Unlock()
	return s
}

// runP18 keeps the tunnel services in line with the document and the
// local configuration until ctx ends.
func (a *Apps) runP18(ctx context.Context) {
	st := a.p18()
	t := time.NewTicker(a.cfg.Interval)
	defer t.Stop()
	for {
		a.syncP18(ctx, st)
		select {
		case <-ctx.Done():
			a.stopP18(st, "")
			st.mu.Lock()
			if st.srv != nil {
				st.srv.Close()
				st.srv = nil
			}
			st.mu.Unlock()
			return
		case <-t.C:
		}
	}
}

func (a *Apps) syncP18(ctx context.Context, st *p18State) {
	a.reloadServe(st)
	doc, self, ok := a.current()
	want := map[string]netip.AddrPort{}
	st.mu.Lock()
	srv := st.srv
	gen := st.gen
	st.mu.Unlock()
	if ok {
		host := self.IPv4
		if a.listenHost.IsValid() {
			host = a.listenHost
		}
		port := func(p uint16) uint16 {
			if a.anyPort {
				return 0
			}
			return p
		}
		if srv != nil && srv.HasShared() && doc.HostsService(self.Name, trust.ServiceServe) {
			want[runnerShared] = netip.AddrPortFrom(host, port(trust.ServePort))
		}
		if srv != nil {
			for _, svc := range srv.OwnPorts() {
				if portReachable(doc, self.Name, svc.Port) {
					want[runnerOwnPfx+svc.Name] = netip.AddrPortFrom(host, port(svc.Port))
				}
			}
		}
		if ca := doc.InternalCA; ca != nil && ca.Issuer == self.Name && doc.HostsService(self.Name, trust.ServiceCert) {
			if _, err := a.loadCA(st, doc); err == nil {
				want[runnerIssuer] = netip.AddrPortFrom(host, port(trust.CertPort))
			} else {
				st.mu.Lock()
				st.certErr = "iç CA anahtarı: " + err.Error()
				st.mu.Unlock()
			}
		}
	}
	a.reconcileP18(ctx, st, want, gen, srv)
	if !ok {
		return
	}
	st.mu.Lock()
	changed := doc.Version != st.version
	st.version = doc.Version
	st.mu.Unlock()
	if changed && srv != nil {
		if n := srv.Revalidate(); n > 0 {
			a.log.Info("published service connections closed after a rule change", "count", n)
		}
	}
	if srv != nil && srv.NeedsTLS() {
		a.ensureCert(ctx, st, doc, self)
	}
}

// portReachable reports whether some device may reach port on name.
func portReachable(doc *trust.Document, name string, port uint16) bool {
	for _, d := range doc.Devices {
		if d.Name != name && doc.Allows(d.Name, name, trust.ProtocolTCP, port) {
			return true
		}
	}
	return false
}

// reloadServe rebuilds the server when serve.json changed.
func (a *Apps) reloadServe(st *p18State) {
	path := ServeConfigPath(a.cfg.Dir)
	stamp := ""
	if fi, err := os.Stat(path); err == nil {
		stamp = fmt.Sprintf("%d/%d", fi.ModTime().UnixNano(), fi.Size())
	}
	// Live single file links (#460) also need the shared serve port.
	links := a.linksForServe()
	if links != nil {
		stamp += "+links"
	}
	st.mu.Lock()
	same := st.loaded && stamp == st.stamp
	st.mu.Unlock()
	if same {
		return
	}
	var srv *proxy.Server
	var cfgErr string
	if stamp != "" {
		cfg := proxy.Config{Schema: proxy.ConfigSchema}
		var err error
		if _, serr := os.Stat(path); serr == nil {
			cfg, err = LoadServeConfig(a.cfg.Dir)
		}
		if err == nil && (len(cfg.Services) > 0 || links != nil) {
			env := proxy.Env{
				Current:     a.current,
				MapPeer:     a.mapPeer,
				Certificate: func() *tls.Certificate { return a.currentCert(st) },
				OIDCKey:     a.oidcKey,
				Logger:      a.log.With("service", "serve"),
				Now:         a.cfg.Now,
			}
			if links != nil {
				env.Links = links
			}
			srv, err = proxy.New(cfg, env)
		}
		if err != nil {
			cfgErr = err.Error()
			a.log.Warn("publishing configuration rejected", "error", cfgErr)
		}
	}
	st.mu.Lock()
	old := st.srv
	st.srv, st.cfgErr, st.stamp, st.loaded = srv, cfgErr, stamp, true
	st.gen++
	st.mu.Unlock()
	if old != nil {
		a.stopP18(st, runnerIssuer)
		old.Close()
	}
}

// stopP18 stops every runner except keep.
func (a *Apps) stopP18(st *p18State, keep string) {
	st.mu.Lock()
	var waits []chan struct{}
	for k, r := range st.runners {
		if k == keep || r.cancel == nil {
			continue
		}
		r.cancel()
		waits = append(waits, r.done)
		r.cancel = nil
	}
	st.mu.Unlock()
	for _, d := range waits {
		<-d
	}
}

func (a *Apps) reconcileP18(ctx context.Context, st *p18State, want map[string]netip.AddrPort, gen uint64, srv *proxy.Server) {
	st.mu.Lock()
	var stops []chan struct{}
	for k, r := range st.runners {
		if r.cancel != nil {
			select {
			case <-r.done:
				r.cancel = nil
				r.retryAt = a.cfg.Now().Add(appsRetryDelay)
			default:
			}
		}
		addr, ok := want[k]
		if r.cancel != nil && (!ok || addr != r.addr || (k != runnerIssuer && r.gen != gen)) {
			r.cancel()
			stops = append(stops, r.done)
			r.cancel = nil
			a.log.Info("tunnel service stopped", "service", k)
		}
		if !ok {
			r.err, r.retryAt = "", time.Time{}
		}
	}
	st.mu.Unlock()
	for _, d := range stops {
		<-d
	}
	for k, addr := range want {
		st.mu.Lock()
		r := st.runners[k]
		if r == nil {
			r = &p18Runner{}
			st.runners[k] = r
		}
		skip := r.cancel != nil || a.cfg.Now().Before(r.retryAt)
		st.mu.Unlock()
		if skip {
			continue
		}
		cancel, done, bound, err := a.startP18(ctx, st, k, addr, srv)
		st.mu.Lock()
		if err != nil {
			r.err, r.retryAt = err.Error(), a.cfg.Now().Add(appsRetryDelay)
			st.mu.Unlock()
			a.log.Warn("tunnel service could not start", "service", k, "error", err.Error())
			continue
		}
		r.addr, r.bound, r.gen, r.cancel, r.done, r.err = addr, bound, gen, cancel, done, ""
		st.mu.Unlock()
		a.log.Info("tunnel service listening", "service", k)
	}
}

func (a *Apps) startP18(ctx context.Context, st *p18State, key string, addr netip.AddrPort, srv *proxy.Server) (context.CancelFunc, chan struct{}, netip.AddrPort, error) {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", addr.String())
	if err != nil {
		return nil, nil, netip.AddrPort{}, fmt.Errorf("tünel adresi dinlenemedi: %w", err)
	}
	bound := addr
	if ta, ok := ln.Addr().(*net.TCPAddr); ok {
		bound = netip.AddrPortFrom(ta.AddrPort().Addr().Unmap(), ta.AddrPort().Port())
	}
	sctx, cancel := context.WithCancel(ctx)
	var serve func() error
	switch {
	case key == runnerShared && srv != nil:
		serve = func() error { return srv.ServeShared(sctx, ln) }
	case strings.HasPrefix(key, runnerOwnPfx) && srv != nil:
		name := strings.TrimPrefix(key, runnerOwnPfx)
		serve = func() error { return srv.ServeOwn(sctx, ln, name) }
	case key == runnerIssuer:
		iss := pki.NewIssuer(pki.IssuerConfig{
			Authorize: a.authorizeCert,
			CA: func() (*pki.CA, error) {
				doc, _, ok := a.current()
				if !ok {
					return nil, errNoTunnel()
				}
				return a.loadCA(st, doc)
			},
			Now:    a.cfg.Now,
			Logger: a.log.With("service", "cert"),
		})
		serve = func() error { return iss.Serve(sctx, ln) }
	default:
		_ = ln.Close()
		cancel()
		return nil, nil, netip.AddrPort{}, fmt.Errorf("bilinmeyen tünel servisi %q", key)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer ln.Close()
		if err := serve(); err != nil && sctx.Err() == nil {
			a.log.Warn("tunnel service stopped with an error", "service", key, "error", err.Error())
		}
	}()
	return cancel, done, bound, nil
}

// authorizeCert decides a certificate request by its tunnel source.
func (a *Apps) authorizeCert(remote netip.Addr) (pki.Grant, bool) {
	doc, _, dev, ok := a.peer(remote)
	if !ok || !a.cfg.Now().Before(dev.ExpiresAt) || !doc.AllowsCertRequest(dev.Name) {
		return pki.Grant{}, false
	}
	dns, ips, ok := doc.CertNames(dev.Name)
	if !ok {
		return pki.Grant{}, false
	}
	return pki.Grant{Device: dev.Name, DNS: dns, IPs: ips, Lifetime: doc.InternalCA.Lifetime()}, true
}

// loadCA loads the CA key matching the pinned certificate.
func (a *Apps) loadCA(st *p18State, doc *trust.Document) (*pki.CA, error) {
	if doc.InternalCA == nil {
		return nil, errors.New("ağda iç CA yok")
	}
	st.mu.Lock()
	if st.ca != nil && slices.Equal(st.caDER, doc.InternalCA.Certificate) {
		ca := st.ca
		st.mu.Unlock()
		return ca, nil
	}
	st.mu.Unlock()
	keyPEM, err := securefile.ReadPrivate(CAKeyPath(a.cfg.Dir), maxKeyFile)
	if err != nil {
		return nil, err
	}
	ca, err := pki.LoadCA(doc.InternalCA.Certificate, keyPEM)
	if err != nil {
		return nil, err
	}
	st.mu.Lock()
	st.ca, st.caDER = ca, slices.Clone(doc.InternalCA.Certificate)
	st.mu.Unlock()
	return ca, nil
}

func (a *Apps) currentCert(st *p18State) *tls.Certificate {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.cert
}

// certKey identifies what a certificate must cover.
func certKeyFor(doc *trust.Document, self trust.Device) string {
	dns, ips, _ := doc.CertNames(self.Name)
	var b strings.Builder
	b.WriteString(pki.Fingerprint(doc.InternalCA.Certificate))
	for _, n := range dns {
		b.WriteString("|" + n)
	}
	for _, ip := range ips {
		b.WriteString("|" + ip.String())
	}
	return b.String()
}

// fresh reports whether c covers key and has more than a third of its
// lifetime left.
func freshCert(c *tls.Certificate, now time.Time) bool {
	if c == nil || c.Leaf == nil {
		return false
	}
	life := c.Leaf.NotAfter.Sub(c.Leaf.NotBefore)
	return now.Before(c.Leaf.NotAfter.Add(-life / 3))
}

// ensureCert keeps a certificate of this device from the internal CA.
func (a *Apps) ensureCert(ctx context.Context, st *p18State, doc *trust.Document, self trust.Device) {
	now := a.cfg.Now()
	if doc.InternalCA == nil {
		st.mu.Lock()
		st.cert, st.certKey, st.certErr = nil, "", "ağda iç CA yok; HTTPS servisleri sertifikasız"
		st.mu.Unlock()
		return
	}
	want := certKeyFor(doc, self)
	st.mu.Lock()
	if st.certKey == want && freshCert(st.cert, now) {
		st.mu.Unlock()
		return
	}
	if now.Before(st.certTry) {
		st.mu.Unlock()
		return
	}
	st.mu.Unlock()
	dir := filepath.Join(a.cfg.Dir, AppsDir, ServeDir)
	if c := loadCertFiles(dir, doc, self, now); c != nil && freshCert(c, now) {
		st.mu.Lock()
		st.cert, st.certKey, st.certErr, st.certWait = c, want, "", 0
		st.mu.Unlock()
		return
	}
	c, err := a.obtainCert(ctx, st, doc, self, dir, now)
	st.mu.Lock()
	defer st.mu.Unlock()
	if err != nil {
		st.certWait = min(max(st.certWait*2, certRetryMin), certRetryMax)
		st.certTry = now.Add(st.certWait)
		st.certErr = err.Error()
		a.log.Warn("TLS certificate not obtained", "error", err.Error())
		return
	}
	st.cert, st.certKey, st.certErr, st.certWait, st.certTry = c, want, "", 0, time.Time{}
	a.log.Info("TLS certificate obtained from the internal CA", "not_after", c.Leaf.NotAfter.UTC().Format(time.RFC3339))
}

// loadCertFiles reads a stored certificate if it still matches the
// pinned CA and this device's names.
func loadCertFiles(dir string, doc *trust.Document, self trust.Device, now time.Time) *tls.Certificate {
	keyPEM, err := securefile.ReadPrivate(filepath.Join(dir, tlsKeyFile), maxKeyFile)
	if err != nil {
		return nil
	}
	certPEM, err := securefile.ReadLimited(filepath.Join(dir, tlsCertFile), maxKeyFile)
	if err != nil {
		return nil
	}
	key, err := pki.ParseKeyPEM(keyPEM)
	if err != nil {
		return nil
	}
	certs, err := pki.ParseCertsPEM(certPEM)
	if err != nil {
		return nil
	}
	return buildCert(key, certs[0].Raw, doc, self, now)
}

// buildCert checks leaf against the pinned CA and this device's names.
func buildCert(key *ecdsa.PrivateKey, leafDER []byte, doc *trust.Document, self trust.Device, now time.Time) *tls.Certificate {
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil
	}
	caCert, err := doc.InternalCA.ParsedCertificate()
	if err != nil || pki.VerifyLeaf(leaf, caCert, now) != nil {
		return nil
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil
	}
	dns, ips, _ := doc.CertNames(self.Name)
	if !slices.Equal(leaf.DNSNames, dns) || len(leaf.IPAddresses) != len(ips) {
		return nil
	}
	return &tls.Certificate{Certificate: [][]byte{leafDER, caCert.Raw}, PrivateKey: key, Leaf: leaf}
}

func (a *Apps) obtainCert(ctx context.Context, st *p18State, doc *trust.Document, self trust.Device, dir string, now time.Time) (*tls.Certificate, error) {
	key, err := pki.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	var leafDER []byte
	if doc.InternalCA.Issuer == self.Name {
		ca, err := a.loadCA(st, doc)
		if err != nil {
			return nil, err
		}
		dns, ips, _ := doc.CertNames(self.Name)
		if leafDER, err = ca.Issue(&key.PublicKey, dns, ips, now, doc.InternalCA.Lifetime()); err != nil {
			return nil, err
		}
	} else {
		issuer, ok := doc.DeviceByName(doc.InternalCA.Issuer)
		if !ok || !issuer.IPv4.IsValid() {
			return nil, errors.New("iç CA dağıtıcısı belgede yok")
		}
		rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		leafDER, err = pki.Request(rctx, netip.AddrPortFrom(issuer.IPv4, trust.CertPort), self.IPv4, key, doc.InternalCA.Certificate, now)
		if err != nil {
			return nil, err
		}
	}
	c := buildCert(key, leafDER, doc, self, now)
	if c == nil {
		return nil, errors.New("alınan sertifika bu cihazın adlarını kapsamıyor")
	}
	keyPEM, err := pki.KeyPEM(key)
	if err != nil {
		return nil, err
	}
	if err := securefile.Replace(filepath.Join(dir, tlsKeyFile), keyPEM); err != nil {
		return nil, err
	}
	if err := securefile.Replace(filepath.Join(dir, tlsCertFile), pki.CertPEM(c.Certificate...)); err != nil {
		return nil, err
	}
	return c, nil
}

// oidcKey loads or creates the signing key of an identity provider.
func (a *Apps) oidcKey(service string) (*ecdsa.PrivateKey, error) {
	if !proxy.ValidName(service) {
		return nil, errors.New("geçersiz servis adı")
	}
	path := filepath.Join(a.cfg.Dir, AppsDir, ServeDir, service, oidcKeyFile)
	if b, err := securefile.ReadPrivate(path, maxKeyFile); err == nil {
		return pki.ParseKeyPEM(b)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	key, err := pki.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	b, err := pki.KeyPEM(key)
	if err != nil {
		return nil, err
	}
	if err := securefile.WriteNew(path, b); err != nil {
		return nil, err
	}
	return key, nil
}

// TunnelServicesStatus is a summary for the command line.
type TunnelServicesStatus struct {
	ConfigError string            `json:"config_error,omitempty"`
	Listening   []string          `json:"listening"`
	Errors      map[string]string `json:"errors,omitempty"`
	CertError   string            `json:"cert_error,omitempty"`
	CertUntil   *time.Time        `json:"cert_until,omitempty"`
}

// TunnelServices returns the state of the tunnel services.
func (a *Apps) TunnelServices() TunnelServicesStatus {
	st := a.p18()
	st.mu.Lock()
	defer st.mu.Unlock()
	out := TunnelServicesStatus{ConfigError: st.cfgErr, CertError: st.certErr, Listening: []string{}, Errors: map[string]string{}}
	for k, r := range st.runners {
		if r.cancel != nil {
			out.Listening = append(out.Listening, k)
		}
		if r.err != "" {
			out.Errors[k] = r.err
		}
	}
	slices.Sort(out.Listening)
	if st.cert != nil && st.cert.Leaf != nil {
		t := st.cert.Leaf.NotAfter
		out.CertUntil = &t
	}
	return out
}
