package pki

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

// Certificate requests over the tunnel (ADR-0138).
//
// The issuer listens on its tunnel address (trust.CertPort) and answers
// POST /v1/cert with a DER certificate request in the body. It finds the
// requesting device from the TCP source address only and certifies the
// names the network document gives that device; the names in the request
// are ignored. The answer is the PEM chain: the new certificate, then the
// CA certificate. There is no TLS on this port: WireGuard already
// encrypts and authenticates the source.

// CertPath is the issuer's request path.
const CertPath = "/v1/cert"

const (
	issuerReadTimeout = 10 * time.Second
	maxChainReply     = 32 << 10
	// rate limits: per device and for the whole issuer.
	perDeviceWindow = time.Hour
	perDeviceMax    = 12
	globalMax       = 240
	maxTracked      = 1024
)

// Grant is what the issuer may certify for a request.
type Grant struct {
	Device   string
	DNS      []string
	IPs      []netip.Addr
	Lifetime time.Duration
}

// IssuerConfig configures the issuer.
type IssuerConfig struct {
	// Authorize maps the TCP source address to a grant; false refuses.
	Authorize func(remote netip.Addr) (Grant, bool)
	// CA returns the loaded CA; an error answers 503.
	CA     func() (*CA, error)
	Now    func() time.Time
	Logger *slog.Logger
}

// Issuer answers certificate requests.
type Issuer struct {
	cfg IssuerConfig
	mu  sync.Mutex
	// seen holds recent issue times per device and for everyone.
	seen map[string][]time.Time
	all  []time.Time
}

// NewIssuer returns an issuer.
func NewIssuer(cfg IssuerConfig) *Issuer {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	return &Issuer{cfg: cfg, seen: map[string][]time.Time{}}
}

// allow applies the rate limits and records the issue.
func (s *Issuer) allow(device string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	cut := now.Add(-perDeviceWindow)
	prune := func(ts []time.Time) []time.Time {
		i := 0
		for i < len(ts) && !ts[i].After(cut) {
			i++
		}
		return ts[i:]
	}
	s.all = prune(s.all)
	ts := prune(s.seen[device])
	if len(ts) == 0 {
		delete(s.seen, device)
	}
	if len(ts) >= perDeviceMax || len(s.all) >= globalMax {
		return false
	}
	if len(s.seen) >= maxTracked {
		for k, v := range s.seen {
			if len(prune(v)) == 0 {
				delete(s.seen, k)
			}
		}
		if len(s.seen) >= maxTracked {
			return false
		}
	}
	s.seen[device] = append(ts, now)
	s.all = append(s.all, now)
	return true
}

// ServeHTTP implements the request endpoint.
func (s *Issuer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Path != CertPath {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "yalnızca POST", http.StatusMethodNotAllowed)
		return
	}
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		http.Error(w, "kaynak adresi okunamadı", http.StatusForbidden)
		return
	}
	g, ok := s.cfg.Authorize(ap.Addr().Unmap())
	if !ok {
		http.Error(w, "bu cihaz sertifika isteyemez (cert kuralı yok)", http.StatusForbidden)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxCSRSize+1))
	if err != nil || len(body) > MaxCSRSize {
		http.Error(w, "istek çok büyük", http.StatusRequestEntityTooLarge)
		return
	}
	pub, err := ParseCSR(body)
	if err != nil {
		http.Error(w, "geçersiz sertifika isteği (ECDSA P-256 CSR gerekir)", http.StatusBadRequest)
		return
	}
	ca, err := s.cfg.CA()
	if err != nil {
		s.cfg.Logger.Warn("internal CA unavailable", "error", err.Error())
		http.Error(w, "iç CA hazır değil", http.StatusServiceUnavailable)
		return
	}
	now := s.cfg.Now()
	if !s.allow(g.Device, now) {
		http.Error(w, "çok fazla sertifika isteği; daha sonra deneyin", http.StatusTooManyRequests)
		return
	}
	der, err := ca.Issue(pub, g.DNS, g.IPs, now, g.Lifetime)
	if err != nil {
		s.cfg.Logger.Warn("certificate not issued", "device", g.Device, "error", err.Error())
		http.Error(w, "sertifika verilemedi", http.StatusInternalServerError)
		return
	}
	leaf, _ := x509.ParseCertificate(der)
	if leaf != nil {
		s.cfg.Logger.Info("certificate issued", "device", g.Device, "serial", leaf.SerialNumber.Text(16), "not_after", leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	_, _ = w.Write(CertPEM(der, ca.Cert.Raw))
}

// Serve answers requests on ln until ctx ends.
func (s *Issuer) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           s,
		ReadHeaderTimeout: issuerReadTimeout,
		ReadTimeout:       issuerReadTimeout,
		WriteTimeout:      issuerReadTimeout,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
		ErrorLog:          slog.NewLogLogger(slog.DiscardHandler, slog.LevelError),
	}
	stop := context.AfterFunc(ctx, func() { _ = srv.Close() })
	defer stop()
	err := srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) || ctx.Err() != nil {
		return nil
	}
	return err
}

// Request asks the issuer at addr for a certificate of key. local, when
// valid, is the source address to dial from (this device's tunnel
// address). The answer is checked: the certificate must be for key, chain
// to the pinned CA certificate and verify now.
func Request(ctx context.Context, addr netip.AddrPort, local netip.Addr, key *ecdsa.PrivateKey, pinnedCA []byte, now time.Time) (leafDER []byte, err error) {
	ca, err := x509.ParseCertificate(pinnedCA)
	if err != nil {
		return nil, fmt.Errorf("pki: pinned CA: %w", err)
	}
	csr, err := NewCSR(key, "openscale")
	if err != nil {
		return nil, err
	}
	d := &net.Dialer{Timeout: 10 * time.Second}
	if local.IsValid() {
		d.LocalAddr = &net.TCPAddr{IP: net.IP(local.AsSlice())}
	}
	hc := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return d.DialContext(ctx, "tcp", addr.String())
			},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+addr.String()+CertPath, bytes.NewReader(csr))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/pkcs10")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sertifika dağıtıcısına bağlanılamadı (cert kuralı ve tünel açık mı?): %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxChainReply+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxChainReply {
		return nil, errors.New("pki: answer is too large")
	}
	if resp.StatusCode != http.StatusOK {
		msg := string(bytes.TrimSpace(body))
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return nil, fmt.Errorf("sertifika dağıtıcısı reddetti (%d): %s", resp.StatusCode, msg)
	}
	certs, err := ParseCertsPEM(body)
	if err != nil {
		return nil, err
	}
	leaf := certs[0]
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, errors.New("pki: the issued certificate is not for this key")
	}
	if err := VerifyLeaf(leaf, ca, now); err != nil {
		return nil, err
	}
	return leaf.Raw, nil
}
