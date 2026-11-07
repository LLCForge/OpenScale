// Package oidc is a minimal OpenID Connect provider whose users are the
// devices of an OpenScale network (F-113, ADR-0140). It runs only inside
// the tunnel, behind internal/proxy, which has already found the device a
// browser connects from by its tunnel source address. There is no login
// page and no password: the device identity is the authentication, the
// same way the rest of OpenScale decides access.
//
// Supported: discovery, JWKS, the authorization code flow with PKCE (S256,
// required for every client), the token endpoint (client_secret_basic,
// client_secret_post or public clients) and userinfo. ID tokens are ES256
// JWTs. Not supported: implicit and hybrid flows, refresh tokens, dynamic
// client registration, consent screens and sessions.
package oidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Lifetimes and limits.
const (
	CodeLifetime  = 60 * time.Second
	TokenLifetime = 10 * time.Minute
	maxCodes      = 1024
	maxTokens     = 4096
	maxFormBody   = 16 << 10
	maxState      = 512
	maxNonce      = 256
)

// Subject is the authenticated device.
type Subject struct {
	// ID is the device's stable id (the "sub" claim); it survives a
	// rename.
	ID   string
	Name string
	FQDN string
	Tags []string
}

// Client is a registered relying party.
type Client struct {
	ID string
	// SecretSHA256 is the hex SHA-256 of the secret; empty: public client.
	SecretSHA256 string
	RedirectURIs []string
}

// Config configures a provider.
type Config struct {
	// Issuer returns the issuer URL (scheme, host and port, no path).
	Issuer  func() string
	Clients []Client
	Key     *ecdsa.PrivateKey
	// Identity returns the device of a request; false refuses.
	Identity func(*http.Request) (Subject, bool)
	Now      func() time.Time
	Logger   *slog.Logger
	Random   io.Reader
}

type pendingCode struct {
	client, redirect, challenge, nonce string
	subject                            Subject
	authTime, expires                  time.Time
}

type issuedToken struct {
	client  string
	subject Subject
	expires time.Time
}

// Provider is an OpenID Connect provider.
type Provider struct {
	cfg     Config
	kid     string
	clients map[string]Client

	mu     sync.Mutex
	codes  map[string]pendingCode
	tokens map[string]issuedToken
}

// New returns a provider.
func New(cfg Config) (*Provider, error) {
	if cfg.Key == nil || cfg.Key.Curve != elliptic.P256() {
		return nil, errors.New("oidc: ECDSA P-256 signing key required")
	}
	if cfg.Issuer == nil || cfg.Identity == nil {
		return nil, errors.New("oidc: issuer and identity required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Random == nil {
		cfg.Random = rand.Reader
	}
	spki, err := x509.MarshalPKIXPublicKey(&cfg.Key.PublicKey)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(spki)
	p := &Provider{
		cfg:     cfg,
		kid:     hex.EncodeToString(sum[:8]),
		clients: map[string]Client{},
		codes:   map[string]pendingCode{},
		tokens:  map[string]issuedToken{},
	}
	for _, c := range cfg.Clients {
		p.clients[c.ID] = c
	}
	return p, nil
}

// Paths of the provider below the issuer.
const (
	PathDiscovery = "/.well-known/openid-configuration"
	PathJWKS      = "/jwks"
	PathAuthorize = "/authorize"
	PathToken     = "/token"
	PathUserinfo  = "/userinfo"
)

// ServeHTTP routes the provider's endpoints.
func (p *Provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	switch r.URL.Path {
	case PathDiscovery:
		p.discovery(w, r)
	case PathJWKS:
		p.jwks(w, r)
	case PathAuthorize:
		p.authorize(w, r)
	case PathToken:
		p.token(w, r)
	case PathUserinfo:
		p.userinfo(w, r)
	default:
		http.NotFound(w, r)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func onlyMethods(w http.ResponseWriter, r *http.Request, methods ...string) bool {
	for _, m := range methods {
		if r.Method == m {
			return true
		}
	}
	w.Header().Set("Allow", strings.Join(methods, ", "))
	http.Error(w, "yöntem desteklenmiyor", http.StatusMethodNotAllowed)
	return false
}

func (p *Provider) discovery(w http.ResponseWriter, r *http.Request) {
	if !onlyMethods(w, r, http.MethodGet, http.MethodHead) {
		return
	}
	iss := p.cfg.Issuer()
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                iss,
		"authorization_endpoint":                iss + PathAuthorize,
		"token_endpoint":                        iss + PathToken,
		"userinfo_endpoint":                     iss + PathUserinfo,
		"jwks_uri":                              iss + PathJWKS,
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"ES256"},
		"scopes_supported":                      []string{"openid", "profile"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"code_challenge_methods_supported":      []string{"S256"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "name", "preferred_username", "openscale_fqdn", "openscale_tags"},
	})
}

func (p *Provider) jwks(w http.ResponseWriter, r *http.Request) {
	if !onlyMethods(w, r, http.MethodGet, http.MethodHead) {
		return
	}
	pub := p.cfg.Key.PublicKey
	ecdh, err := pub.ECDH()
	if err != nil {
		http.Error(w, "anahtar hatası", http.StatusInternalServerError)
		return
	}
	raw := ecdh.Bytes() // 0x04 || X || Y
	b := base64.RawURLEncoding
	writeJSON(w, http.StatusOK, map[string]any{"keys": []map[string]string{{
		"kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256", "kid": p.kid,
		"x": b.EncodeToString(raw[1:33]), "y": b.EncodeToString(raw[33:65]),
	}}})
}

// errorPage answers an authorization error that must not be redirected
// (unknown client or redirect URI).
func errorPage(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, "<!doctype html><meta charset=utf-8><title>OpenScale</title><p>"+html.EscapeString(msg)+"</p>")
}

func validVerifierChars(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~') {
			return false
		}
	}
	return true
}

func (p *Provider) randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(p.cfg.Random, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (p *Provider) authorize(w http.ResponseWriter, r *http.Request) {
	if !onlyMethods(w, r, http.MethodGet) {
		return
	}
	q := r.URL.Query()
	for _, k := range []string{"client_id", "redirect_uri", "response_type", "scope", "state", "nonce", "code_challenge", "code_challenge_method"} {
		if len(q[k]) > 1 {
			errorPage(w, http.StatusBadRequest, "Parametre birden çok kez verilmiş: "+k)
			return
		}
	}
	cl, ok := p.clients[q.Get("client_id")]
	if !ok {
		errorPage(w, http.StatusBadRequest, "Bilinmeyen istemci.")
		return
	}
	redirect := q.Get("redirect_uri")
	if !containsExact(cl.RedirectURIs, redirect) {
		errorPage(w, http.StatusBadRequest, "Yönlendirme adresi bu istemci için kayıtlı değil.")
		return
	}
	target, err := url.Parse(redirect)
	if err != nil {
		errorPage(w, http.StatusBadRequest, "Yönlendirme adresi geçersiz.")
		return
	}
	state := q.Get("state")
	if len(state) > maxState {
		errorPage(w, http.StatusBadRequest, "state çok uzun.")
		return
	}
	fail := func(code, desc string) {
		v := target.Query()
		v.Set("error", code)
		v.Set("error_description", desc)
		if state != "" {
			v.Set("state", state)
		}
		target.RawQuery = v.Encode()
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, target.String(), http.StatusFound)
	}
	switch {
	case q.Get("response_type") != "code":
		fail("unsupported_response_type", "only code")
		return
	case !containsExact(strings.Fields(q.Get("scope")), "openid"):
		fail("invalid_scope", "openid scope required")
		return
	case q.Get("code_challenge_method") != "S256":
		fail("invalid_request", "PKCE with S256 required")
		return
	}
	challenge := q.Get("code_challenge")
	if len(challenge) != 43 || !validVerifierChars(challenge) {
		fail("invalid_request", "invalid code_challenge")
		return
	}
	nonce := q.Get("nonce")
	if len(nonce) > maxNonce {
		fail("invalid_request", "nonce too long")
		return
	}
	sub, ok := p.cfg.Identity(r)
	if !ok {
		fail("access_denied", "not an OpenScale device allowed here")
		return
	}
	code, err := p.randomToken()
	if err != nil {
		fail("server_error", "random")
		return
	}
	now := p.cfg.Now()
	p.mu.Lock()
	p.pruneLocked(now)
	if len(p.codes) >= maxCodes {
		p.mu.Unlock()
		fail("temporarily_unavailable", "too many pending codes")
		return
	}
	p.codes[code] = pendingCode{client: cl.ID, redirect: redirect, challenge: challenge, nonce: nonce, subject: sub, authTime: now, expires: now.Add(CodeLifetime)}
	p.mu.Unlock()
	p.cfg.Logger.Info("oidc login", "client", cl.ID, "device", sub.Name)
	v := target.Query()
	v.Set("code", code)
	if state != "" {
		v.Set("state", state)
	}
	target.RawQuery = v.Encode()
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func (p *Provider) pruneLocked(now time.Time) {
	for k, c := range p.codes {
		if !now.Before(c.expires) {
			delete(p.codes, k)
		}
	}
	for k, t := range p.tokens {
		if !now.Before(t.expires) {
			delete(p.tokens, k)
		}
	}
}

func containsExact(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// clientAuth authenticates the client of a token request.
func (p *Provider) clientAuth(r *http.Request, form url.Values) (Client, bool) {
	id, secret, basic := r.BasicAuth()
	if basic {
		var err1, err2 error
		id, err1 = url.QueryUnescape(id)
		secret, err2 = url.QueryUnescape(secret)
		if err1 != nil || err2 != nil || form.Get("client_secret") != "" {
			return Client{}, false
		}
	} else {
		id, secret = form.Get("client_id"), form.Get("client_secret")
	}
	cl, ok := p.clients[id]
	if !ok {
		return Client{}, false
	}
	if cl.SecretSHA256 == "" {
		return cl, true
	}
	if secret == "" {
		return Client{}, false
	}
	sum := sha256.Sum256([]byte(secret))
	got := hex.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(got), []byte(cl.SecretSHA256)) != 1 {
		return Client{}, false
	}
	return cl, true
}

func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	if !onlyMethods(w, r, http.MethodPost) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(strings.ToLower(ct), "application/x-www-form-urlencoded") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	form := r.PostForm
	for _, k := range []string{"grant_type", "code", "redirect_uri", "code_verifier", "client_id", "client_secret"} {
		if len(form[k]) > 1 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
			return
		}
	}
	cl, ok := p.clientAuth(r, form)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="openscale"`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	if form.Get("grant_type") != "authorization_code" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
		return
	}
	now := p.cfg.Now()
	p.mu.Lock()
	pc, found := p.codes[form.Get("code")]
	delete(p.codes, form.Get("code")) // single use, even when the rest fails
	p.mu.Unlock()
	verifier := form.Get("code_verifier")
	if !found || !now.Before(pc.expires) || pc.client != cl.ID || pc.redirect != form.Get("redirect_uri") ||
		len(verifier) < 43 || len(verifier) > 128 || !validVerifierChars(verifier) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	sum := sha256.Sum256([]byte(verifier))
	if subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(pc.challenge)) != 1 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	idToken, err := p.signIDToken(cl.ID, pc, now)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	access, err := p.randomToken()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	p.mu.Lock()
	p.pruneLocked(now)
	if len(p.tokens) >= maxTokens {
		p.mu.Unlock()
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "temporarily_unavailable"})
		return
	}
	p.tokens[access] = issuedToken{client: cl.ID, subject: pc.subject, expires: now.Add(TokenLifetime)}
	p.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": access,
		"token_type":   "Bearer",
		"expires_in":   int(TokenLifetime.Seconds()),
		"id_token":     idToken,
		"scope":        "openid",
	})
}

func claims(s Subject) map[string]any {
	tags := s.Tags
	if tags == nil {
		tags = []string{}
	}
	return map[string]any{
		"sub":                s.ID,
		"name":               s.Name,
		"preferred_username": s.Name,
		"openscale_fqdn":     s.FQDN,
		"openscale_tags":     tags,
	}
}

func (p *Provider) signIDToken(aud string, pc pendingCode, now time.Time) (string, error) {
	c := claims(pc.subject)
	c["iss"] = p.cfg.Issuer()
	c["aud"] = aud
	c["iat"] = now.Unix()
	c["exp"] = now.Add(TokenLifetime).Unix()
	c["auth_time"] = pc.authTime.Unix()
	if pc.nonce != "" {
		c["nonce"] = pc.nonce
	}
	return SignJWT(p.cfg.Key, p.kid, c)
}

// SignJWT signs claims as an ES256 compact JWT.
func SignJWT(key *ecdsa.PrivateKey, kid string, claims map[string]any) (string, error) {
	b := base64.RawURLEncoding
	hdr, err := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT", "kid": kid})
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signing := b.EncodeToString(hdr) + "." + b.EncodeToString(body)
	digest := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signing + "." + b.EncodeToString(sig), nil
}

func (p *Provider) userinfo(w http.ResponseWriter, r *http.Request) {
	if !onlyMethods(w, r, http.MethodGet, http.MethodPost) {
		return
	}
	auth := r.Header.Get("Authorization")
	tok, ok := strings.CutPrefix(auth, "Bearer ")
	if !ok || tok == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="openscale"`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}
	now := p.cfg.Now()
	p.mu.Lock()
	t, found := p.tokens[tok]
	p.mu.Unlock()
	if !found || !now.Before(t.expires) {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}
	writeJSON(w, http.StatusOK, claims(t.subject))
}
