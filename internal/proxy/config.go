// Package proxy publishes services of a device inside the tunnel (F-215,
// ADR-0139): HTTP(S) reverse proxies with optional path and method rules
// (#114), static files and directories, TCP forwarding and the network
// identity provider (ADR-0140). It listens only on the device's tunnel
// address, decides every request or connection from the signed network
// document by the tunnel source address and never accepts a forwarded
// client address from a header.
package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/openscale/openscale/internal/trust"
)

// ConfigFile is the publishing configuration, under the apps directory of
// the data (or state) directory. It is local to the device: the signed
// document decides who may reach the services, this file only what the
// device publishes and how far it narrows the rules.
const ConfigFile = "serve.json"

// ConfigSchema is the configuration version.
const ConfigSchema = 1

// Service types.
const (
	TypeHTTP  = "http"
	TypeFiles = "files"
	TypeTCP   = "tcp"
	TypeOIDC  = "oidc"
)

// Limits.
const (
	MaxServices     = 32
	MaxConfigSize   = 256 << 10
	maxPaths        = 32
	maxPathLen      = 256
	maxAllow        = 64
	maxTargetLen    = 512
	maxClients      = 32
	maxRedirectURIs = 8
	maxClientIDLen  = 64
)

// OIDCClient is a relying party of an identity provider service.
type OIDCClient struct {
	ID string `json:"id"`
	// SecretSHA256 is the hex SHA-256 of the client secret; empty makes
	// a public client (PKCE is required for every client anyway).
	SecretSHA256 string   `json:"secret_sha256,omitempty"`
	RedirectURIs []string `json:"redirect_uris"`
}

// Service is one published service.
type Service struct {
	// Name is a DNS label: the service answers as
	// <name>.<device>.<domain> on the shared port.
	Name string `json:"name"`
	Type string `json:"type"`
	// Target is the backend: an http(s) URL (http) or host:port (tcp).
	Target string `json:"target,omitempty"`
	// Root is the directory a files service serves.
	Root string `json:"root,omitempty"`
	// Listing shows directory listings (files).
	Listing bool `json:"listing,omitempty"`
	// Port publishes the service on its own tunnel port instead of the
	// shared serve port; a plain rule for that TCP port then decides
	// access. tcp services always need it.
	Port uint16 `json:"port,omitempty"`
	// TLS serves HTTPS with a certificate of the internal CA and
	// redirects plain HTTP requests (ADR-0138).
	TLS bool `json:"tls,omitempty"`
	// Paths limits an http service to these path prefixes (#114); a
	// prefix ending in "/" covers everything below it, otherwise the path
	// must match exactly.
	Paths []string `json:"paths,omitempty"`
	// ReadOnly allows only GET, HEAD and OPTIONS and no protocol upgrade
	// (#114).
	ReadOnly bool `json:"read_only,omitempty"`
	// Allow narrows who may use the service (device names, tag:x,
	// group:y, *); empty leaves it to the rules. It can never grant more
	// than the rules.
	Allow []string `json:"allow,omitempty"`
	// Clients are the relying parties of an oidc service.
	Clients []OIDCClient `json:"clients,omitempty"`
}

// Config is the publishing configuration.
type Config struct {
	Schema   int       `json:"schema"`
	Services []Service `json:"services"`
}

// Shared reports whether the service is on the shared serve port.
func (s Service) Shared() bool { return s.Port == 0 }

// HTTPLike reports whether the service speaks HTTP.
func (s Service) HTTPLike() bool { return s.Type != TypeTCP }

// reservedPorts are OpenScale's own tunnel ports and the local API.
func reservedPort(p uint16) bool {
	switch {
	case p == 0, p == 53, p == trust.SSHPort, p == 47821:
		return true
	case p >= 4039 && p <= 4052:
		return true
	}
	return false
}

// ValidName reports whether s is a service name: a lowercase DNS label.
func ValidName(s string) bool {
	if s == "" || len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// ParseConfig parses and validates a configuration strictly.
func ParseConfig(data []byte) (Config, error) {
	var c Config
	if len(data) > MaxConfigSize {
		return c, errors.New("serve.json çok büyük")
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("serve.json okunamadı: %w", err)
	}
	if dec.More() {
		return Config{}, errors.New("serve.json: fazladan veri")
	}
	return c, c.Validate()
}

// Encode returns the configuration as indented JSON.
func (c Config) Encode() ([]byte, error) {
	c.Schema = ConfigSchema
	if c.Services == nil {
		c.Services = []Service{}
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Validate checks the whole configuration.
func (c Config) Validate() error {
	if c.Schema != ConfigSchema {
		return fmt.Errorf("serve.json: şema %d desteklenmiyor", c.Schema)
	}
	if len(c.Services) > MaxServices {
		return fmt.Errorf("en fazla %d servis yayınlanabilir", MaxServices)
	}
	names := map[string]bool{}
	ports := map[uint16]bool{}
	for _, s := range c.Services {
		if err := s.Validate(); err != nil {
			return fmt.Errorf("servis %q: %w", s.Name, err)
		}
		if names[s.Name] {
			return fmt.Errorf("servis adı %q iki kez kullanılmış", s.Name)
		}
		names[s.Name] = true
		if s.Port != 0 {
			if ports[s.Port] {
				return fmt.Errorf("port %d iki serviste kullanılmış", s.Port)
			}
			ports[s.Port] = true
		}
	}
	return nil
}

// Validate checks one service.
func (s Service) Validate() error {
	if !ValidName(s.Name) {
		return errors.New("ad küçük harf, rakam ve '-' içeren bir DNS etiketi olmalı (en çok 63 karakter)")
	}
	if s.Port != 0 && reservedPort(s.Port) {
		return fmt.Errorf("port %d OpenScale'e ayrılmış", s.Port)
	}
	if len(s.Allow) > maxAllow {
		return fmt.Errorf("allow en fazla %d giriş içerebilir", maxAllow)
	}
	for _, a := range s.Allow {
		if a == "" || len(a) > 128 || strings.ContainsAny(a, " \t\r\n") {
			return fmt.Errorf("geçersiz allow girişi %q", a)
		}
	}
	if s.Type != TypeHTTP && (len(s.Paths) != 0 || s.ReadOnly) {
		return errors.New("paths ve read_only yalnızca http servislerinde kullanılır")
	}
	if s.Type != TypeFiles && (s.Root != "" || s.Listing) {
		return errors.New("root ve listing yalnızca files servislerinde kullanılır")
	}
	if s.Type != TypeOIDC && len(s.Clients) != 0 {
		return errors.New("clients yalnızca oidc servislerinde kullanılır")
	}
	switch s.Type {
	case TypeHTTP:
		if _, err := ParseHTTPTarget(s.Target); err != nil {
			return err
		}
		if len(s.Paths) > maxPaths {
			return fmt.Errorf("en fazla %d yol", maxPaths)
		}
		for _, p := range s.Paths {
			if !validPathRule(p) {
				return fmt.Errorf("geçersiz yol kuralı %q ('/' ile başlamalı, '..', '//', '%%' ve '\\' içermemeli)", p)
			}
		}
	case TypeFiles:
		if s.Target != "" {
			return errors.New("files servisinde target kullanılmaz")
		}
		if s.Root == "" || len(s.Root) > 1024 {
			return errors.New("files servisi root (dizin) ister")
		}
	case TypeTCP:
		if s.Port == 0 {
			return errors.New("tcp servisi kendi portunu (port) ister")
		}
		if s.TLS {
			return errors.New("tcp servisinde tls kullanılmaz (bağlantı olduğu gibi iletilir)")
		}
		if _, _, err := ParseTCPTarget(s.Target); err != nil {
			return err
		}
	case TypeOIDC:
		if s.Target != "" {
			return errors.New("oidc servisinde target kullanılmaz")
		}
		if len(s.Clients) > maxClients {
			return fmt.Errorf("en fazla %d istemci", maxClients)
		}
		ids := map[string]bool{}
		for _, cl := range s.Clients {
			if err := cl.Validate(); err != nil {
				return fmt.Errorf("istemci %q: %w", cl.ID, err)
			}
			if ids[cl.ID] {
				return fmt.Errorf("istemci %q iki kez tanımlı", cl.ID)
			}
			ids[cl.ID] = true
		}
	default:
		return fmt.Errorf("bilinmeyen tür %q (http, files, tcp, oidc)", s.Type)
	}
	return nil
}

// Validate checks an OIDC client.
func (cl OIDCClient) Validate() error {
	if cl.ID == "" || len(cl.ID) > maxClientIDLen {
		return errors.New("istemci kimliği 1-64 karakter olmalı")
	}
	for i := 0; i < len(cl.ID); i++ {
		c := cl.ID[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return errors.New("istemci kimliği yalnızca harf, rakam, '-', '_' ve '.' içerebilir")
		}
	}
	if cl.SecretSHA256 != "" {
		if len(cl.SecretSHA256) != 64 || strings.ToLower(cl.SecretSHA256) != cl.SecretSHA256 || strings.Trim(cl.SecretSHA256, "0123456789abcdef") != "" {
			return errors.New("secret_sha256 64 küçük harf onaltılık karakter olmalı")
		}
	}
	if len(cl.RedirectURIs) == 0 || len(cl.RedirectURIs) > maxRedirectURIs {
		return fmt.Errorf("1-%d yönlendirme adresi gerekir", maxRedirectURIs)
	}
	for _, r := range cl.RedirectURIs {
		u, err := url.Parse(r)
		if err != nil || len(r) > maxTargetLen || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.Fragment != "" || u.User != nil {
			return fmt.Errorf("geçersiz yönlendirme adresi %q (http/https, parçasız, kullanıcı bilgisiz)", r)
		}
	}
	return nil
}

func validPathRule(p string) bool {
	if p == "" || len(p) > maxPathLen || p[0] != '/' || strings.ContainsAny(p, "%\\?#") || strings.Contains(p, "//") {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." || seg == "." {
			return false
		}
	}
	return true
}

// ParseHTTPTarget checks an http service's backend URL.
func ParseHTTPTarget(s string) (*url.URL, error) {
	if s == "" || len(s) > maxTargetLen {
		return nil, errors.New("http servisi target ister (ör. http://127.0.0.1:8080)")
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("geçersiz target %q (şema http veya https olmalı; kullanıcı bilgisi ve sorgu olmadan)", s)
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("geçersiz target portu %q", p)
		}
	}
	return u, nil
}

// ParseTCPTarget checks a tcp service's backend host:port.
func ParseTCPTarget(s string) (string, uint16, error) {
	if s == "" || len(s) > maxTargetLen {
		return "", 0, errors.New("tcp servisi target (adres:port) ister")
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil || host == "" {
		return "", 0, fmt.Errorf("geçersiz target %q (adres:port)", s)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", 0, fmt.Errorf("geçersiz target portu %q", port)
	}
	return host, uint16(n), nil
}

// pathAllowed applies an http service's path rules to a cleaned path.
func pathAllowed(rules []string, p string) bool {
	if len(rules) == 0 {
		return true
	}
	return slices.ContainsFunc(rules, func(r string) bool {
		if strings.HasSuffix(r, "/") {
			return strings.HasPrefix(p, r) || p+"/" == r
		}
		return p == r
	})
}

// cleanRequestPath returns the request path when it is unambiguous: no
// encoded slash, dot or backslash, no dot segments and no empty segments,
// so the backend sees exactly the path the rules were applied to.
func cleanRequestPath(u *url.URL) (string, bool) {
	raw := u.EscapedPath()
	low := strings.ToLower(raw)
	if raw == "" || raw[0] != '/' || strings.Contains(low, "%2f") || strings.Contains(low, "%2e") || strings.Contains(low, "%5c") || strings.Contains(low, "%00") || strings.Contains(raw, "\\") || strings.Contains(raw, "//") {
		return "", false
	}
	p := u.Path
	if strings.ContainsRune(p, 0) {
		return "", false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return "", false
		}
	}
	if path.Clean(p) != strings.TrimSuffix(p, "/") && p != "/" {
		return "", false
	}
	return p, true
}

// ipInPrefixes reports whether a falls into one of ps.
func ipInPrefixes(a netip.Addr, ps ...netip.Prefix) bool {
	a = a.Unmap()
	for _, p := range ps {
		if p.IsValid() && p.Contains(a) {
			return true
		}
	}
	return false
}
