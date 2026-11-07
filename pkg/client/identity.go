package client

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Source device of a connection (F-081, ADR-0108).
//
// A program that serves the tunnel (a web application behind a reverse
// proxy, for example) can ask which device a connection comes from. The
// answer is a device of the network, never a person: anyone using that
// computer has the same identity. The address is always the TCP
// connection's own remote address; X-Forwarded-For and similar headers
// are never trusted.

// Headers IdentityHandler sets. Requests arriving with any header whose
// name starts with "OpenScale-" lose it first, so a client cannot forge
// an identity.
const (
	HeaderDevice      = "OpenScale-Device"
	HeaderFQDN        = "OpenScale-Device-FQDN"
	HeaderTags        = "OpenScale-Device-Tags"
	HeaderFingerprint = "OpenScale-Device-Fingerprint"
)

// Resolver answers WhoIs; *Client implements it.
type Resolver interface {
	WhoIs(ctx context.Context, addr string) (WhoIsResult, error)
}

// IdentityOptions configures IdentityHandler.
type IdentityOptions struct {
	// AllowUnknown passes requests whose source is not a device of the
	// network (with the identity headers removed) instead of refusing
	// them with 403.
	AllowUnknown bool
	// CacheTTL keeps answers for this long (default 10 s, negative turns
	// the cache off).
	CacheTTL time.Duration
}

type identityKey struct{}

// DeviceFrom returns the device IdentityHandler found for the request.
func DeviceFrom(ctx context.Context) (Device, bool) {
	d, ok := ctx.Value(identityKey{}).(Device)
	return d, ok
}

const (
	defaultIdentityTTL = 10 * time.Second
	maxIdentityCache   = 1024
	identityTimeout    = 5 * time.Second
)

type cachedIdentity struct {
	dev     *Device
	expires time.Time
}

// identityCache bounds the answers kept per source address.
type identityCache struct {
	mu  sync.Mutex
	ttl time.Duration
	m   map[string]cachedIdentity
	now func() time.Time
}

func (c *identityCache) get(ip string) (*Device, bool) {
	if c.ttl <= 0 {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[ip]
	if !ok || !c.now().Before(e.expires) {
		delete(c.m, ip)
		return nil, false
	}
	return e.dev, true
}

func (c *identityCache) put(ip string, d *Device) {
	if c.ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) >= maxIdentityCache {
		now := c.now()
		for k, e := range c.m {
			if !now.Before(e.expires) {
				delete(c.m, k)
			}
		}
		if len(c.m) >= maxIdentityCache {
			clear(c.m)
		}
	}
	c.m[ip] = cachedIdentity{dev: d, expires: c.now().Add(c.ttl)}
}

// stripIdentity removes every header a client may have sent to pose as a
// device.
func stripIdentity(h http.Header) {
	for k := range h {
		if strings.HasPrefix(strings.ToLower(k), "openscale-") {
			delete(h, k)
		}
	}
}

// remoteIP returns the address part of a request's RemoteAddr.
func remoteIP(remote string) string {
	if ap, err := netip.ParseAddrPort(remote); err == nil {
		return ap.Addr().Unmap().String()
	}
	if h, _, err := net.SplitHostPort(remote); err == nil {
		return h
	}
	return remote
}

// IdentityHandler adds the source device's identity headers before next.
// It fails closed: when the tunnel cannot be asked, the request is
// answered with 502 instead of being passed on without an identity.
func IdentityHandler(next http.Handler, r Resolver, opts IdentityOptions) http.Handler {
	ttl := opts.CacheTTL
	if ttl == 0 {
		ttl = defaultIdentityTTL
	}
	cache := &identityCache{ttl: ttl, m: map[string]cachedIdentity{}, now: time.Now}
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		stripIdentity(req.Header)
		ip := remoteIP(req.RemoteAddr)
		dev, ok := cache.get(ip)
		if !ok {
			ctx, cancel := context.WithTimeout(req.Context(), identityTimeout)
			res, err := r.WhoIs(ctx, ip)
			cancel()
			if err != nil {
				http.Error(w, "OpenScale kimliği doğrulanamadı", http.StatusBadGateway)
				return
			}
			dev = res.Device
			cache.put(ip, dev)
		}
		if dev == nil {
			if !opts.AllowUnknown {
				http.Error(w, "Bu adres OpenScale ağındaki bir cihaz değil", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, req)
			return
		}
		req.Header.Set(HeaderDevice, dev.Name)
		req.Header.Set(HeaderFQDN, dev.FQDN)
		req.Header.Set(HeaderTags, strings.Join(dev.Tags, ","))
		req.Header.Set(HeaderFingerprint, dev.Fingerprint)
		next.ServeHTTP(w, req.WithContext(context.WithValue(req.Context(), identityKey{}, *dev)))
	})
}
