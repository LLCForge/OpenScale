package node

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"maps"
	"net/netip"
	"path/filepath"
	"time"

	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/wgconf"
)

// Endpoint cache (F-005): the last endpoints that worked, so the tunnels
// come up even when the coordinator cannot be reached at start. The
// document itself is already kept by member.Store (signature re-verified
// on open, expiry checked on use); this file only adds where peers were
// last seen. It is owner-only (0600) and entries expire, keeping as little
// metadata as possible on disk.
const (
	endpointCacheFile    = "endpoints.json"
	endpointCacheVersion = 1
	// endpointCacheMaxAge drops entries not confirmed for this long.
	endpointCacheMaxAge = 7 * 24 * time.Hour
	// endpointCacheSaveEvery limits writes that only refresh timestamps
	// or forget devices.
	endpointCacheSaveEvery = time.Minute
	// maxEndpointCache bounds the file read at start.
	maxEndpointCache = 256 << 10
	// maxCachedPeers bounds the entries kept.
	maxCachedPeers = 4096
)

type cachedEndpoint struct {
	Endpoint string    `json:"endpoint"`
	Seen     time.Time `json:"seen"`
}

type endpointCache struct {
	Version     int                       `json:"version"`
	NetworkID   string                    `json:"network_id"`
	Coordinator *cachedEndpoint           `json:"coordinator,omitempty"`
	Peers       map[string]cachedEndpoint `json:"peers"`
}

// endpointCachePath returns where the cache lives: the configured path or
// the member state directory next to the stored document.
func (e *Engine) endpointCachePath() string {
	if e.cfg.EndpointCache != "" {
		return e.cfg.EndpointCache
	}
	return filepath.Join(e.cfg.Store.Dir(), endpointCacheFile)
}

// validCachedEndpoint accepts only a concrete unicast address and port.
func validCachedEndpoint(s string) (netip.AddrPort, bool) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil || ap.Port() == 0 {
		return netip.AddrPort{}, false
	}
	a := ap.Addr()
	if !a.IsValid() || a.IsUnspecified() || a.IsMulticast() || a.IsInterfaceLocalMulticast() {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(a.Unmap(), ap.Port()), true
}

// readEndpointCache loads the cache for networkID, dropping expired,
// future-dated and malformed entries. A missing file is not an error.
func readEndpointCache(path, networkID string, now time.Time) (endpointCache, error) {
	empty := endpointCache{Version: endpointCacheVersion, NetworkID: networkID, Peers: map[string]cachedEndpoint{}}
	data, err := securefile.ReadPrivate(path, maxEndpointCache)
	if errors.Is(err, fs.ErrNotExist) {
		return empty, nil
	}
	if err != nil {
		return empty, err
	}
	var c endpointCache
	if err := json.Unmarshal(data, &c); err != nil {
		return empty, errors.New("endpoint cache is corrupt")
	}
	if c.Version != endpointCacheVersion || c.NetworkID != networkID {
		return empty, nil // another network or format: start over
	}
	fresh := func(ce cachedEndpoint) bool {
		_, ok := validCachedEndpoint(ce.Endpoint)
		return ok && now.Sub(ce.Seen) <= endpointCacheMaxAge && ce.Seen.Before(now.Add(time.Hour))
	}
	out := empty
	if c.Coordinator != nil && fresh(*c.Coordinator) {
		co := *c.Coordinator
		out.Coordinator = &co
	}
	for k, ce := range c.Peers {
		if len(out.Peers) >= maxCachedPeers {
			break
		}
		if raw, err := hex.DecodeString(k); err != nil || len(raw) != trust.KeySize || !fresh(ce) {
			continue
		}
		out.Peers[k] = ce
	}
	return out, nil
}

func writeEndpointCache(path string, c endpointCache) error {
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return securefile.Replace(path, data)
}

// loadEndpointCache reads the cache at start and remembers it for the
// coordinator fallback and for setting peer endpoints.
func (e *Engine) loadEndpointCache(doc *trust.Document) {
	c, err := readEndpointCache(e.endpointCachePath(), doc.NetworkID, e.cfg.Now())
	if err != nil {
		e.logger.Warn("endpoint cache ignored", "error", err.Error())
	}
	e.mu.Lock()
	e.epCache = c
	e.mu.Unlock()
}

// cachedCoordinator returns the last coordinator endpoint that worked.
func (e *Engine) cachedCoordinator() (netip.AddrPort, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.epCache.Coordinator == nil {
		return netip.AddrPort{}, false
	}
	return validCachedEndpoint(e.epCache.Coordinator.Endpoint)
}

// applyCachedEndpoints gives every configured tunnel peer without an
// endpoint its cached one. WireGuard then handshakes on its own, with or
// without the coordinator.
func (e *Engine) applyCachedEndpoints(st wgconf.Status, coordKey trust.Key) string {
	e.mu.Lock()
	peers := maps.Clone(e.epCache.Peers)
	e.mu.Unlock()
	var uapi string
	for key, cur := range st.Peers {
		if key == coordKey || cur.Endpoint.IsValid() || cur.Relayed {
			continue
		}
		ce, ok := peers[hex.EncodeToString(key[:])]
		if !ok {
			continue
		}
		if ep, ok := validCachedEndpoint(ce.Endpoint); ok {
			uapi += wgconf.SetEndpoint(key, ep)
		}
	}
	return uapi
}

// recordEndpoints folds the endpoints WireGuard confirmed with a recent
// handshake into the cache. A new or moved endpoint is written at once;
// other changes (refreshed timestamps, forgotten devices) at most once a
// minute; nothing is written when nothing changed. Relayed peers are not
// recorded: the relay needs the coordinator anyway.
func (e *Engine) recordEndpoints(doc *trust.Document, st wgconf.Status) {
	now := e.cfg.Now()
	e.mu.Lock()
	c := endpointCache{Version: endpointCacheVersion, NetworkID: doc.NetworkID, Peers: maps.Clone(e.epCache.Peers)}
	if e.epCache.Coordinator != nil {
		co := *e.epCache.Coordinator
		c.Coordinator = &co
	}
	lastWrite := e.epSaved
	e.mu.Unlock()
	if c.Peers == nil {
		c.Peers = map[string]cachedEndpoint{}
	}

	tunnel := map[trust.Key]bool{}
	if self, err := e.selfIn(doc); err == nil {
		for _, p := range doc.TunnelPeersOf(self.Name) {
			tunnel[p.WireGuardKey] = true
		}
	}
	var coordKey trust.Key
	if doc.Coordinator != nil {
		coordKey = doc.Coordinator.WireGuardKey
	}
	changed, urgent := false, false
	for key, cur := range st.Peers {
		if cur.Relayed || !cur.Endpoint.IsValid() || cur.LastHandshakeUnix <= 0 {
			continue
		}
		if now.Sub(time.Unix(cur.LastHandshakeUnix, 0)) > staleHandshake {
			continue
		}
		if _, ok := validCachedEndpoint(cur.Endpoint.String()); !ok {
			continue
		}
		ce := cachedEndpoint{Endpoint: cur.Endpoint.String(), Seen: now.UTC().Truncate(time.Second)}
		var old *cachedEndpoint
		switch {
		case key == coordKey:
			old = c.Coordinator
		case tunnel[key]:
			if o, ok := c.Peers[hex.EncodeToString(key[:])]; ok {
				old = &o
			}
		default:
			continue
		}
		moved := old == nil || old.Endpoint != ce.Endpoint
		if !moved && now.Sub(old.Seen) <= time.Hour {
			continue
		}
		changed, urgent = true, urgent || moved
		if key == coordKey {
			c.Coordinator = &ce
		} else {
			c.Peers[hex.EncodeToString(key[:])] = ce
		}
	}
	// Forget devices that are no longer tunnel peers and stale entries.
	for k, ce := range c.Peers {
		raw, err := hex.DecodeString(k)
		var key trust.Key
		if err == nil && len(raw) == trust.KeySize {
			copy(key[:], raw)
		}
		if !tunnel[key] || now.Sub(ce.Seen) > endpointCacheMaxAge {
			delete(c.Peers, k)
			changed = true
		}
	}
	if c.Coordinator != nil && now.Sub(c.Coordinator.Seen) > endpointCacheMaxAge {
		c.Coordinator, changed = nil, true
	}
	if !changed || (!urgent && now.Sub(lastWrite) < endpointCacheSaveEvery) {
		return
	}
	e.mu.Lock()
	e.epSaved = now
	e.epCache = c
	e.mu.Unlock()
	if err := writeEndpointCache(e.endpointCachePath(), c); err != nil {
		e.logger.Warn("endpoint cache not saved", "error", err.Error())
	}
}
