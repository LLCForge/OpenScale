package node

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/wgconf"
)

func keyN(n byte) trust.Key {
	var k trust.Key
	k[0] = n
	return k
}

func hexKey(k trust.Key) string { return hex.EncodeToString(k[:]) }

func TestEndpointCacheRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, endpointCacheFile)
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

	if c, err := readEndpointCache(path, "net1", now); err != nil || len(c.Peers) != 0 || c.Coordinator != nil {
		t.Fatalf("missing file: %+v %v", c, err)
	}
	good := cachedEndpoint{Endpoint: "198.51.100.4:51820", Seen: now.Add(-time.Hour)}
	in := endpointCache{Version: endpointCacheVersion, NetworkID: "net1",
		Coordinator: &cachedEndpoint{Endpoint: "203.0.113.1:51820", Seen: now.Add(-time.Minute)},
		Peers: map[string]cachedEndpoint{
			hexKey(keyN(1)): good,
			hexKey(keyN(2)): {Endpoint: "198.51.100.5:51820", Seen: now.Add(-8 * 24 * time.Hour)}, // too old
			hexKey(keyN(3)): {Endpoint: "198.51.100.6:51820", Seen: now.Add(48 * time.Hour)},      // from the future
			hexKey(keyN(4)): {Endpoint: "0.0.0.0:51820", Seen: now},                               // unspecified
			hexKey(keyN(5)): {Endpoint: "224.0.0.1:51820", Seen: now},                             // multicast
			hexKey(keyN(6)): {Endpoint: "198.51.100.7:0", Seen: now},                              // no port
			hexKey(keyN(7)): {Endpoint: "relay-00", Seen: now},
			"zz":            good, // not a key
		}}
	if err := writeEndpointCache(path, in); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("cache file mode %v (%v), want 0600", fi.Mode().Perm(), err)
		}
	}
	c, err := readEndpointCache(path, "net1", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Peers) != 1 || c.Peers[hexKey(keyN(1))] != good {
		t.Fatalf("peers %+v", c.Peers)
	}
	if c.Coordinator == nil || c.Coordinator.Endpoint != "203.0.113.1:51820" {
		t.Fatalf("coordinator %+v", c.Coordinator)
	}
	// Another network's cache is ignored.
	if c, err := readEndpointCache(path, "net2", now); err != nil || len(c.Peers) != 0 || c.Coordinator != nil {
		t.Fatalf("other network: %+v %v", c, err)
	}
	// A corrupt file is reported and ignored.
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if c, err := readEndpointCache(path, "net1", now); err == nil || len(c.Peers) != 0 {
		t.Fatalf("corrupt file accepted: %+v", c)
	}
	// Files other users can read are refused (POSIX only).
	if runtime.GOOS != "windows" {
		data, _ := json.Marshal(in)
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := readEndpointCache(path, "net1", now); err == nil {
			t.Fatal("world-readable cache accepted")
		}
	}
}

func TestRecordEndpoints(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	self := trust.Device{Name: "laptop", WireGuardKey: keyN(10), IPv4: netip.MustParseAddr("100.80.0.2"), ExpiresAt: now.Add(time.Hour)}
	peer := trust.Device{Name: "masaustu", WireGuardKey: keyN(11), IPv4: netip.MustParseAddr("100.80.0.3"), ExpiresAt: now.Add(time.Hour)}
	other := trust.Device{Name: "telefon", WireGuardKey: keyN(12), IPv4: netip.MustParseAddr("100.80.0.4"), ExpiresAt: now.Add(time.Hour)}
	doc := &trust.Document{NetworkID: "net1", Devices: []trust.Device{self, peer, other},
		Coordinator: &trust.Coordinator{WireGuardKey: keyN(20)},
		Rules:       []trust.Rule{{From: []string{"laptop"}, To: []string{"masaustu"}, Protocol: trust.ProtocolAny}}}
	if len(doc.TunnelPeersOf("laptop")) != 1 {
		t.Skip("rule model changed; adjust the test document")
	}
	path := filepath.Join(t.TempDir(), "ep.json")
	e := &Engine{cfg: Config{Now: func() time.Time { return now }, EndpointCache: path}, wgKey: self.WireGuardKey,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	e.epCache = endpointCache{Peers: map[string]cachedEndpoint{
		hexKey(other.WireGuardKey): {Endpoint: "192.0.2.50:1", Seen: now}, // no longer a tunnel peer
	}}

	recent := now.Add(-30 * time.Second).Unix()
	st := wgconf.Status{Peers: map[trust.Key]wgconf.PeerStatus{
		peer.WireGuardKey:  {Endpoint: netip.MustParseAddrPort("198.51.100.4:51820"), LastHandshakeUnix: recent},
		keyN(20):           {Endpoint: netip.MustParseAddrPort("203.0.113.1:51820"), LastHandshakeUnix: recent},
		other.WireGuardKey: {Endpoint: netip.MustParseAddrPort("198.51.100.9:51820"), LastHandshakeUnix: recent},
	}}
	e.recordEndpoints(doc, st)
	c, err := readEndpointCache(path, "net1", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Peers) != 1 || c.Peers[hexKey(peer.WireGuardKey)].Endpoint != "198.51.100.4:51820" {
		t.Fatalf("peers %+v", c.Peers)
	}
	if c.Coordinator == nil || c.Coordinator.Endpoint != "203.0.113.1:51820" {
		t.Fatalf("coordinator %+v", c.Coordinator)
	}

	// Unchanged endpoints are not written again.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	now = now.Add(30 * time.Second)
	e.recordEndpoints(doc, st)
	if _, err := os.Stat(path); err == nil {
		t.Fatal("unchanged cache rewritten")
	}
	// A moved endpoint is written at once.
	st.Peers[peer.WireGuardKey] = wgconf.PeerStatus{Endpoint: netip.MustParseAddrPort("198.51.100.4:51821"), LastHandshakeUnix: now.Unix()}
	e.recordEndpoints(doc, st)
	if c, err := readEndpointCache(path, "net1", now); err != nil || c.Peers[hexKey(peer.WireGuardKey)].Endpoint != "198.51.100.4:51821" {
		t.Fatalf("moved endpoint not written: %+v %v", c.Peers, err)
	}
	// Forgetting a device waits for the save interval.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	doc2 := *doc
	doc2.Rules = nil
	e.recordEndpoints(&doc2, st)
	if _, err := os.Stat(path); err == nil {
		t.Fatal("forgetting written before the save interval")
	}
	now = now.Add(endpointCacheSaveEvery)
	e.recordEndpoints(&doc2, st)
	if c, err := readEndpointCache(path, "net1", now); err != nil || len(c.Peers) != 0 {
		t.Fatalf("forgotten device kept: %+v %v", c.Peers, err)
	}
	e.recordEndpoints(doc, st) // back to the original rules
	if err := writeEndpointCache(path, endpointCache{Version: endpointCacheVersion, NetworkID: "net1",
		Coordinator: &cachedEndpoint{Endpoint: "203.0.113.1:51820", Seen: now},
		Peers:       map[string]cachedEndpoint{hexKey(peer.WireGuardKey): {Endpoint: "198.51.100.4:51820", Seen: now}}}); err != nil {
		t.Fatal(err)
	}
	e.loadEndpointCache(doc)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	// Relayed and stale peers are not recorded; unchanged data is not
	// rewritten.
	now = now.Add(2 * time.Minute)
	st.Peers[peer.WireGuardKey] = wgconf.PeerStatus{Relayed: true, LastHandshakeUnix: now.Unix()}
	e.recordEndpoints(doc, st)
	if _, err := os.Stat(path); err == nil {
		t.Fatal("unchanged cache rewritten")
	}

	// applyCachedEndpoints sets only peers without an endpoint.
	st = wgconf.Status{Peers: map[trust.Key]wgconf.PeerStatus{
		peer.WireGuardKey: {},
		keyN(20):          {},
	}}
	uapi := e.applyCachedEndpoints(st, keyN(20))
	if want := wgconf.SetEndpoint(peer.WireGuardKey, netip.MustParseAddrPort("198.51.100.4:51820")); uapi != want {
		t.Fatalf("uapi %q, want %q", uapi, want)
	}
	st.Peers[peer.WireGuardKey] = wgconf.PeerStatus{Endpoint: netip.MustParseAddrPort("198.51.100.99:1")}
	if uapi := e.applyCachedEndpoints(st, keyN(20)); uapi != "" {
		t.Fatalf("known endpoint overwritten: %q", uapi)
	}
	if ap, ok := e.cachedCoordinator(); !ok || ap.String() != "203.0.113.1:51820" {
		t.Fatalf("cached coordinator %v %v", ap, ok)
	}
}
