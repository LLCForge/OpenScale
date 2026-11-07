// Package handover keeps the tunnel's outage short across a restart of the
// service, above all an update (#203, ADR-0235).
//
// While the tunnel runs, the service keeps a snapshot of the WireGuard
// peers that answer (endpoint and last handshake; the keys are on disk
// already). When the service stops it writes the snapshot to a handover
// file in its own private folder; the next start takes the file (it is
// removed at once, used or not), checks its age and network, and seeds the
// engine's endpoint cache with it, so the new process configures every peer
// with a fresh endpoint before it reaches the coordinator. The file is
// short-lived, unsigned data: it only says where peers were seen, never who
// they are; the signed document still decides which peers exist and with
// which keys, and an endpoint that is wrong only costs a handshake retry.
package handover

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/wgconf"
)

// FileName is the handover file in the service's private state folder.
const FileName = "handover.json"

// Limits.
const (
	// MaxAge is how old a handover file may be when the next start takes
	// it: an update stops and starts the service within seconds.
	MaxAge = 2 * time.Minute
	// fresh is how recent a handshake must be to hand the peer over
	// (WireGuard renews every two minutes while traffic flows).
	fresh      = 3 * time.Minute
	futureSkew = 5 * time.Second
	maxFile    = 512 << 10
	maxPeers   = 4096
	format     = "openscale-handover-v1"
	// SnapshotEvery is how often a Keeper refreshes its snapshot.
	SnapshotEvery = 5 * time.Second
)

// Errors of Take.
var (
	// ErrNone: there is no handover file.
	ErrNone = errors.New("handover: none")
	// ErrStale: the file is older than MaxAge or dated in the future.
	ErrStale = errors.New("handover: too old")
	// ErrCorrupt: the file cannot be used.
	ErrCorrupt = errors.New("handover: corrupt")
)

// Peer is one WireGuard peer that answered.
type Peer struct {
	// Key is the WireGuard public key (hex).
	Key       string    `json:"key"`
	Endpoint  string    `json:"endpoint"`
	Handshake time.Time `json:"handshake"`
}

// State is the content of the handover file.
type State struct {
	Format    string    `json:"format"`
	Created   time.Time `json:"created"`
	From      string    `json:"from"`
	NetworkID string    `json:"networkId"`
	Interface string    `json:"interface,omitempty"`
	// Coordinator is the coordinator's endpoint, if it answered.
	Coordinator *Peer  `json:"coordinator,omitempty"`
	Peers       []Peer `json:"peers"`
}

func validEndpoint(s string) (netip.AddrPort, bool) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil || ap.Port() == 0 {
		return netip.AddrPort{}, false
	}
	a := ap.Addr()
	if !a.IsValid() || a.IsUnspecified() || a.IsMulticast() {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(a.Unmap(), ap.Port()), true
}

// Capture builds a snapshot from the WireGuard status: every directly
// reached peer with a recent handshake. Relayed peers are left out (the
// relay needs the coordinator anyway).
func Capture(networkID, iface, from string, coordKey trust.Key, peers map[trust.Key]wgconf.PeerStatus, now time.Time) State {
	st := State{Format: format, Created: now.UTC(), From: from, NetworkID: networkID, Interface: iface, Peers: []Peer{}}
	for key, p := range peers {
		if p.Relayed || !p.Endpoint.IsValid() || p.LastHandshakeUnix <= 0 {
			continue
		}
		hs := time.Unix(p.LastHandshakeUnix, 0).UTC()
		if now.Sub(hs) > fresh {
			continue
		}
		ep, ok := validEndpoint(p.Endpoint.String())
		if !ok {
			continue
		}
		hp := Peer{Key: hex.EncodeToString(key[:]), Endpoint: ep.String(), Handshake: hs}
		if key == coordKey {
			st.Coordinator = &hp
			continue
		}
		if len(st.Peers) < maxPeers {
			st.Peers = append(st.Peers, hp)
		}
	}
	sort.Slice(st.Peers, func(i, j int) bool { return st.Peers[i].Key < st.Peers[j].Key })
	return st
}

// Write saves the snapshot into dir (created 0700; the file is 0600 and,
// on Windows, inherits the service folder's administrators-only access).
func Write(dir string, st State) error {
	st.Format = format
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if len(data) > maxFile {
		return errors.New("handover: too large")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return securefile.Replace(filepath.Join(dir, FileName), data)
}

// Take reads and removes the handover file of dir. It is used at most once:
// the file is removed whether or not it is usable. A file other users can
// read (POSIX), a damaged file, one for another network or one older than
// MaxAge is refused.
func Take(dir, networkID string, now time.Time) (*State, error) {
	path := filepath.Join(dir, FileName)
	data, err := securefile.ReadPrivate(path, maxFile)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNone
	}
	rmErr := os.Remove(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	if rmErr != nil && !errors.Is(rmErr, fs.ErrNotExist) {
		// A file that cannot be removed would be offered again: refuse it.
		return nil, fmt.Errorf("%w: not removable: %v", ErrCorrupt, rmErr)
	}
	var st State
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&st); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: trailing data", ErrCorrupt)
	}
	if st.Format != format || len(st.Peers) > maxPeers {
		return nil, fmt.Errorf("%w: format", ErrCorrupt)
	}
	if st.Created.After(now.Add(futureSkew)) || now.Sub(st.Created) > MaxAge {
		return nil, ErrStale
	}
	if st.NetworkID != networkID {
		return nil, fmt.Errorf("%w: another network", ErrCorrupt)
	}
	return &st, nil
}

// Endpoint cache of internal/node (F-005, endpoints.json in the member
// state folder). The engine reads it at start and gives every tunnel peer
// without an endpoint its cached one, before it contacts the coordinator.
// The format is that file's: version 1, network id, coordinator and peers
// by hex key with the time they were last confirmed.
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

// EndpointCacheFile is the engine's cache name in the member state folder.
const EndpointCacheFile = "endpoints.json"

const endpointCacheVersion = 1

// Seed folds the handover's endpoints into the engine's endpoint cache at
// path and returns how many peers it set. Entries of the cache that the
// handover does not mention are kept; a cache of another network or format
// is replaced.
func Seed(path string, st *State, now time.Time) (int, error) {
	if st == nil {
		return 0, nil
	}
	c := endpointCache{Version: endpointCacheVersion, NetworkID: st.NetworkID, Peers: map[string]cachedEndpoint{}}
	if data, err := securefile.ReadPrivate(path, maxFile); err == nil {
		var old endpointCache
		if json.Unmarshal(data, &old) == nil && old.Version == endpointCacheVersion && old.NetworkID == st.NetworkID && old.Peers != nil {
			c = old
		}
	}
	seen := func(hs time.Time) time.Time {
		// The cache refuses future-dated entries; the handshake is recent.
		if hs.After(now) {
			hs = now
		}
		return hs.UTC().Truncate(time.Second)
	}
	n := 0
	for _, p := range st.Peers {
		raw, err := hex.DecodeString(p.Key)
		ep, ok := validEndpoint(p.Endpoint)
		if err != nil || len(raw) != trust.KeySize || !ok {
			continue
		}
		c.Peers[p.Key] = cachedEndpoint{Endpoint: ep.String(), Seen: seen(p.Handshake)}
		n++
	}
	if co := st.Coordinator; co != nil {
		if ep, ok := validEndpoint(co.Endpoint); ok {
			c.Coordinator = &cachedEndpoint{Endpoint: ep.String(), Seen: seen(co.Handshake)}
		}
	}
	if len(c.Peers) > maxPeers {
		return n, errors.New("handover: endpoint cache too large")
	}
	data, err := json.Marshal(c)
	if err != nil {
		return n, err
	}
	return n, securefile.Replace(path, data)
}

// Keeper keeps the latest snapshot of a running tunnel and writes it when
// the service stops.
type Keeper struct {
	// Dir is the private folder of the handover file.
	Dir string
	// Capture returns a fresh snapshot; ok is false when the tunnel cannot
	// say (it is going down).
	Capture func() (State, bool)
	// OnStop is called with the parent context done, before the handover
	// is written (Linux keeps the TUN for an update); nil does nothing.
	OnStop func()
	// Logf reports what was written; nil discards it.
	Logf func(format string, args ...any)

	mu   sync.Mutex
	last *State
}

// Snapshot refreshes the kept snapshot.
func (k *Keeper) Snapshot() {
	if st, ok := k.Capture(); ok {
		k.mu.Lock()
		k.last = &st
		k.mu.Unlock()
	}
}

// Run refreshes the snapshot every SnapshotEvery until run ends. When
// stopping is done (the service stops, not just this tunnel) it writes
// the handover: a fresh snapshot if the tunnel still answers, else the
// last one.
func (k *Keeper) Run(run context.Context, stopping func() bool) {
	k.Snapshot()
	t := time.NewTicker(SnapshotEvery)
	defer t.Stop()
	for {
		select {
		case <-run.Done():
			if stopping() {
				if k.OnStop != nil {
					k.OnStop()
				}
				k.Flush()
			}
			return
		case <-t.C:
			k.Snapshot()
		}
	}
}

// Flush writes the newest snapshot it can get.
func (k *Keeper) Flush() {
	k.Snapshot()
	k.mu.Lock()
	st := k.last
	k.mu.Unlock()
	if st == nil {
		return
	}
	if err := Write(k.Dir, *st); err != nil {
		if k.Logf != nil {
			k.Logf("handover not written: %v", err)
		}
		return
	}
	if k.Logf != nil {
		k.Logf("handover written: %d peers", len(st.Peers))
	}
}
