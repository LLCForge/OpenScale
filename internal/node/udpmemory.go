package node

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"maps"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/osnet"
	"github.com/openscale/openscale/internal/securefile"
)

// UDP block memory (#393). When a network turns out to block UDP and the
// coordinator is reached over the TCP transport (ADR-0032), a keyed
// fingerprint of that network (osnet.NetworkFingerprint) is remembered.
// Joining the same network again starts on TCP at once instead of waiting
// for failed syncs. The UDP echo of the TCP transport keeps running, so a
// network that unblocked UDP moves back to UDP and is forgotten.
//
// The file is owner-only, holds no network names (only keyed hashes with a
// random per-device salt) and every entry expires.
const (
	udpMemoryFile    = "udp-blocked.json"
	udpMemoryVersion = 1
	// udpMemoryMaxAge forgets a network not confirmed as blocked for this long.
	udpMemoryMaxAge = 30 * 24 * time.Hour
	// udpMemoryMaxEntries bounds the remembered networks.
	udpMemoryMaxEntries = 64
	// maxUDPMemoryFile bounds the file read.
	maxUDPMemoryFile = 16 << 10
	udpMemorySaltLen = 16
)

type udpMemoryData struct {
	Version int                  `json:"version"`
	Salt    string               `json:"salt"`
	Blocked map[string]time.Time `json:"blocked"`
}

// udpMemory is the remembered set of UDP-blocking networks.
type udpMemory struct {
	path  string
	now   func() time.Time
	ident func() ([]osnet.CurrentNetwork, error)

	mu     sync.Mutex
	loaded bool
	data   udpMemoryData
}

func newUDPMemory(path string, now func() time.Time, ident func() ([]osnet.CurrentNetwork, error)) *udpMemory {
	return &udpMemory{path: path, now: now, ident: ident}
}

// parseUDPMemory reads the file, dropping malformed, expired and
// future-dated entries. A bad salt yields an empty memory with no salt.
func parseUDPMemory(raw []byte, now time.Time) udpMemoryData {
	out := udpMemoryData{Version: udpMemoryVersion, Blocked: map[string]time.Time{}}
	var in udpMemoryData
	if err := json.Unmarshal(raw, &in); err != nil || in.Version != udpMemoryVersion {
		return out
	}
	salt, err := hex.DecodeString(in.Salt)
	if err != nil || len(salt) != udpMemorySaltLen {
		return out
	}
	out.Salt = in.Salt
	for fp, at := range in.Blocked {
		if len(fp) != osnet.NetworkFingerprintLen || !isLowerHex(fp) {
			continue
		}
		if at.After(now.Add(time.Minute)) || now.Sub(at) > udpMemoryMaxAge {
			continue
		}
		out.Blocked[fp] = at
		if len(out.Blocked) >= udpMemoryMaxEntries {
			break
		}
	}
	return out
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// loadLocked reads the file once; mu is held.
func (m *udpMemory) loadLocked() {
	if m.loaded {
		return
	}
	m.loaded = true
	m.data = udpMemoryData{Version: udpMemoryVersion, Blocked: map[string]time.Time{}}
	raw, err := securefile.ReadPrivate(m.path, maxUDPMemoryFile)
	if err == nil {
		m.data = parseUDPMemory(raw, m.now())
	}
	if m.data.Salt == "" {
		var salt [udpMemorySaltLen]byte
		if _, err := rand.Read(salt[:]); err == nil {
			m.data.Salt = hex.EncodeToString(salt[:])
		}
	}
}

// fingerprint returns the current network's fingerprint, "" when it cannot
// be identified.
func (m *udpMemory) fingerprint() string {
	if m == nil || m.ident == nil {
		return ""
	}
	nets, err := m.ident()
	if err != nil {
		return ""
	}
	m.mu.Lock()
	m.loadLocked()
	salt, _ := hex.DecodeString(m.data.Salt)
	m.mu.Unlock()
	return osnet.NetworkFingerprint(nets, salt)
}

// blocked reports whether fp is remembered as blocking UDP.
func (m *udpMemory) blocked(fp string) bool {
	if m == nil || fp == "" {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.loadLocked()
	at, ok := m.data.Blocked[fp]
	return ok && m.now().Sub(at) <= udpMemoryMaxAge
}

// note remembers (blocked) or forgets fp and saves the file when it changed.
func (m *udpMemory) note(fp string, blocked bool) error {
	if m == nil || fp == "" {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.loadLocked()
	if m.data.Salt == "" {
		return errors.New("udp memory: no salt")
	}
	now := m.now()
	_, had := m.data.Blocked[fp]
	if blocked {
		m.data.Blocked[fp] = now
		for len(m.data.Blocked) > udpMemoryMaxEntries {
			// Drop the oldest entry.
			keys := slices.Collect(maps.Keys(m.data.Blocked))
			oldest := slices.MinFunc(keys, func(a, b string) int { return m.data.Blocked[a].Compare(m.data.Blocked[b]) })
			delete(m.data.Blocked, oldest)
		}
	} else {
		if !had {
			return nil
		}
		delete(m.data.Blocked, fp)
	}
	raw, err := json.Marshal(m.data)
	if err != nil {
		return err
	}
	return securefile.Replace(m.path, raw)
}

// udpMemoryPath is where the memory lives: next to the stored document.
func (e *Engine) udpMemoryPath() string {
	if e.cfg.Store == nil || e.cfg.Store.Dir() == "" {
		return ""
	}
	return filepath.Join(e.cfg.Store.Dir(), udpMemoryFile)
}

// recallUDPBlock starts on the TCP transport when the current network is
// remembered as blocking UDP. It runs on its own goroutine (reading the
// network name may take a moment).
func (e *Engine) recallUDPBlock() {
	m := e.p03.udpMem
	if m == nil || e.tcp == nil || e.tcp.forced {
		return
	}
	fp := m.fingerprint()
	e.p03.setFingerprint(fp)
	if fp == "" || e.tcp.Active() || !m.blocked(fp) {
		return
	}
	e.logger.Info("this network blocked UDP before; starting on the TCP transport")
	e.tcp.want(true)
}

// onTCPUp runs when the TCP transport carries the coordinator traffic:
// UDP did not work on this network, remember it.
func (e *Engine) onTCPUp() {
	e.kickCoordinator()
	if e.tcp == nil || e.tcp.forced || e.p03.udpMem == nil {
		return
	}
	go func() {
		fp := e.p03.udpMem.fingerprint()
		e.p03.setFingerprint(fp)
		if err := e.p03.udpMem.note(fp, true); err != nil {
			e.logger.Debug("udp memory", "error", err.Error())
		}
	}()
}

// onTCPDown runs when UDP works again: forget the network.
func (e *Engine) onTCPDown() {
	e.kickCoordinator()
	if e.p03.udpMem == nil {
		return
	}
	go func() {
		fp := e.p03.udpMem.fingerprint()
		e.p03.setFingerprint(fp)
		if err := e.p03.udpMem.note(fp, false); err != nil {
			e.logger.Debug("udp memory", "error", err.Error())
		}
	}()
}

// UDPBlockRemembered reports whether the current network was remembered as
// blocking UDP at the last check (#393).
func (e *Engine) UDPBlockRemembered() bool {
	fp := e.p03.fingerprint()
	return fp != "" && e.p03.udpMem.blocked(fp)
}

// ForgetUDPBlocks deletes the UDP block memory (#393).
func (e *Engine) ForgetUDPBlocks() error {
	m := e.p03.udpMem
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.loadLocked()
	if len(m.data.Blocked) == 0 {
		return nil
	}
	m.data.Blocked = map[string]time.Time{}
	raw, err := json.Marshal(m.data)
	if err != nil {
		return err
	}
	if err := securefile.Replace(m.path, raw); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
