package netwatch

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/securefile"
)

// Unknown LAN device alarm (#730). The home server running OpenScale reads
// the operating system's neighbour table (Linux /proc/net/arp, Windows
// GetIpNetTable, macOS the routing socket's link-layer entries) without
// sending anything, and reports MAC addresses it has not seen before.
//
// Only the vendor prefix (first three bytes) and a keyed digest of each
// MAC address are stored. The key is random per installation and lives in
// the private state file, so the stored digests cannot be matched against
// a list of addresses elsewhere.

// Neighbor is one neighbour table entry.
type Neighbor struct {
	Addr netip.Addr
	MAC  net.HardwareAddr
}

// Neighbors reads this computer's IPv4 neighbour table. It returns nil
// where the table cannot be read.
func Neighbors() []Neighbor { return readNeighbors() }

// Known is one remembered device.
type Known struct {
	OUI       string    `json:"oui"`
	Digest    string    `json:"digest"`
	Random    bool      `json:"random,omitempty"`
	Label     string    `json:"label,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// NewDevice is a MAC address seen for the first time.
type NewDevice struct {
	OUI    string     `json:"oui"`
	Digest string     `json:"digest"`
	Random bool       `json:"random"`
	Addr   netip.Addr `json:"addr"`
	At     time.Time  `json:"at"`
}

// Message is the owner-facing text; the LAN address is left to the panel.
func (n NewDevice) Message() string {
	if n.Random {
		return "Ev ağına rastgele MAC adresli yeni bir cihaz katıldı (telefonların gizli Wi-Fi adresi olabilir)."
	}
	return "Ev ağına daha önce görülmemiş bir cihaz katıldı (üretici öneki " + n.OUI + ")."
}

// LAN watch limits.
const (
	maxKnown     = 4096
	maxLabel     = 64
	maxStateFile = 2 << 20
	digestBytes  = 16
	lanSchema    = 1
)

// LANWatch remembers the devices of one LAN. It is safe for concurrent
// use.
type LANWatch struct {
	mu    sync.Mutex
	key   []byte
	known map[string]*Known // by digest
	// Learning is true until the first observation: the devices present
	// then become the baseline without alarms.
	Learning bool
	// IgnoreRandom skips locally administered (randomized) addresses.
	IgnoreRandom bool
}

// NewLANWatch returns an empty watch with a fresh random key, in learning
// mode.
func NewLANWatch() (*LANWatch, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return &LANWatch{key: key, known: map[string]*Known{}, Learning: true}, nil
}

func validUnicast(mac net.HardwareAddr) bool {
	if len(mac) != 6 || mac[0]&1 != 0 {
		return false
	}
	for _, b := range mac {
		if b != 0 {
			return true
		}
	}
	return false
}

// Digest returns the keyed digest of mac.
func (w *LANWatch) Digest(mac net.HardwareAddr) string {
	h := hmac.New(sha256.New, w.key)
	h.Write([]byte("openscale-lan-v1"))
	h.Write(mac)
	return hex.EncodeToString(h.Sum(nil)[:digestBytes])
}

func ouiOf(mac net.HardwareAddr) string {
	return fmt.Sprintf("%02x:%02x:%02x", mac[0], mac[1], mac[2])
}

// Observe compares a neighbour table read with the known devices and
// returns the new ones. In learning mode it records them silently.
func (w *LANWatch) Observe(neighbors []Neighbor, now time.Time) []NewDevice {
	w.mu.Lock()
	defer w.mu.Unlock()
	learning := w.Learning
	w.Learning = false
	var out []NewDevice
	seen := map[string]bool{}
	for _, n := range neighbors {
		if !validUnicast(n.MAC) {
			continue
		}
		random := n.MAC[0]&2 != 0
		if random && w.IgnoreRandom {
			continue
		}
		d := w.Digest(n.MAC)
		if seen[d] {
			continue
		}
		seen[d] = true
		if k, ok := w.known[d]; ok {
			k.LastSeen = now
			continue
		}
		if len(w.known) >= maxKnown {
			w.evictOldest()
		}
		w.known[d] = &Known{OUI: ouiOf(n.MAC), Digest: d, Random: random, FirstSeen: now, LastSeen: now}
		if !learning {
			out = append(out, NewDevice{OUI: ouiOf(n.MAC), Digest: d, Random: random, Addr: n.Addr.Unmap(), At: now})
		}
	}
	return out
}

func (w *LANWatch) evictOldest() {
	var victim string
	var oldest time.Time
	for d, k := range w.known {
		if victim == "" || k.LastSeen.Before(oldest) {
			victim, oldest = d, k.LastSeen
		}
	}
	delete(w.known, victim)
}

// Label names a known device (the owner's "this is the printer").
func (w *LANWatch) Label(digest, label string) error {
	label = strings.TrimSpace(label)
	if len(label) > maxLabel || strings.ContainsAny(label, "\r\n\t") {
		return fmt.Errorf("etiket en fazla %d karakter olmalı", maxLabel)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	k, ok := w.known[digest]
	if !ok {
		return errors.New("böyle bir cihaz kaydı yok")
	}
	k.Label = label
	return nil
}

// Forget removes a known device so it alarms again when it returns.
func (w *LANWatch) Forget(digest string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	_, ok := w.known[digest]
	delete(w.known, digest)
	return ok
}

// Known lists the remembered devices, most recently seen first.
func (w *LANWatch) Known() []Known {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]Known, 0, len(w.known))
	for _, k := range w.known {
		out = append(out, *k)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].LastSeen.Equal(out[j].LastSeen) {
			return out[i].LastSeen.After(out[j].LastSeen)
		}
		return out[i].Digest < out[j].Digest
	})
	return out
}

type lanState struct {
	Schema       int     `json:"schema"`
	Key          string  `json:"key"`
	Learning     bool    `json:"learning"`
	IgnoreRandom bool    `json:"ignore_random,omitempty"`
	Known        []Known `json:"known"`
}

// Save writes the watch (with its key) as a private file.
func (w *LANWatch) Save(path string) error {
	w.mu.Lock()
	st := lanState{Schema: lanSchema, Key: hex.EncodeToString(w.key), Learning: w.Learning, IgnoreRandom: w.IgnoreRandom}
	for _, k := range w.known {
		st.Known = append(st.Known, *k)
	}
	w.mu.Unlock()
	sort.Slice(st.Known, func(i, j int) bool { return st.Known[i].Digest < st.Known[j].Digest })
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return securefile.Replace(path, data)
}

// LoadLANWatch reads a file written by Save.
func LoadLANWatch(path string) (*LANWatch, error) {
	data, err := securefile.ReadPrivate(path, maxStateFile)
	if err != nil {
		return nil, err
	}
	var st lanState
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("LAN cihaz kaydı okunamadı: %w", err)
	}
	if st.Schema != lanSchema {
		return nil, fmt.Errorf("LAN cihaz kaydı sürümü %d desteklenmiyor", st.Schema)
	}
	key, err := hex.DecodeString(st.Key)
	if err != nil || len(key) != 32 {
		return nil, errors.New("LAN cihaz kaydının anahtarı bozuk")
	}
	w := &LANWatch{key: key, known: map[string]*Known{}, Learning: st.Learning, IgnoreRandom: st.IgnoreRandom}
	for _, k := range st.Known {
		if len(w.known) >= maxKnown || len(k.Digest) != 2*digestBytes || len(k.OUI) != 8 {
			continue
		}
		k := k
		w.known[k.Digest] = &k
	}
	return w, nil
}
