package filter

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/openscale/openscale/internal/packet"
)

// Quarantine, decoy ports and isolation (ADR-0189, #626, #627, #609).
//
//   - Quarantine: a quarantined peer's packets are refused in both
//     directions, including replies of flows that were open and traffic it
//     sends through this exit node, until the owner releases it or the
//     quarantine ends. A port scan (#626) or a decoy hit (#627) can put the
//     peer into quarantine at once instead of the timed block of ADR-0102.
//     The node keeps the list in its state directory, so a restart does
//     not lift it. Quarantine is local: removing the peer from the network
//     still takes the owner's signature.
//   - Decoy ports: ports of this device that look like SSH, RDP or SMB to
//     a scanner. Unlike canary ports they are checked before the rules:
//     even a rule that opens the port cannot hide a touch. A peer's new
//     connection to one is refused, reported and quarantined. Only ports
//     this device does not really serve belong here.
//   - Isolation: every packet to and from peers and the internet through
//     the tunnel is refused (lost mode, #609). The coordinator's control
//     traffic does not pass the filter and keeps working.

// DecoyPreset are the ports "ssh", "rdp" and "smb" stand for.
var DecoyPreset = map[string][]uint16{
	"ssh": {22},
	"rdp": {3389},
	"smb": {139, 445},
}

// MaxDecoyPorts bounds the decoy port list.
const MaxDecoyPorts = 32

// MaxQuarantined bounds the quarantine list.
const MaxQuarantined = 1024

// Threat kinds added by ADR-0189.
const (
	// ThreatDecoy: a peer touched a decoy port.
	ThreatDecoy ThreatKind = "decoy_port"
	// ThreatQuarantine: a peer was put into quarantine.
	ThreatQuarantine ThreatKind = "quarantine"
)

// ErrDecoy is wrapped by decoy validation errors.
var ErrDecoy = errors.New("tuzak port ayarı geçersiz")

// G3Config configures quarantine and decoys; the zero value is off.
type G3Config struct {
	// DecoyPorts are TCP and UDP ports of this device that nothing really
	// serves. Any new connection from a peer quarantines it.
	DecoyPorts []uint16 `json:"decoy_ports,omitempty"`
	// QuarantineOnScan quarantines a scanning peer instead of the timed
	// block of ThreatConfig.
	QuarantineOnScan bool `json:"quarantine_on_scan,omitempty"`
	// QuarantineFor limits a quarantine; zero lasts until released.
	QuarantineFor time.Duration `json:"quarantine_for,omitempty"`
}

// Validate checks the configuration.
func (c G3Config) Validate() error {
	if len(c.DecoyPorts) > MaxDecoyPorts {
		return fmt.Errorf("%w: en fazla %d tuzak port", ErrDecoy, MaxDecoyPorts)
	}
	for _, p := range c.DecoyPorts {
		if p == 0 {
			return fmt.Errorf("%w: port 0 olamaz", ErrDecoy)
		}
	}
	if c.QuarantineFor != 0 && (c.QuarantineFor < MinBlockFor || c.QuarantineFor > 30*24*time.Hour) {
		return fmt.Errorf("%w: karantina süresi %s ile 30 gün arasında olmalı", ErrDecoy, MinBlockFor)
	}
	return nil
}

// DecoyPortsFor expands preset names ("ssh", "rdp", "smb") and numbers.
func DecoyPortsFor(names []string) ([]uint16, error) {
	var out []uint16
	for _, n := range names {
		if ports, ok := DecoyPreset[n]; ok {
			out = append(out, ports...)
			continue
		}
		var p int
		if _, err := fmt.Sscanf(n, "%d", &p); err != nil || p < 1 || p > 65535 || fmt.Sprint(p) != n {
			return nil, fmt.Errorf("%w: %q bir port veya ssh, rdp, smb olmalı", ErrDecoy, n)
		}
		out = append(out, uint16(p))
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// QuarantineEntry is one quarantined peer.
type QuarantineEntry struct {
	Peer   string    `json:"peer"`
	Reason string    `json:"reason"`
	Since  time.Time `json:"since"`
	// Until is zero for a quarantine that lasts until released.
	Until time.Time `json:"until,omitzero"`
}

type g3FilterState struct {
	cfg        G3Config
	decoy      map[uint16]bool
	quarantine map[string]QuarantineEntry
	isolated   bool
	// onQuarantine is called (on its own goroutine) when the list changes,
	// so the node can save it.
	onQuarantine func([]QuarantineEntry)
}

// SetG3 installs the decoy and quarantine configuration. onChange, when
// not nil, receives the quarantine list after every change.
func (f *Filter) SetG3(c G3Config, onChange func([]QuarantineEntry)) error {
	if err := c.Validate(); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.g3.cfg = c
	f.g3.decoy = map[uint16]bool{}
	for _, p := range c.DecoyPorts {
		f.g3.decoy[p] = true
	}
	f.g3.onQuarantine = onChange
	if f.g3.quarantine == nil {
		f.g3.quarantine = map[string]QuarantineEntry{}
	}
	return nil
}

// SetIsolated turns isolation (lost mode) on or off.
func (f *Filter) SetIsolated(on bool) {
	f.mu.Lock()
	f.g3.isolated = on
	if on {
		f.flows = map[flowKey]time.Time{}
	}
	f.mu.Unlock()
}

// Isolated reports whether isolation is on.
func (f *Filter) Isolated() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.g3.isolated
}

// Quarantine puts peer into quarantine (zero d: until released).
func (f *Filter) Quarantine(peer, reason string, d time.Duration) error {
	if peer == "" {
		return errors.New("cihaz adı boş")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.quarantineLocked(peer, reason, d, f.now())
}

func (f *Filter) quarantineLocked(peer, reason string, d time.Duration, now time.Time) error {
	if f.g3.quarantine == nil {
		f.g3.quarantine = map[string]QuarantineEntry{}
	}
	if _, ok := f.g3.quarantine[peer]; !ok && len(f.g3.quarantine) >= MaxQuarantined {
		return fmt.Errorf("karantina listesi dolu (%d)", MaxQuarantined)
	}
	e := QuarantineEntry{Peer: peer, Reason: reason, Since: now.Truncate(time.Minute)}
	if d > 0 {
		e.Until = now.Add(d)
	}
	f.g3.quarantine[peer] = e
	f.dropFlowsOfLocked(peer)
	f.notifyQuarantineLocked()
	return nil
}

// Release lifts a quarantine and reports whether there was one.
func (f *Filter) Release(peer string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.g3.quarantine[peer]; !ok {
		return false
	}
	delete(f.g3.quarantine, peer)
	f.notifyQuarantineLocked()
	return true
}

// Quarantined returns the current quarantine list, sorted by peer.
func (f *Filter) Quarantined() []QuarantineEntry {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.quarantineListLocked()
}

// RestoreQuarantine replaces the list (loaded from disk); expired entries
// are skipped.
func (f *Filter) RestoreQuarantine(list []QuarantineEntry) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.now()
	f.g3.quarantine = map[string]QuarantineEntry{}
	for _, e := range list {
		if e.Peer == "" || (!e.Until.IsZero() && !now.Before(e.Until)) || len(f.g3.quarantine) >= MaxQuarantined {
			continue
		}
		f.g3.quarantine[e.Peer] = e
	}
}

func (f *Filter) quarantineListLocked() []QuarantineEntry {
	out := slices.Collect(maps.Values(f.g3.quarantine))
	slices.SortFunc(out, func(a, b QuarantineEntry) int {
		switch {
		case a.Peer < b.Peer:
			return -1
		case a.Peer > b.Peer:
			return 1
		}
		return 0
	})
	return out
}

func (f *Filter) notifyQuarantineLocked() {
	if cb := f.g3.onQuarantine; cb != nil {
		list := f.quarantineListLocked()
		go cb(list)
	}
}

// dropFlowsOfLocked forgets the flows whose remote end is peer.
func (f *Filter) dropFlowsOfLocked(peer string) {
	for k := range f.flows {
		if f.peers[k.remote] == peer {
			delete(f.flows, k)
		}
	}
}

// quarantinedLocked reports whether peer is in quarantine now.
func (f *Filter) quarantinedLocked(peer string) bool {
	e, ok := f.g3.quarantine[peer]
	if !ok {
		return false
	}
	if !e.Until.IsZero() && !f.now().Before(e.Until) {
		delete(f.g3.quarantine, peer)
		f.notifyQuarantineLocked()
		return false
	}
	return true
}

// g3InboundLocked runs before the normal inbound decision. refuse is true
// when the packet must be dropped. Called with f.mu held.
func (f *Filter) g3InboundLocked(info packet.Info) (refuse bool) {
	if f.g3.isolated {
		return true
	}
	peer, ok := f.peers[info.Src]
	if !ok {
		return false
	}
	if f.quarantinedLocked(peer) {
		return true
	}
	if len(f.g3.decoy) > 0 && f.selfIPs[info.Dst] && hasPorts(info) && newAttempt(info) && f.g3.decoy[info.DstPort] {
		now := f.now()
		_ = f.quarantineLocked(peer, fmt.Sprintf("tuzak port %d", info.DstPort), f.g3.cfg.QuarantineFor, now)
		if f.threats != nil {
			f.raiseLocked(ThreatEvent{Kind: ThreatDecoy, Peer: peer, Port: info.DstPort}, now, false)
		}
		return true
	}
	return false
}

// g3OutboundLocked refuses packets to quarantined peers and everything
// while isolated. Called with f.mu held.
func (f *Filter) g3OutboundLocked(info packet.Info) bool {
	if f.g3.isolated {
		return true
	}
	if peer, ok := f.peers[info.Dst]; ok && f.quarantinedLocked(peer) {
		return true
	}
	return false
}

// scanQuarantineLocked is called when a scan or canary blocks peer: with
// QuarantineOnScan the peer is quarantined as well.
func (f *Filter) scanQuarantineLocked(ev ThreatEvent, now time.Time) {
	if !f.g3.cfg.QuarantineOnScan || ev.Peer == "" {
		return
	}
	switch ev.Kind {
	case ThreatInboundScan, ThreatCanaryPort, ThreatCanaryAddress:
	default:
		return
	}
	if _, ok := f.g3.quarantine[ev.Peer]; ok {
		return
	}
	_ = f.quarantineLocked(ev.Peer, string(ev.Kind), f.g3.cfg.QuarantineFor, now)
}
