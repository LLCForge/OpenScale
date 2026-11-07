package node

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/openscale/openscale/internal/filter"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

// Device-side opsec of group G3 (ADR-0189, ADR-0190): quarantine and decoy
// ports (#626, #627), lost mode (#609), clone suspicion (#603) and the
// multi-coordinator cross-check (#631).

// QuarantineFile keeps the quarantine list across restarts.
const QuarantineFile = "quarantine.json"

const maxQuarantineFile = 256 << 10

// LostModeFunc reports whether doc marks self as lost. The signed field
// lives in the document (owned by another group); the node only acts on
// the answer.
type LostModeFunc func(doc *trust.Document, self trust.Device) bool

// LostTag is the reserved device tag that marks a device as lost (#609).
// Tags are root-signed and already part of the document, so the mark needs
// no new document field and older clients simply ignore it. The owner sets
// it with `openscale device tag --name <cihaz> --tags kayip` (keeping the
// device's other tags) and removes it the same way.
const LostTag = "kayip"

// LostByTag is the default LostModeFunc: self carries LostTag.
func LostByTag(_ *trust.Document, self trust.Device) bool {
	return slices.Contains(self.Tags, LostTag)
}

// CloneWatchConfig tunes clone suspicion; the zero value is on.
type CloneWatchConfig struct {
	Disable bool `json:"disable,omitempty"`
	// Window is how far back endpoint changes are looked at (default 10
	// min); Flips is how many returns to an earlier address in it count as
	// a suspicion (default 3).
	Window time.Duration `json:"window,omitempty"`
	Flips  int           `json:"flips,omitempty"`
}

// Clone watch bounds.
const (
	DefaultCloneWindow = 10 * time.Minute
	DefaultCloneFlips  = 3
)

func (c CloneWatchConfig) validate() error {
	if c.Window != 0 && (c.Window < time.Minute || c.Window > 24*time.Hour) {
		return errors.New("klon izleme penceresi 1 dakika ile 24 saat arasında olmalı")
	}
	if c.Flips != 0 && (c.Flips < 2 || c.Flips > 100) {
		return errors.New("klon izleme eşiği 2 ile 100 arasında olmalı")
	}
	return nil
}

func (c CloneWatchConfig) window() time.Duration {
	if c.Window == 0 {
		return DefaultCloneWindow
	}
	return c.Window
}

func (c CloneWatchConfig) flips() int {
	if c.Flips == 0 {
		return DefaultCloneFlips
	}
	return c.Flips
}

// setupQuarantine installs decoys and quarantine and loads the saved list.
func (e *Engine) setupQuarantine(c filter.G3Config) error {
	path := e.quarantinePath()
	if err := e.filter.SetG3(c, func(list []filter.QuarantineEntry) { e.saveQuarantine(path, list) }); err != nil {
		return err
	}
	list, err := loadQuarantine(path)
	if err != nil {
		e.logger.Warn("quarantine list", "error", err.Error())
		return nil
	}
	e.filter.RestoreQuarantine(list)
	return nil
}

func (e *Engine) quarantinePath() string {
	if e.cfg.Store == nil || e.cfg.Store.Dir() == "" {
		return ""
	}
	return filepath.Join(e.cfg.Store.Dir(), QuarantineFile)
}

func loadQuarantine(path string) ([]filter.QuarantineEntry, error) {
	if path == "" {
		return nil, nil
	}
	data, err := securefile.ReadLimited(path, maxQuarantineFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var list []filter.QuarantineEntry
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("karantina dosyası bozuk: %w", err)
	}
	return list, nil
}

func (e *Engine) saveQuarantine(path string, list []filter.QuarantineEntry) {
	if path == "" {
		return
	}
	if list == nil {
		list = []filter.QuarantineEntry{}
	}
	data, err := json.MarshalIndent(list, "", "  ")
	if err == nil {
		err = securefile.Replace(path, data)
	}
	if err != nil {
		e.logger.Warn("quarantine list not saved", "error", err.Error())
	}
}

// Quarantine puts a peer into quarantine by name (zero d: until released).
func (e *Engine) Quarantine(peer string, d time.Duration) error {
	doc := e.cfg.Store.Document()
	if _, ok := doc.DeviceByName(peer); !ok {
		return fmt.Errorf("%q adlı cihaz belgede yok", peer)
	}
	return e.filter.Quarantine(peer, "sahip kararı", d)
}

// ReleaseQuarantine lifts a quarantine.
func (e *Engine) ReleaseQuarantine(peer string) bool { return e.filter.Release(peer) }

// Quarantined lists the quarantined peers.
func (e *Engine) Quarantined() []filter.QuarantineEntry { return e.filter.Quarantined() }

// LostStatus is the lost mode state.
type LostStatus struct {
	Lost  bool      `json:"lost"`
	Since time.Time `json:"since,omitzero"`
	// PublicIP is this device's address as the coordinator saw it: the
	// coarse location the coordinator can report to the owner.
	PublicIP string    `json:"public_ip,omitempty"`
	LastSync time.Time `json:"last_sync,omitzero"`
}

// checkLost applies or lifts lost mode.
func (e *Engine) checkLost() {
	f := e.cfg.G3.Lost
	if f == nil {
		f = LostByTag // signed device tag (#609)
	}
	doc := e.cfg.Store.Document()
	self, err := e.Self()
	lost := err == nil && doc != nil && f(doc, self)
	s := &e.g3
	s.mu.Lock()
	was := !s.lostSince.IsZero()
	switch {
	case lost && !was:
		s.lostSince = e.cfg.Now()
	case !lost && was:
		s.lostSince = time.Time{}
	}
	s.mu.Unlock()
	if lost == was {
		return
	}
	e.filter.SetIsolated(lost)
	if lost {
		// Only the coordinator tunnel stays: no exit node, no peer.
		_ = e.SetExitNode("")
		e.raiseG3(G3Alert{Kind: "lost_mode", Text: "Cihaz kayıp olarak işaretlendi: yalnızca koordinatör bağlantısı açık, yerel oturumlar kapatılıyor."})
		if cb := e.cfg.G3.OnLost; cb != nil {
			go cb()
		}
		return
	}
	e.logger.Info("lost mode lifted")
}

// LostStatus reports lost mode.
func (e *Engine) LostStatus() LostStatus {
	s := &e.g3
	s.mu.Lock()
	since := s.lostSince
	s.mu.Unlock()
	e.mu.Lock()
	defer e.mu.Unlock()
	st := LostStatus{Lost: !since.IsZero(), Since: since, LastSync: e.status.LastSync}
	if st.Lost {
		st.PublicIP = e.publicIP
	}
	return st
}

// CloneSuspect is one peer whose key seems to be used at two places.
type CloneSuspect struct {
	Peer      string   `json:"peer"`
	Flips     int      `json:"flips"`
	Addresses []string `json:"addresses"`
}

// cloneFlips counts, within window before now, how often the endpoint
// address returned to one seen earlier but not just before (A, B, A).
// Relayed entries and port-only changes do not count.
func cloneFlips(h []EndpointChange, now time.Time, window time.Duration) (int, []string) {
	var seq []netip.Addr
	for _, c := range h {
		if c.Relayed || now.Sub(c.At) > window {
			continue
		}
		ap, err := netip.ParseAddrPort(c.Endpoint)
		if err != nil {
			continue
		}
		a := ap.Addr().Unmap()
		if len(seq) > 0 && seq[len(seq)-1] == a {
			continue
		}
		seq = append(seq, a)
	}
	flips := 0
	for i := 2; i < len(seq); i++ {
		if slices.Contains(seq[:i-1], seq[i]) {
			flips++
		}
	}
	var addrs []string
	for _, a := range seq {
		if s := a.String(); !slices.Contains(addrs, s) {
			addrs = append(addrs, s)
		}
	}
	return flips, addrs
}

// CloneSuspects looks at every peer's endpoint history (#603). Normal
// roaming moves forward (home, phone network, office); a key that keeps
// jumping back and forth between two places points to a copied key.
func (e *Engine) CloneSuspects() []CloneSuspect {
	c := e.cfg.G3.CloneWatch
	if c.Disable {
		return nil
	}
	now := e.cfg.Now()
	doc := e.cfg.Store.Document()
	names := map[trust.Key]string{}
	for _, d := range doc.Devices {
		names[d.WireGuardKey] = d.Name
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []CloneSuspect
	for k, h := range e.epHistory {
		n, addrs := cloneFlips(h, now, c.window())
		if n >= c.flips() && names[k] != "" {
			out = append(out, CloneSuspect{Peer: names[k], Flips: n, Addresses: addrs})
		}
	}
	slices.SortFunc(out, func(a, b CloneSuspect) int { return compareStrings(a.Peer, b.Peer) })
	return out
}

func (e *Engine) checkClones() {
	for _, s := range e.CloneSuspects() {
		e.raiseG3(G3Alert{Kind: "clone_suspect", Peer: s.Peer,
			Text: fmt.Sprintf("%s cihazının anahtarı kısa sürede %d kez iki ayrı yer arasında gidip geldi; anahtar kopyalanmış olabilir.", s.Peer, s.Flips)})
	}
}

// CoordinatorCrossCheck extends the integrity report (#154) with the
// checks of #631: the document should name at least two coordinators at
// different hosts, and each should have answered recently. A coordinator
// that stays silent while others answer may be censoring this device.
func (e *Engine) CoordinatorCrossCheck() IntegrityReport {
	rep := e.CoordinatorIntegrity()
	doc := e.cfg.Store.Document()
	now := e.cfg.Now()
	coords := doc.AllCoordinators()
	hosts := map[string]bool{}
	for _, c := range coords {
		hosts[endpointHost(c.Endpoint)] = true
	}
	switch {
	case len(coords) < 2:
		rep.Findings = append(rep.Findings, IntegrityFinding{Severity: "uyari",
			Text: "Belgede tek koordinatör var; başka bir sağlayıcıdaki ikinci koordinatör olmadan sahte belge veya sansür çapraz denetlenemez."})
	case len(hosts) < 2:
		rep.Findings = append(rep.Findings, IntegrityFinding{Severity: "uyari",
			Text: "Koordinatörlerin hepsi aynı sunucu adresinde; ayrı sağlayıcılarda çalışmaları önerilir."})
	}
	fresh := 0
	for _, v := range rep.Coordinators {
		if now.Sub(v.At) <= integrityFresh {
			fresh++
		}
	}
	if len(coords) >= 2 && fresh < 2 && fresh < len(coords) {
		rep.Findings = append(rep.Findings, IntegrityFinding{Severity: "uyari",
			Text: fmt.Sprintf("Son dakikalarda %d koordinatörden yalnızca %d tanesi yanıt verdi; çapraz denetim eksik.", len(coords), fresh)})
	}
	return rep
}

func endpointHost(ep string) string {
	if ap, err := netip.ParseAddrPort(ep); err == nil {
		return ap.Addr().String()
	}
	for i := len(ep) - 1; i >= 0; i-- {
		if ep[i] == ':' {
			return ep[:i]
		}
	}
	return ep
}

// runG3 is the periodic G3 work: lost mode, clone suspicion, the exit
// canary and the cross-check alarms.
func (e *Engine) runG3(ctx context.Context) {
	t := time.NewTicker(g3Tick)
	defer t.Stop()
	for {
		e.checkLost()
		if !e.cfg.G3.CloneWatch.Disable {
			e.checkClones()
		}
		e.runCanary(ctx, defaultCanaryDial, nil)
		for _, f := range e.CoordinatorCrossCheck().Findings {
			if f.Severity == "kritik" {
				e.raiseG3(G3Alert{Kind: "coordinators", Peer: f.Coordinator, Text: f.Text})
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// g3Tick is how often runG3 looks.
const g3Tick = 15 * time.Second
