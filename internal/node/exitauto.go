package node

import (
	"context"
	"slices"
	"time"

	"github.com/openscale/openscale/internal/osnet"
	"github.com/openscale/openscale/internal/trust"
)

// Automatic exit node choice (ADR-0133): failover between exit nodes and
// the lowest-latency choice (#81, F-035), and turning the exit node on
// only on untrusted networks (#80).
//
// The controller only calls SetExitNode. When every candidate is down it
// keeps the current choice, so internet traffic stays in the tunnel (and
// is dropped) instead of leaking to the local network; with the kill switch
// on, nothing leaves during a switch either.

// Exit choice modes.
const (
	// ExitModeFailover uses the first healthy candidate in order and goes
	// back to an earlier one after it has been healthy for a while.
	ExitModeFailover = "failover"
	// ExitModeFastest uses the healthy candidate with the lowest probe
	// round trip and switches only for a clearly faster one.
	ExitModeFastest = "fastest"
)

// Controller timing.
const (
	exitAutoInterval = 10 * time.Second
	// exitHandshakeFresh: a WireGuard session with keepalives renews its
	// handshake every two minutes; older means the exit is gone.
	exitHandshakeFresh = 3*time.Minute + 20*time.Second
	// exitProbeFresh is how recent a probe answer must be.
	exitProbeFresh = 2 * time.Minute
	// exitSwitchAfter failed checks in a row trigger a failover.
	exitSwitchAfter = 2
	// exitStableFor is how long a candidate must stay healthy before the
	// controller moves to it while the current one still works.
	exitStableFor = 2 * time.Minute
	// exitStartGrace leaves a new exit node time for its first handshake.
	exitStartGrace = 30 * time.Second
)

// ExitAutoConfig configures RunExitAuto.
type ExitAutoConfig struct {
	// Candidates are exit node names in order of preference; empty means
	// every exit node of the network this device may use, in document
	// order.
	Candidates []string
	// Mode is ExitModeFailover or ExitModeFastest; empty is failover.
	Mode string
	// Untrusted, when set, turns the exit node on only while a network
	// that the trust list does not cover is in use (#80).
	Untrusted *osnet.NetworkTrust
	// Networks reads the current networks (osnet.CurrentNetworks).
	Networks func() ([]osnet.CurrentNetwork, error)
	// OnChange reports a decision ("" is no exit node) and why.
	OnChange func(exit, reason string)
	// Interval overrides the check interval (tests).
	Interval time.Duration
}

// ExitHealth is one candidate's state at a check.
type ExitHealth struct {
	Name   string
	Online bool
	// RTT is the probe round trip; zero when unknown.
	RTT time.Duration
}

// exitChooser holds the hysteresis state between checks.
type exitChooser struct {
	mode         string
	failStreak   int
	healthySince map[string]time.Time
	activeSince  map[string]time.Time
}

func newExitChooser(mode string) *exitChooser {
	if mode != ExitModeFastest {
		mode = ExitModeFailover
	}
	return &exitChooser{mode: mode, healthySince: map[string]time.Time{}, activeSince: map[string]time.Time{}}
}

// choose returns the exit node to use. order lists the candidates; health
// has an entry for each. The current choice is kept while it works, after
// one failed check, and when no candidate works at all.
func (c *exitChooser) choose(now time.Time, current string, order []string, health map[string]ExitHealth) (string, string) {
	for _, n := range order {
		if health[n].Online {
			if _, ok := c.healthySince[n]; !ok {
				c.healthySince[n] = now
			}
		} else {
			delete(c.healthySince, n)
		}
	}
	stable := func(n string) bool {
		since, ok := c.healthySince[n]
		return ok && now.Sub(since) >= exitStableFor
	}
	cur, curOK := health[current]
	inOrder := slices.Contains(order, current)
	if current != "" && inOrder {
		if _, ok := c.activeSince[current]; !ok {
			c.activeSince[current] = now
		}
		if !cur.Online && now.Sub(c.activeSince[current]) < exitStartGrace {
			cur.Online, curOK = true, true // waiting for the first handshake
		}
	}
	if current != "" && inOrder && curOK && cur.Online {
		c.failStreak = 0
		switch c.mode {
		case ExitModeFailover:
			for _, n := range order {
				if n == current {
					break
				}
				if stable(n) {
					return c.switchTo(now, n), "öncelikli çıkış düğümü yeniden sağlıklı"
				}
			}
		case ExitModeFastest:
			best := c.fastest(order, health, stable)
			if best != "" && best != current && cur.RTT > 0 && health[best].RTT > 0 && health[best].RTT*10 < cur.RTT*7 {
				return c.switchTo(now, best), "belirgin şekilde daha hızlı çıkış düğümü"
			}
		}
		return current, ""
	}
	if current != "" && inOrder {
		c.failStreak++
		if c.failStreak < exitSwitchAfter {
			return current, ""
		}
	}
	var next string
	if c.mode == ExitModeFastest {
		next = c.fastest(order, health, func(string) bool { return true })
	} else {
		for _, n := range order {
			if health[n].Online {
				next = n
				break
			}
		}
	}
	if next == "" {
		// Nothing works: keep the choice, traffic stays in the tunnel.
		if current == "" && len(order) > 0 {
			return c.switchTo(now, order[0]), "hiçbir çıkış düğümü yanıt vermiyor; trafik tünelde tutuluyor"
		}
		return current, ""
	}
	if next == current {
		return current, ""
	}
	reason := "çıkış düğümü yanıt vermiyor, yedeğe geçildi"
	if current == "" || !inOrder {
		reason = "çıkış düğümü seçildi"
	}
	return c.switchTo(now, next), reason
}

func (c *exitChooser) switchTo(now time.Time, n string) string {
	c.failStreak = 0
	c.activeSince = map[string]time.Time{n: now}
	return n
}

func (c *exitChooser) fastest(order []string, health map[string]ExitHealth, ok func(string) bool) string {
	best := ""
	for _, n := range order {
		h := health[n]
		if !h.Online || !ok(n) {
			continue
		}
		if best == "" {
			best = n
			continue
		}
		b := health[best]
		if h.RTT > 0 && (b.RTT == 0 || h.RTT < b.RTT) {
			best = n
		}
	}
	return best
}

// exitCandidates resolves the candidate list against doc.
func exitCandidates(doc *trust.Document, self trust.Device, want []string) []string {
	usable := func(n string) bool {
		if n == self.Name {
			return false
		}
		if d, ok := doc.DeviceByName(n); ok {
			return d.HasRole(trust.RoleExitNode)
		}
		_, ok := doc.ExternalExitByName(n)
		return ok
	}
	var out []string
	if len(want) > 0 {
		for _, n := range want {
			if usable(n) && !slices.Contains(out, n) {
				out = append(out, n)
			}
		}
		return out
	}
	for _, d := range doc.Devices {
		if usable(d.Name) {
			out = append(out, d.Name)
		}
	}
	return out
}

// ExitHealthNow measures the candidates: a fresh WireGuard handshake or a
// fresh probe answer counts as online; RTT comes from the probe.
func (e *Engine) ExitHealthNow(names []string) map[string]ExitHealth {
	doc := e.cfg.Store.Document()
	out := make(map[string]ExitHealth, len(names))
	stats, _ := e.PeerStats()
	now := e.cfg.Now()
	for _, n := range names {
		var key trust.Key
		if d, ok := doc.DeviceByName(n); ok {
			key = d.WireGuardKey
		} else if x, ok := doc.ExternalExitByName(n); ok {
			key = x.WireGuardKey
		} else {
			continue
		}
		h := ExitHealth{Name: n}
		if st, ok := stats[key]; ok && st.LastHandshakeUnix > 0 && now.Sub(time.Unix(st.LastHandshakeUnix, 0)) < exitHandshakeFresh {
			h.Online = true
		}
		if rtt, ok := e.probe.bestRTT(key, exitProbeFresh); ok {
			h.Online, h.RTT = true, rtt
		}
		out[n] = h
	}
	return out
}

// bestRTT returns the round trip of a peer's best fresh path.
func (p *prober) bestRTT(key trust.Key, fresh time.Duration) (time.Duration, bool) {
	now := p.now()
	p.mu.Lock()
	defer p.mu.Unlock()
	pp := p.peers[p.byKey[key]]
	if pp == nil {
		return 0, false
	}
	_, v, ok := pp.best(now, fresh)
	return v.rtt, ok && v.rtt > 0
}

// ExitWanted returns the exit node chosen by the owner or the controller.
func (e *Engine) ExitWanted() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.exitWant
}

// RunExitAuto runs the automatic exit node choice until ctx ends.
func (e *Engine) RunExitAuto(ctx context.Context, cfg ExitAutoConfig) {
	every := cfg.Interval
	if every <= 0 {
		every = exitAutoInterval
	}
	chooser := newExitChooser(cfg.Mode)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		e.exitAutoStep(chooser, cfg)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (e *Engine) exitAutoStep(chooser *exitChooser, cfg ExitAutoConfig) {
	doc := e.cfg.Store.Document()
	if doc == nil {
		return
	}
	self, err := e.selfIn(doc)
	if err != nil {
		return
	}
	current := e.ExitWanted()
	if cfg.Untrusted != nil {
		var nets []osnet.CurrentNetwork
		var nerr error = errNoNetworkReader
		if cfg.Networks != nil {
			nets, nerr = cfg.Networks()
		}
		if cfg.Untrusted.IsTrusted(nets, nerr) {
			if current != "" {
				if e.SetExitNode("") == nil && cfg.OnChange != nil {
					cfg.OnChange("", "güvenilir ağ: çıkış düğümü kapatıldı")
				}
			}
			return
		}
	}
	order := exitCandidates(doc, self, cfg.Candidates)
	if len(order) == 0 {
		return
	}
	next, reason := chooser.choose(e.cfg.Now(), current, order, e.ExitHealthNow(order))
	if next == current {
		return
	}
	if err := e.SetExitNode(next); err != nil {
		e.logger.Warn("automatic exit node", "exit", next, "error", err.Error())
		return
	}
	e.logger.Info("automatic exit node", "using", next, "reason", reason)
	if cfg.OnChange != nil {
		cfg.OnChange(next, reason)
	}
}

type exitAutoError string

func (e exitAutoError) Error() string { return string(e) }

const errNoNetworkReader = exitAutoError("ağ bilgisi okunamıyor")
