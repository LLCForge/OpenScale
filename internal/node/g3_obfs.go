package node

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/openscale/openscale/internal/filter"
	"github.com/openscale/openscale/internal/obfs"
)

// Network opsec options of group G3 (ADR-0186..0191). Each is off by
// default; nothing here weakens a protection that is on.

// G3Config gathers the options. Every field is local to this device
// (never signed): none of them can widen what the document allows.
type G3Config struct {
	// Obfs disguises WireGuard datagrams and wraps the TCP transport in
	// TLS (#612, #613, #615, #616; ADR-0186).
	Obfs ObfsConfig
	// ExitChain sends the WireGuard datagrams for the exit node in use
	// through a second exit node (#618, ADR-0187).
	ExitChain ExitChainConfig
	// ExitCanary checks, while an exit node is in use, that TLS servers
	// still show the keys seen without it (#628, ADR-0188).
	ExitCanary ExitCanaryConfig
	// ExitDNSPins are SPKI pins ("sha256/<base64>") the DoH or DoT server
	// of ExitDNSUpstream must match (#624, ADR-0188).
	ExitDNSPins []string
	// ExitDNSRequirePins refuses an exit DNS upstream without pins: plain
	// DNS, the recursive resolver and unpinned DoH/DoT drop members'
	// queries instead (#624).
	ExitDNSRequirePins bool
	// Lost reports whether the owner marked this device lost (#609,
	// ADR-0190); nil is never lost. The signed field itself belongs to the
	// document (another group); this is the node side.
	Lost LostModeFunc
	// OnLost is called once each time lost mode starts, so the service can
	// close local sessions (remote desktop, SSH, file transfers) and lock
	// the screen.
	OnLost func()
	// CloneWatch looks for a peer key seen at two places at once (#603,
	// ADR-0190). The zero value turns it on with defaults.
	CloneWatch CloneWatchConfig
	// Decoys configures decoy ports and quarantine (#626, #627,
	// ADR-0189); the zero value is off.
	Decoys filter.G3Config
	// OnAlert receives every G3 alarm on its own goroutine.
	OnAlert func(G3Alert)
}

// G3Alert is one alarm for the owner. It never carries payloads, keys or
// secrets.
type G3Alert struct {
	// Kind is "exit_mitm", "clone_suspect", "lost_mode", "coordinators".
	Kind string    `json:"kind"`
	Peer string    `json:"peer,omitempty"`
	Text string    `json:"text"`
	At   time.Time `json:"at"`
}

// ObfsConfig configures the transport disguise (ADR-0186).
type ObfsConfig struct {
	// Mode: off, auto (accept both, answer in kind) or on (disguise all).
	Mode obfs.Mode
	// Padding buckets for the disguised datagrams (#615); empty uses
	// obfs.DefaultBuckets while Mode is not off.
	Padding obfs.Padding
	// Jitter delays bulk datagrams (#616); zero is off.
	Jitter obfs.Jitter
	// TLS wraps the coordinator TCP transport in TLS (#613); nil keeps
	// the plain stream.
	TLS *obfs.ClientTLS
}

// g3State is the engine state of the G3 options.
type g3State struct {
	obfs *obfs.Bind

	mu        sync.Mutex
	alerts    []G3Alert
	alerted   map[string]time.Time
	canary    canaryState
	lostSince time.Time
	chain     *chainState
}

const (
	maxG3Alerts   = 64
	g3AlertRepeat = time.Hour
)

// setupG3 validates the options and installs the parts that must exist
// before Run.
func (e *Engine) setupG3() error {
	if err := e.loadG3File(); err != nil {
		return err
	}
	g := &e.cfg.G3
	o := &g.Obfs
	if o.Mode != obfs.ModeOff {
		if len(o.Padding.Buckets) == 0 {
			o.Padding = obfs.DefaultPadding()
		}
		if err := o.Padding.Validate(); err != nil {
			return err
		}
		if err := o.Jitter.Validate(); err != nil {
			return err
		}
	} else if o.Jitter.Max != 0 {
		return errors.New("zamanlama gürültüsü yalnızca trafik gizleme açıkken kullanılabilir")
	}
	if o.TLS != nil {
		if e.tcp == nil {
			return errors.New("TLS gizleme TCP yedek aktarımı gerektirir")
		}
		cfg, err := o.TLS.Config(e.cfg.Now)
		if err != nil {
			return err
		}
		e.tcp.camo = func(c net.Conn) (net.Conn, error) {
			return obfs.DialTLS(c, cfg.Clone(), tcpDialTimeout)
		}
	}
	if err := e.validateChain(); err != nil {
		return err
	}
	if err := g.ExitCanary.validate(); err != nil {
		return err
	}
	if err := e.validateExitDNSPins(); err != nil {
		return err
	}
	if err := g.CloneWatch.validate(); err != nil {
		return err
	}
	return e.setupQuarantine(g.Decoys)
}

// wrapObfs installs the disguise under the TCP fallback and relay, so
// those see plain WireGuard datagrams. Off returns b unchanged.
func (e *Engine) wrapObfs(b conn.Bind) conn.Bind {
	o := e.cfg.G3.Obfs
	if o.Mode == obfs.ModeOff {
		return b
	}
	doc := e.cfg.Store.Document()
	key, err := obfs.DeriveKey(doc.NetworkID)
	if err != nil {
		e.logger.Warn("traffic disguise off", "error", err.Error())
		return b
	}
	ob, err := obfs.NewBind(b, obfs.Options{Mode: o.Mode, Key: key, Padding: o.Padding, Jitter: o.Jitter, Now: e.cfg.Now})
	if err != nil {
		e.logger.Warn("traffic disguise off", "error", err.Error())
		return b
	}
	e.g3.obfs = ob
	e.logger.Info("traffic disguise", "mode", o.Mode.String(), "jitter", o.Jitter.Max.String(), "tls", o.TLS != nil)
	return ob
}

// ObfsStatus is the disguise state for diagnostics and the panel.
type ObfsStatus struct {
	Mode    string     `json:"mode"`
	TLS     bool       `json:"tls"`
	Buckets []int      `json:"buckets,omitempty"`
	Jitter  string     `json:"jitter,omitempty"`
	Stats   obfs.Stats `json:"stats"`
}

// ObfsStatus reports the disguise settings and counters.
func (e *Engine) ObfsStatus() ObfsStatus {
	o := e.cfg.G3.Obfs
	st := ObfsStatus{Mode: o.Mode.String(), TLS: o.TLS != nil, Buckets: o.Padding.Buckets}
	if o.Jitter.Max > 0 {
		st.Jitter = o.Jitter.Max.String()
	}
	if b := e.g3.obfs; b != nil {
		st.Stats = b.Stats()
	}
	return st
}

// raiseG3 records an alarm once per kind and peer per hour and notifies.
func (e *Engine) raiseG3(a G3Alert) {
	a.At = e.cfg.Now().Truncate(time.Minute)
	key := a.Kind + "\x00" + a.Peer
	s := &e.g3
	s.mu.Lock()
	if s.alerted == nil {
		s.alerted = map[string]time.Time{}
	}
	if until, ok := s.alerted[key]; ok && a.At.Before(until) {
		s.mu.Unlock()
		return
	}
	if len(s.alerted) > 4*maxG3Alerts {
		clear(s.alerted)
	}
	s.alerted[key] = a.At.Add(g3AlertRepeat)
	if len(s.alerts) >= maxG3Alerts {
		s.alerts = s.alerts[1:]
	}
	s.alerts = append(s.alerts, a)
	s.mu.Unlock()
	e.logger.Warn("opsec alarm", "kind", a.Kind, "peer", a.Peer, "text", a.Text)
	if f := e.cfg.G3.OnAlert; f != nil {
		go f(a)
	}
}

// G3Alerts returns the recent alarms, oldest first.
func (e *Engine) G3Alerts() []G3Alert {
	s := &e.g3
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]G3Alert(nil), s.alerts...)
}

// describeObfs is a one-line summary for logs and the CLI.
func describeObfs(o ObfsConfig) string {
	if o.Mode == obfs.ModeOff {
		return "kapalı"
	}
	s := fmt.Sprintf("kip=%s kovalar=%v", o.Mode, o.Padding.Buckets)
	if o.Jitter.Max > 0 {
		s += " gürültü<=" + o.Jitter.Max.String()
	}
	if o.TLS != nil {
		s += " tls=" + o.TLS.ServerName
	}
	return s
}
