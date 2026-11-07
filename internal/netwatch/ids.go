// Package netwatch is the network security watch of ADR-0215: a light
// intrusion detector over tunnel packet metadata (#729), an alarm for
// unknown devices on the home LAN (#730) and an audit of the owner's
// devices' internet-facing ports from the exit node (#731).
//
// Nothing here inspects packet contents, sends a packet on its own or
// changes a system setting. The detector sees only addresses, protocol,
// destination port and whether a packet opened a connection; the LAN
// watch reads the neighbour table; the port audit connects only to the
// public address an owner's own device reported, on the ports the owner
// approved.
package netwatch

import (
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"sync"
	"time"
)

// Alert kinds of the detector.
const (
	KindPortScan   = "port_scan"
	KindHostSweep  = "host_sweep"
	KindSYNFlood   = "syn_flood"
	KindBadPorts   = "known_bad_ports"
	KindBruteForce = "brute_force"
)

// Flow is the metadata of one new connection attempt seen inside the
// tunnel (a TCP SYN or the first UDP packet of a flow), as the packet
// filter already knows it. No payload is ever passed in.
type Flow struct {
	At    time.Time
	Src   netip.Addr
	Dst   netip.Addr
	Proto uint8 // IANA protocol number: 6 tcp, 17 udp
	Port  uint16
	// Dropped is true when the packet filter refused the attempt.
	Dropped bool
}

// Alert is one detected pattern.
type Alert struct {
	Kind  string     `json:"kind"`
	Src   netip.Addr `json:"src"`
	Dst   netip.Addr `json:"dst,omitzero"`
	Port  uint16     `json:"port,omitempty"`
	Count int        `json:"count"`
	At    time.Time  `json:"at"`
	// Quarantine suggests isolating the source device; the owner decides
	// (fwtemplate.Quarantine builds the rules).
	Quarantine bool   `json:"quarantine"`
	Message    string `json:"message"`
}

// IDSConfig holds the detector's thresholds; zero fields take defaults.
type IDSConfig struct {
	// Window is how far back counts reach.
	Window time.Duration
	// ScanPorts distinct destination ports on one host within Window is a
	// port scan.
	ScanPorts int
	// SweepHosts distinct hosts on one port within Window is a sweep.
	SweepHosts int
	// FloodRate new attempts per FloodWindow from one source is a flood.
	FloodRate   int
	FloodWindow time.Duration
	// BruteAttempts new connections to one login port of one host within
	// Window is a brute force pattern.
	BruteAttempts int
	// BadPorts distinct known abused ports within Window raise an alert.
	BadPorts int
	// Cooldown suppresses the same alert kind for the same source.
	Cooldown time.Duration
	// LoginPorts and AbusedPorts override the built-in port lists.
	LoginPorts  []uint16
	AbusedPorts []uint16
}

// Detector defaults.
const (
	defaultWindow      = time.Minute
	defaultScanPorts   = 20
	defaultSweepHosts  = 16
	defaultFloodRate   = 200
	defaultFloodWindow = 10 * time.Second
	defaultBrute       = 30
	defaultBadPorts    = 3
	defaultCooldown    = 15 * time.Minute
	maxSources         = 4096
	maxEventsPerSource = 2048
	bruteWindowFactor  = 5
)

// DefaultLoginPorts are services whose repeated new connections look like
// password guessing: SSH, Telnet, SMB, RDP, VNC and OpenScale's own SSH.
var DefaultLoginPorts = []uint16{22, 23, 445, 3389, 5900, 4022}

// DefaultAbusedPorts are ports that worms and remote access tools use
// and that no home service should be dialed on: Telnet alternates, ADB
// over TCP, IRC bots, common reverse shell listeners, router management
// exploits and old backdoors.
var DefaultAbusedPorts = []uint16{2323, 4444, 5555, 6667, 7547, 12345, 31337, 37215, 52869}

func (c IDSConfig) withDefaults() IDSConfig {
	if c.Window <= 0 {
		c.Window = defaultWindow
	}
	if c.ScanPorts <= 0 {
		c.ScanPorts = defaultScanPorts
	}
	if c.SweepHosts <= 0 {
		c.SweepHosts = defaultSweepHosts
	}
	if c.FloodRate <= 0 {
		c.FloodRate = defaultFloodRate
	}
	if c.FloodWindow <= 0 {
		c.FloodWindow = defaultFloodWindow
	}
	if c.BruteAttempts <= 0 {
		c.BruteAttempts = defaultBrute
	}
	if c.BadPorts <= 0 {
		c.BadPorts = defaultBadPorts
	}
	if c.Cooldown <= 0 {
		c.Cooldown = defaultCooldown
	}
	if c.LoginPorts == nil {
		c.LoginPorts = DefaultLoginPorts
	}
	if c.AbusedPorts == nil {
		c.AbusedPorts = DefaultAbusedPorts
	}
	return c
}

type event struct {
	at   time.Time
	dst  netip.Addr
	port uint16
	tcp  bool
}

type source struct {
	events []event
	last   time.Time
	alerts map[string]time.Time
}

// Detector keeps a sliding window per source address. It is safe for
// concurrent use and bounded in memory.
type Detector struct {
	cfg     IDSConfig
	mu      sync.Mutex
	sources map[netip.Addr]*source
	horizon time.Duration
}

// NewDetector returns a detector with cfg's thresholds.
func NewDetector(cfg IDSConfig) *Detector {
	cfg = cfg.withDefaults()
	h := max(cfg.Window*bruteWindowFactor, cfg.FloodWindow)
	return &Detector{cfg: cfg, sources: map[netip.Addr]*source{}, horizon: h}
}

// Observe adds one flow and returns the alerts it completes.
func (d *Detector) Observe(f Flow) []Alert {
	if !f.Src.IsValid() || !f.Dst.IsValid() {
		return nil
	}
	f.Src, f.Dst = f.Src.Unmap(), f.Dst.Unmap()
	d.mu.Lock()
	defer d.mu.Unlock()
	s, ok := d.sources[f.Src]
	if !ok {
		if len(d.sources) >= maxSources {
			d.evict(f.At)
		}
		s = &source{alerts: map[string]time.Time{}}
		d.sources[f.Src] = s
	}
	s.last = f.At
	cut := f.At.Add(-d.horizon)
	i := 0
	for i < len(s.events) && s.events[i].at.Before(cut) {
		i++
	}
	s.events = s.events[i:]
	if len(s.events) >= maxEventsPerSource {
		s.events = s.events[len(s.events)-maxEventsPerSource+1:]
	}
	s.events = append(s.events, event{at: f.At, dst: f.Dst, port: f.Port, tcp: f.Proto == 6})
	return d.evaluate(f, s)
}

func (d *Detector) evict(now time.Time) {
	var victim netip.Addr
	var oldest time.Time
	for a, s := range d.sources {
		if now.Sub(s.last) > d.horizon {
			delete(d.sources, a)
			continue
		}
		if !victim.IsValid() || s.last.Before(oldest) {
			victim, oldest = a, s.last
		}
	}
	if len(d.sources) >= maxSources && victim.IsValid() {
		delete(d.sources, victim)
	}
}

func (d *Detector) evaluate(f Flow, s *source) []Alert {
	c := d.cfg
	var out []Alert
	emit := func(a Alert) {
		key := a.Kind
		if t, ok := s.alerts[key]; ok && f.At.Sub(t) < c.Cooldown {
			return
		}
		s.alerts[key] = f.At
		a.Src, a.At = f.Src, f.At
		out = append(out, a)
	}
	winStart := f.At.Add(-c.Window)
	floodStart := f.At.Add(-c.FloodWindow)
	bruteStart := f.At.Add(-c.Window * bruteWindowFactor)
	ports := map[uint16]bool{}
	hosts := map[netip.Addr]bool{}
	bad := map[uint16]bool{}
	flood, brute := 0, 0
	isLogin := f.Proto == 6 && slices.Contains(c.LoginPorts, f.Port)
	for _, e := range s.events {
		if !e.at.Before(floodStart) {
			flood++
		}
		if isLogin && e.tcp && e.dst == f.Dst && e.port == f.Port && !e.at.Before(bruteStart) {
			brute++
		}
		if e.at.Before(winStart) {
			continue
		}
		if e.dst == f.Dst {
			ports[e.port] = true
		}
		if e.port == f.Port {
			hosts[e.dst] = true
		}
		if slices.Contains(c.AbusedPorts, e.port) {
			bad[e.port] = true
		}
	}
	if len(ports) >= c.ScanPorts {
		emit(Alert{Kind: KindPortScan, Dst: f.Dst, Count: len(ports), Quarantine: true,
			Message: fmt.Sprintf("Bir cihaz %s içinde aynı hedefin %d farklı portunu denedi (port tarama).", c.Window, len(ports))})
	}
	if len(hosts) >= c.SweepHosts {
		emit(Alert{Kind: KindHostSweep, Port: f.Port, Count: len(hosts), Quarantine: true,
			Message: fmt.Sprintf("Bir cihaz %s içinde %d farklı cihazın %d portunu denedi (ağ taraması).", c.Window, len(hosts), f.Port)})
	}
	if flood >= c.FloodRate {
		emit(Alert{Kind: KindSYNFlood, Count: flood, Quarantine: true,
			Message: fmt.Sprintf("Bir cihaz %s içinde %d yeni bağlantı denedi (bağlantı fırtınası).", c.FloodWindow, flood)})
	}
	if len(bad) >= c.BadPorts {
		emit(Alert{Kind: KindBadPorts, Count: len(bad), Quarantine: true,
			Message: fmt.Sprintf("Bir cihaz kötü amaçlı yazılımların kullandığı %d farklı portu denedi: %s.", len(bad), portList(bad))})
	}
	if isLogin && brute >= c.BruteAttempts {
		emit(Alert{Kind: KindBruteForce, Dst: f.Dst, Port: f.Port, Count: brute, Quarantine: false,
			Message: fmt.Sprintf("Bir cihaz %s içinde %d portuna %d kez bağlanmaya çalıştı (parola deneme kalıbı).", c.Window*bruteWindowFactor, f.Port, brute)})
	}
	return out
}

func portList(m map[uint16]bool) string {
	ps := make([]int, 0, len(m))
	for p := range m {
		ps = append(ps, int(p))
	}
	sort.Ints(ps)
	return fmt.Sprint(ps)
}

// Sources reports how many sources are tracked (for diagnostics).
func (d *Detector) Sources() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.sources)
}
