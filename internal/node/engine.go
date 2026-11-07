// Package node is the device daemon engine: it keeps the WireGuard device
// in line with the latest root-signed document, exchanges endpoints through
// the coordinator, and enforces the packet filter (ADR-0013).
package node

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"math/rand/v2"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/filter"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/memprofile"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/wgconf"
)

const (
	keepaliveSeconds    = 25
	defaultPollInterval = 15 * time.Second
	staleHandshake      = 2 * time.Minute
	// Coordinator retry after a failed sync (F-006): from syncRetryBase
	// (or the poll interval, if shorter) doubling up to syncRetryMax.
	syncRetryBase   = 2 * time.Second
	syncRetryMax    = time.Minute
	syncRetryJitter = 0.2
)

// Tunnel MTU (F-019). The default leaves room for a relayed packet, which
// is encrypted twice (ADR-0017); 1420 is WireGuard's usual value for a
// direct path over a 1500-byte network.
const (
	DefaultMTU = 1280
	MinMTU     = 1280
	MaxMTU     = 1420
)

// ValidateMTU checks a manually configured tunnel MTU.
func ValidateMTU(mtu int) error {
	if mtu < MinMTU || mtu > MaxMTU {
		return fmt.Errorf("MTU %d geçersiz; %d ile %d arasında olmalı", mtu, MinMTU, MaxMTU)
	}
	return nil
}

// Bounds for the configurable relay timings (F-026).
const (
	minRelayAfter        = time.Second
	maxRelayAfter        = 10 * time.Minute
	minDirectRetry       = 10 * time.Second
	maxDirectRetryConfig = 24 * time.Hour
)

// ErrNotMember is returned when this device's key is not in the document.
var ErrNotMember = errors.New("this device is not in the network document (revoked or not added yet)")

// Config configures the engine.
type Config struct {
	Store   *member.Store
	Secrets *trust.DeviceSecrets
	// TUN is the OS interface (or a test channel TUN). The engine owns it.
	TUN        tun.Device
	Bind       conn.Bind
	ListenPort int
	// NetworkDir, when set, is the owner's network directory; newer
	// documents found there are adopted and published to the coordinator.
	NetworkDir   string
	PollInterval time.Duration
	// RelayAfter is how long a peer may go without a direct handshake
	// before it is reached through the coordinator (ADR-0017); zero uses
	// the default (30 s). Allowed: 1 s to 10 min.
	RelayAfter time.Duration
	// DirectRetry is how long a relayed peer waits before its direct path
	// is tried again; failed tries double it up to an hour (F-006, F-026).
	// Zero uses the default (5 min). Allowed: 10 s to 24 h.
	DirectRetry time.Duration
	// ForceRelay reaches every peer through the coordinator and never
	// tries a direct path (F-022): this device exchanges UDP with the
	// coordinator only.
	ForceRelay bool
	// MTU is the tunnel interface MTU (F-019): TCP SYNs crossing the
	// tunnel get their MSS clamped to it (F-048). Zero uses DefaultMTU;
	// otherwise it must lie between MinMTU and MaxMTU. The interface
	// itself is created by the caller with the same value.
	MTU int
	// EndpointCache is the file that keeps the last working peer and
	// coordinator endpoints for starting without the coordinator (F-005).
	// Empty uses endpoints.json in the store directory.
	EndpointCache string
	// ExitNode is the name of the exit node to start with ("" for none).
	ExitNode string
	// ExitRouter moves internet traffic into the tunnel while an exit node
	// is in use (OS specific, ADR-0018). Nil keeps the OS routes alone.
	ExitRouter ExitRouter
	// OnExitRole is called when this device gains or loses the exit node
	// role, so the OS can turn forwarding and NAT on or off.
	OnExitRole func(on bool)
	// Routes applies subnet routes, router forwarding and exit node
	// exceptions in the OS (routes.go, ADR-0133). Nil keeps the OS alone.
	Routes RouteApplier
	// Shields refuses every connection other devices open to this one,
	// whatever the rules allow (F-077); SetShields changes it later.
	Shields bool
	// ExitDNSUpstream is the resolver an exit node forwards members' DNS
	// queries to ("" reads /etc/resolv.conf).
	ExitDNSUpstream string
	// ExitDNSVia overrides ExitDNSUpstream while an upstream exit is in
	// use (ADR-0142): members' queries go to server, sent from the
	// upstream tunnel address source so they travel inside that tunnel
	// (or to Tor's DNSPort on loopback for the Tor exit). ok with an
	// invalid server drops the queries (upstream wanted, tunnel missing);
	// ok false uses ExitDNSUpstream. Nil is never an upstream.
	ExitDNSVia func() (server netip.AddrPort, source netip.Addr, ok bool)
	// ExitDNSBlocklist is a local block list file whose names the exit
	// node answers with NXDOMAIN (#91, ADR-0102); never downloaded. ""
	// is none.
	ExitDNSBlocklist string
	// ExitDNSGuard hardens the exit node resolver (P05, exitdns_guard.go);
	// the zero value is the safe default.
	ExitDNSGuard ExitDNSGuardConfig
	// DNSSECTrustAnchors is a file of root DS records that replaces the
	// built-in anchors of the "recursive-dnssec" resolver (#89); "" uses
	// the built-in ones.
	DNSSECTrustAnchors string
	// Threats configures port scan detection and canaries (#106, #246);
	// the zero value turns scan detection and blocking on with defaults.
	Threats filter.ThreatConfig
	// OnThreat is called on its own goroutine for every detection.
	OnThreat func(filter.ThreatEvent)

	// StaticEndpoints are addresses the owner knows this device is
	// reachable at (port forwarding, fixed public IP; F-012). They are
	// reported as candidates before the interface addresses.
	StaticEndpoints []netip.AddrPort
	// HideLocalCandidates keeps this device's interface (LAN, IPv6)
	// addresses from the coordinator; only StaticEndpoints and the
	// coordinator-observed endpoint are then used (ADR-0025 privacy note).
	HideLocalCandidates bool
	// CandidateSkipInterfaces are extra interface name prefixes whose
	// addresses are never reported (F-002 block list).
	CandidateSkipInterfaces []string
	// SealedCandidates chooses how candidates reach peers (ADR-0230, #38):
	// sealed end-to-end for each peer, plainly through the coordinator, or
	// both while a peer that cannot read sealed ones is online (default).
	SealedCandidates SealedCandidatesMode
	// DisableBirthdayScan turns the bounded random port scan between two
	// devices behind port-per-destination NATs off (ADR-0231, #54).
	DisableBirthdayScan bool
	// BirthdayProbes is how many random ports one scan tries; zero uses
	// DefaultBirthdayProbes. Allowed: MinBirthdayProbes to MaxBirthdayProbes.
	BirthdayProbes int
	// DocumentSanitizer, when set, parses every network document received
	// from the network in a less privileged helper first (ADR-0233,
	// #161): it returns the canonical bytes the engine then accepts, or an
	// error that rejects the document.
	DocumentSanitizer func(ctx context.Context, data []byte) ([]byte, error)
	// ConnTrack tunes connection tracking (F-084); zero fields keep the
	// defaults.
	ConnTrack filter.Limits
	// DisableUDPOffload turns Linux UDP GSO/GRO of the WireGuard socket off
	// (F-024) when Bind is nil; elsewhere it has no effect. The TUN side is
	// chosen when the interface is created (osnet.CreateTUN).
	DisableUDPOffload bool
	// MagicDNSAllDevices answers MagicDNS for every device in the document;
	// by default names of devices this one has no tunnel to are not
	// answered (F-069).
	MagicDNSAllDevices bool
	// KillSwitchActive reports whether the OS kill switch is on; together
	// with an active exit node it enables captive portal detection (F-018).
	KillSwitchActive func() bool
	// DisableCaptiveCheck turns captive portal detection off.
	DisableCaptiveCheck bool

	// PostQuantum agrees on an ML-KEM-768 pre-shared key with every peer
	// that supports it (ADR-0033); the zero value is on. Peers that do not
	// answer stay classical.
	PostQuantum PostQuantumMode
	// PSKRotation is how often a new post-quantum PSK is agreed; zero uses
	// DefaultPSKRotation. Allowed: MinPSKRotation to MaxPSKRotation.
	PSKRotation time.Duration

	// TCPFallback is the coordinator's TCP transport address ("host:port"),
	// used only while UDP to the coordinator is blocked (ADR-0032); ""
	// uses the coordinator's host on control.DefaultTCPPort (443).
	TCPFallback string
	// DisableTCPFallback never uses the TCP transport.
	DisableTCPFallback bool

	// Keepalive is WireGuard's persistent keepalive interval for every peer
	// (F-021); zero uses DefaultKeepalive (25 s). Allowed: MinKeepalive to
	// MaxKeepalive in whole seconds.
	Keepalive time.Duration
	// AdaptiveKeepalive shortens a peer's keepalive by a third (down to
	// MinKeepalive) each time its handshake is lost and comes back within
	// ten minutes, and lengthens it again by 5 s after an hour without a
	// loss, never above Keepalive.
	AdaptiveKeepalive bool

	// LazyPeers adds a peer to WireGuard only when this device first sends
	// it a packet the filter allows (or the peer calls or relays to it) and
	// removes it after LazyIdle without traffic (F-020, #170). The
	// coordinator and the exit node in use are always configured.
	LazyPeers bool
	// LazyIdle is how long a lazy peer may stay idle; zero uses
	// DefaultLazyIdle. Allowed: MinLazyIdle to MaxLazyIdle.
	LazyIdle time.Duration

	// PortMap asks the local gateway to forward the WireGuard port (PCP,
	// NAT-PMP, UPnP-IGD) and reports the mapped address as a candidate
	// (ADR-0042, #55). Off by default.
	PortMap PortMapConfig
	// Padding pads packets to size buckets before encryption (ADR-0043,
	// #36). Off by default; PaddingCost estimates its cost.
	Padding PaddingMode
	// CoverTraffic sends random dummy packets to the coordinator at about
	// this many bytes per second (ADR-0043, #37); zero is off (default).
	// Allowed: MinCoverTraffic to MaxCoverTraffic; CoverTrafficCost
	// estimates its cost.
	CoverTraffic int
	// InteractivePriority hands ICMP, SSH, remote desktop and DNS packets
	// to WireGuard before bulk transfers (ADR-0043, #142). Off by default.
	InteractivePriority bool
	// TorSOCKS is the loopback SOCKS5 address of the Tor client installed
	// on this system (for example 127.0.0.1:9050). When set the coordinator
	// is reached only over the TCP transport through Tor, every peer is
	// relayed and no UDP is sent (ADR-0044, #63). Empty is off (default).
	TorSOCKS string
	// StaticEndpointNames are static endpoints given as "name:port" (#387),
	// resolved locally and reported like StaticEndpoints.
	StaticEndpointNames []string
	// DisableNAT64 never synthesizes a NAT64 address for an IPv4
	// coordinator on an IPv6-only network (#384, ADR-0152).
	DisableNAT64 bool
	// NetworkIdentity lists the current networks for the UDP block memory
	// (#393); nil uses osnet.CurrentNetworks.
	NetworkIdentity NetworkIdentityFunc
	// G3 holds the network opsec options of ADR-0186..0191 (g3_*.go):
	// transport disguise, TLS camouflage, exit chaining, exit TLS
	// canaries, DoH pins, lost mode and clone checks. Zero is off.
	G3 G3Config

	Resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	Logger  *slog.Logger
	Now     func() time.Time
}

// Engine is a running device daemon.
type Engine struct {
	cfg    Config
	logger *slog.Logger
	wgKey  trust.Key
	filter *filter.Filter
	// sealer exchanges sealed candidates (ADR-0230); nil when off.
	sealer *sealer
	client *client
	wrap   *wrapTUN
	dev    *device.Device

	mu      sync.Mutex
	self    trust.Device
	status  Status
	applied uint64
	// applyFailed is a document version whose application was rolled
	// back; sync applies it again (atomicapply.go, #199).
	applyFailed uint64
	// admins are the overlay addresses allowed to ask for this device's
	// system report; lastInfo rate-limits the answers.
	admins   map[netip.Addr]bool
	lastInfo map[netip.Addr]time.Time
	publicIP string
	relay    *relayBind
	paths    map[trust.Key]*pathState
	// Exit node state, guarded by mu. exitWant is the owner's choice;
	// exitActive the exit node currently routed; exitRole whether this
	// device forwards for others.
	exitWant   string
	exitActive string
	exitRole   bool
	reapply    chan struct{}
	dnsSem     chan struct{}
	chain      chainRelay // signed two-hop exit (#618, g8_chain_relay.go)

	// routing is the subnet routing state (routes.go, ADR-0133).
	routing routingState

	// Network change events (F-004): netPending holds netEvent bits,
	// netWake wakes the run loop.
	netPending atomic.Uint32
	netWake    chan struct{}
	netProbe   func() (string, error)
	netEvery   time.Duration
	rand       func() float64

	// Endpoint cache (F-005) and the coordinator endpoint, guarded by mu.
	epCache         endpointCache
	epSaved         time.Time
	coordUnresolved bool

	// Coordinator extensions (ADR-0025, ADR-0026), guarded by mu.
	caps       coordCaps
	candKey    string
	candSent   time.Time
	localCands []netip.AddrPort
	// plainCands are the candidates last reported plainly (ADR-0230: none
	// while every online peer reads sealed ones); listenPort the WireGuard
	// port they were gathered for.
	plainCands []netip.AddrPort
	listenPort uint16
	lastNotify time.Time
	// peerInfo is the last coordinator view of each peer.
	peerInfo map[trust.Key]peerInfo
	// mapping is the history of this device's endpoint as the coordinator
	// saw it (F-015); epHistory the endpoint changes of each peer (F-016).
	mapping   []mappingSample
	epHistory map[trust.Key][]EndpointChange
	lastEP    map[trust.Key]string
	// dnsView is the document MagicDNS answers from (F-069).
	dnsView *trust.Document
	// netDNS forwards network DNS through MagicDNS (ADR-0034).
	netDNS netDNSState
	// captive is the last captive portal check (F-018); syncFails counts
	// failed syncs in a row.
	captive     CaptiveStatus
	captiveAt   time.Time
	syncFails   int
	captiveHTTP captiveProber
	captiveBusy atomic.Bool

	probe *prober
	pq    *pqManager
	tcp   *tcpFallback
	spa   *spaKnockBind // SPA knocks to coordinators (w3_spa.go, #614)
	// udpFails counts failed syncs during which nothing arrived from the
	// coordinator (coordRx unchanged), guarded by mu (ADR-0032).
	udpFails int
	coordRx  uint64
	// p03 is the connection package P03 state (p03.go).
	p03 p03State
	// keepalives is the adaptive keepalive state (F-021), guarded by mu.
	keepalives map[trust.Key]*kaState
	lazy       lazyState
	// extras: port mapping, Tor and traffic shaping (ADR-0042..0044).
	extras   extrasState
	syncWake chan struct{}
	pathWake chan struct{}
	// member is the root transition and version report state
	// (membership.go, ADR-0027, ADR-0028).
	member membershipState
	// p15 holds several coordinators, peer document exchange and the
	// coordinator integrity report (p15_*.go, ADR-0111).
	p15 p15Node
	// g3 is the network opsec state (g3_*.go, ADR-0186..0191).
	g3 g3State
}

// Status is a snapshot for logs and the future local status API.
type Status struct {
	DocumentVersion uint64
	DocumentExpires time.Time
	Expired         bool
	Peers           int
	LastSync        time.Time
	LastSyncError   string
	// ExitNode is the exit node in use, "" for none.
	ExitNode string
}

// New prepares an engine; Run starts it.
func New(cfg Config) (*Engine, error) {
	if cfg.Store == nil || cfg.Secrets == nil || cfg.TUN == nil {
		return nil, errors.New("engine needs a store, device key and TUN")
	}
	cfg.Store.SetMembersKey(cfg.Secrets.DeviceID, cfg.Secrets.WireGuardPrivate) // members-only documents (#629, ADR-0178)
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = defaultPollInterval
	}
	if cfg.RelayAfter <= 0 {
		cfg.RelayAfter = defaultRelayAfter
	}
	if cfg.RelayAfter < minRelayAfter || cfg.RelayAfter > maxRelayAfter {
		return nil, fmt.Errorf("aktarıcıya geçiş süresi %s ile %s arasında olmalı", minRelayAfter, maxRelayAfter)
	}
	if cfg.DirectRetry <= 0 {
		cfg.DirectRetry = defaultDirectRetry
	}
	if cfg.DirectRetry < minDirectRetry || cfg.DirectRetry > maxDirectRetryConfig {
		return nil, fmt.Errorf("doğrudan yolu yeniden deneme süresi %s ile %s arasında olmalı", minDirectRetry, maxDirectRetryConfig)
	}
	if cfg.MTU == 0 {
		cfg.MTU = DefaultMTU
	}
	if err := ValidateMTU(cfg.MTU); err != nil {
		return nil, err
	}
	if err := normalizeExtras(&cfg); err != nil {
		return nil, err
	}
	if cfg.ForceRelay && cfg.MTU > DefaultMTU {
		// Every packet is encrypted twice on the relay (ADR-0017); above
		// 1280 the outer packet no longer fits a 1500-byte network.
		return nil, fmt.Errorf("aktarıcı zorunluyken MTU en fazla %d olabilir", DefaultMTU)
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	if cfg.MTU > DefaultMTU {
		cfg.Logger.Warn("tunnel MTU above 1280: packets to relayed peers may be fragmented", "mtu", cfg.MTU)
	}
	if len(cfg.StaticEndpoints) > control.MaxCandidates {
		return nil, fmt.Errorf("en fazla %d statik uç nokta tanımlanabilir", control.MaxCandidates)
	}
	for _, ap := range cfg.StaticEndpoints {
		a := ap.Addr()
		if !ap.IsValid() || ap.Port() == 0 || a.Zone() != "" || a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() || a.IsLinkLocalUnicast() {
			return nil, fmt.Errorf("statik uç nokta %s kullanılamaz", ap)
		}
	}
	if err := checkStaticNames(cfg.StaticEndpointNames, len(cfg.StaticEndpoints)); err != nil {
		return nil, err
	}
	if cfg.PSKRotation == 0 {
		cfg.PSKRotation = DefaultPSKRotation
	}
	if cfg.PSKRotation < MinPSKRotation || cfg.PSKRotation > MaxPSKRotation {
		return nil, fmt.Errorf("PSK yenileme aralığı %s ile %s arasında olmalı", MinPSKRotation, MaxPSKRotation)
	}
	if cfg.Keepalive == 0 {
		cfg.Keepalive = DefaultKeepalive
	}
	if err := ValidateKeepalive(cfg.Keepalive); err != nil {
		return nil, err
	}
	if cfg.LazyIdle == 0 {
		cfg.LazyIdle = DefaultLazyIdle
	}
	if cfg.LazyIdle < MinLazyIdle || cfg.LazyIdle > MaxLazyIdle {
		return nil, fmt.Errorf("tembel eş boşta kalma süresi %s ile %s arasında olmalı", MinLazyIdle, MaxLazyIdle)
	}
	if cfg.TCPFallback != "" {
		if _, port, err := net.SplitHostPort(cfg.TCPFallback); err != nil || port == "" {
			return nil, fmt.Errorf("TCP yedek adresi %q geçersiz; ana-makine:port biçiminde olmalı", cfg.TCPFallback)
		} else if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("TCP yedek adresinin portu %q geçersiz", port)
		}
	}
	if cfg.Resolve == nil {
		cfg.Resolve = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	_, wg, err := cfg.Secrets.PublicKeys()
	if err != nil {
		return nil, err
	}
	e := &Engine{cfg: cfg, logger: cfg.Logger, wgKey: wg, filter: filter.New(cfg.Now),
		exitWant: cfg.ExitNode, reapply: make(chan struct{}, 1), dnsSem: make(chan struct{}, exitDNSConcurrency),
		netWake: make(chan struct{}, 1), netEvery: netWatchInterval, rand: rand.Float64,
		syncWake: make(chan struct{}, 1), pathWake: make(chan struct{}, 1), captiveHTTP: httpCaptiveProber{}}
	// The low memory profile (#392) fills the limits the owner left at 0.
	if err := e.filter.SetLimits(memprofile.FillConnTrack(cfg.ConnTrack)); err != nil {
		return nil, err
	}
	e.probe = newProber(cfg.Now, cfg.Logger, cfg.Secrets.SigningKey())
	if err := e.probe.configureBirthday(cfg.DisableBirthdayScan, cfg.BirthdayProbes); err != nil {
		return nil, err
	}
	e.probe.selfHard = func() bool { return e.selfNATHard(e.currentListenPort()) }
	if cfg.SealedCandidates < SealedCandidatesAuto || cfg.SealedCandidates > SealedCandidatesOff {
		return nil, errors.New("şifreli aday kipi geçersiz")
	}
	if cfg.SealedCandidates != SealedCandidatesOff {
		// ADR-0230: a key error only turns sealing off; the tunnel works.
		if s, err := newSealer(cfg.Secrets.WireGuardPrivate, wg, cfg.Now()); err == nil {
			e.sealer = s
		} else {
			e.logger.Warn("sealed candidates unavailable", "error", err.Error())
		}
	}
	e.probe.improved = func() {
		select {
		case e.pathWake <- struct{}{}:
		default:
		}
	}
	if cfg.PostQuantum.Enabled() {
		e.pq = newPQManager(cfg.Now, cfg.Logger, cfg.Secrets.SigningKey(), wg, cfg.PSKRotation, rand.Float64)
		e.probe.onReset = e.pq.onResetHint
	}
	if !cfg.DisableTCPFallback {
		e.tcp = newTCPFallback(nil, cfg.Logger, cfg.Now)
		e.tcp.dial = e.dialCoordinatorTCP
		e.tcp.onUp = e.kickCoordinator
		e.tcp.onUDP = e.kickCoordinator
	}
	e.spa = newSPAKnockBind(cfg.Now, cfg.Logger) // #614
	if e.tcp != nil {
		e.tcp.knock = e.spaTCPKnock
	}
	if err := e.setupG3(); err != nil { // ADR-0186..0191
		return nil, err
	}
	if err := e.setupExtras(); err != nil {
		return nil, err
	}
	e.initP03()
	tunName, _ := cfg.TUN.Name()
	e.netProbe = interfaceFingerprint(tunName, func() []netip.Prefix {
		doc := cfg.Store.Document()
		return []netip.Prefix{doc.IPv4Prefix, doc.IPv6Prefix}
	})
	if _, err := e.selfIn(cfg.Store.Document()); err != nil {
		return nil, err
	}
	// A device key copied to another computer refuses to start (F-137).
	if err := CheckMachineBinding(cfg.Store.Dir(), cfg.Secrets.DeviceID); err != nil {
		return nil, err
	}
	e.filter.SetShields(cfg.Shields)
	if err := e.setupGuards(); err != nil {
		return nil, err
	}
	e.client = newClient(func(pkt []byte) bool { return e.wrap.Inject(pkt) })
	e.client.onPush = e.onPush
	return e, nil
}

// Document returns the current verified document.
func (e *Engine) Document() *trust.Document { return e.cfg.Store.Document() }

// Self returns this device's entry in the current document.
func (e *Engine) Self() (trust.Device, error) {
	return e.selfIn(e.cfg.Store.Document())
}

func (e *Engine) selfIn(doc *trust.Document) (trust.Device, error) {
	for _, d := range doc.Devices {
		if d.WireGuardKey == e.wgKey {
			return d, nil
		}
	}
	return trust.Device{}, ErrNotMember
}

// SetShields turns the shields on or off at once (F-077).
func (e *Engine) SetShields(on bool) { e.filter.SetShields(on) }

// Status returns the current status.
func (e *Engine) Status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.status
}

// Run brings the tunnel up and keeps it synchronized until ctx ends.
//
// Run returns nil when ctx ends, ErrNotMember when this device left the
// document, and an error wrapping ErrTunnelLost when the OS interface
// stopped working (F-146); the caller may then recreate the interface and
// start a new engine.
func (e *Engine) Run(ctx context.Context) error {
	opts := wrapOptions{filter: e.filter, intercept: e.intercept, local: e.answerDNS, logger: e.logger, mtu: e.cfg.MTU}
	if e.cfg.LazyPeers {
		opts.touch = e.lazyTouch
	}
	opts.pad, opts.classify = e.padder(), e.classifier()
	e.wrap = newWrapTUN(e.cfg.TUN, opts)
	bind := e.cfg.Bind
	if bind == nil {
		bind = newBind(e.cfg.DisableUDPOffload)
	}
	bind = e.wrapObfs(bind) // #612, ADR-0186
	e.spa.Bind = bind       // SPA knock above the disguise (#614)
	bind = e.spa
	if e.tcp != nil {
		e.tcp.Bind = bind
		bind = e.tcp
	}
	e.relay = newRelayBind(bind, e.sendRelay, e.cfg.ForceRelay)
	e.relay.probes = e.probe
	e.probe.sendDirect = e.relay.sendTo
	e.probe.sendRelay = e.sendRelay
	if e.pq != nil {
		e.pq.send = e.sendPQ
		e.pq.setPSK = e.setPSK
		e.pq.status = e.pqStatus
		e.pq.hint = e.probe.sendReset
	}
	dev := device.NewDevice(e.wrap, e.relay, wgLogger(e.logger))
	e.mu.Lock()
	e.dev = dev
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		e.dev = nil
		e.mu.Unlock()
		dev.Close()
	}()
	if err := e.dev.IpcSet(wgconf.Interface(e.cfg.Secrets.WireGuardPrivate, e.cfg.ListenPort)); err != nil {
		return fmt.Errorf("configure wireguard: %w", err)
	}
	doc := e.cfg.Store.Document()
	// The stored document (signature verified when the store was opened,
	// expiry checked by apply) and the cached endpoints bring the tunnels
	// up even if the coordinator does not answer (F-005).
	e.loadEndpointCache(doc)
	if err := e.apply(ctx, doc); err != nil {
		return err
	}
	if err := e.useCachedEndpoints(); err != nil {
		e.logger.Warn("cached endpoints", "error", err.Error())
	}
	if err := e.dev.Up(); err != nil {
		return fmt.Errorf("bring wireguard up: %w", err)
	}
	self, _ := e.Self()
	e.logger.Info("tunnel up", "device", self.Name, "mtu", e.cfg.MTU, "force_relay", e.cfg.ForceRelay)

	// loopCtx also ends when the interface or the WireGuard device dies,
	// so a sync waiting on the coordinator does not delay the exit.
	loopCtx, stop := context.WithCancel(ctx)
	defer stop()
	go func() {
		select {
		case <-e.wrap.Failed():
		case <-dev.Wait():
		case <-loopCtx.Done():
		}
		stop()
	}()
	// The loops below write state (endpoints, quarantine, gossip); Run
	// returns only after they ended so nothing writes once it returned.
	var loops sync.WaitGroup
	spawn := func(f func()) {
		loops.Add(1)
		go func() {
			defer loops.Done()
			f()
		}()
	}
	defer func() {
		stop()
		waitLoops(&loops, e.logger)
	}()
	spawn(func() { e.watchNetwork(loopCtx, newNetWatcher(e.netProbe, e.netEvery), e.netEvery) })
	spawn(e.recallUDPBlock) // #393
	spawn(func() { e.probe.run(loopCtx) })
	spawn(func() { e.runG3(loopCtx) }) // ADR-0186..0191
	if e.pq != nil {
		spawn(func() { e.pq.run(loopCtx) })
	}
	if e.tcp != nil {
		spawn(func() { e.tcp.run(loopCtx) })
	}
	spawn(func() { e.runGossip(loopCtx) }) // #25
	defer e.startExtras(loopCtx)()

	retry := Backoff{Base: min(syncRetryBase, e.cfg.PollInterval), Max: max(syncRetryMax, e.cfg.PollInterval), Jitter: syncRetryJitter, Rand: e.rand}
	timer := time.NewTimer(e.cfg.PollInterval)
	defer timer.Stop()
	for {
		err := e.sync(loopCtx)
		if lost := e.tunnelLost(dev); lost != nil && ctx.Err() == nil {
			e.stopExit()
			return lost
		}
		e.mu.Lock()
		e.status.LastSync = e.cfg.Now()
		e.status.LastSyncError = ""
		if err != nil {
			e.status.LastSyncError = err.Error()
		}
		e.mu.Unlock()
		if err != nil && ctx.Err() == nil {
			e.logger.Warn("sync", "error", err.Error())
		}
		if errors.Is(err, ErrNotMember) {
			return err
		}
		wait := e.cfg.PollInterval
		if err != nil {
			wait = retry.Next()
		} else {
			retry.Reset()
		}
		e.saveEndpoints()
		e.sweepLazy()
		e.updateTransport(err)
		e.noteSync(loopCtx, err == nil)
		timer.Reset(wait)
	waiting:
		for {
			select {
			case <-loopCtx.Done():
				e.stopExit()
				if lost := e.tunnelLost(dev); lost != nil && ctx.Err() == nil {
					return lost
				}
				return nil
			case <-timer.C:
				break waiting
			case <-e.reapply:
				if err := e.apply(loopCtx, e.cfg.Store.Document()); err != nil {
					e.logger.Warn("apply exit node choice", "error", err.Error())
				}
				break waiting
			case <-e.netWake:
				e.onNetworkChange(loopCtx, e.takeNetwork())
				retry.Reset()
				break waiting
			case <-e.syncWake:
				// The coordinator pushed a newer document version (ADR-0026).
				break waiting
			case <-e.pathWake:
				// A probe validated a better path (ADR-0025): move there now
				// and keep waiting for the next poll.
				e.repath()
			}
		}
	}
}

// tunnelLost returns why the tunnel died, or nil while it works.
func (e *Engine) tunnelLost(dev *device.Device) error {
	if err := e.wrap.Err(); err != nil {
		return err
	}
	select {
	case <-dev.Wait():
		return fmt.Errorf("%w: WireGuard aygıtı kapandı", ErrTunnelLost)
	default:
		return nil
	}
}

// onNetworkChange reconnects quickly after the network changed or the
// computer woke up (F-004): the coordinator name is resolved again, path
// selection restarts and every peer gets a new handshake at once. The run
// loop then syncs with the coordinator immediately.
func (e *Engine) onNetworkChange(ctx context.Context, ev netEvent) {
	if ev == 0 {
		return
	}
	e.logger.Info("network change; reconnecting", "event", ev.String())
	if ev&netChanged != 0 {
		e.p03NetworkChanged() // #384, #387, #393
	}
	if err := e.refreshCoordinatorEndpoint(ctx); err != nil {
		e.logger.Warn("coordinator endpoint", "error", err.Error())
	}
	e.resetPaths(ev&netChanged != 0)
	e.extrasNetChanged()
	if ev&netChanged != 0 {
		e.probe.reset()
		if uapi := e.resetKeepalive(); uapi != "" {
			e.mu.Lock()
			dev := e.dev
			e.mu.Unlock()
			if dev != nil {
				if err := dev.IpcSet(uapi); err != nil {
					e.logger.Warn("reset keepalive", "error", err.Error())
				}
			}
		}
	}
	e.kickHandshakes()
}

// kickHandshakes starts a new handshake with every peer, the coordinator
// included. WireGuard rate-limits initiations per peer by itself.
func (e *Engine) kickHandshakes() {
	e.mu.Lock()
	dev := e.dev
	e.mu.Unlock()
	st, err := e.wgStatus()
	if err != nil || dev == nil {
		return
	}
	for key := range st.Peers {
		if p := dev.LookupPeer(device.NoisePublicKey(key)); p != nil {
			_ = p.SendHandshakeInitiation(false)
		}
	}
}

// useCachedEndpoints gives peers without an endpoint their cached one.
func (e *Engine) useCachedEndpoints() error {
	if e.cfg.ForceRelay {
		return nil
	}
	st, err := e.wgStatus()
	if err != nil {
		return err
	}
	var coordKey trust.Key
	if c := e.cfg.Store.Document().Coordinator; c != nil {
		coordKey = c.WireGuardKey
	}
	if uapi := e.applyCachedEndpoints(st, coordKey); uapi != "" {
		return e.dev.IpcSet(uapi)
	}
	return nil
}

// saveEndpoints records the endpoints that work now (F-005).
func (e *Engine) saveEndpoints() {
	if e.cfg.ForceRelay {
		return
	}
	st, err := e.wgStatus()
	if err != nil {
		return
	}
	e.recordEndpoints(e.cfg.Store.Document(), st)
}

func (e *Engine) wgStatus() (wgconf.Status, error) {
	e.mu.Lock()
	dev := e.dev
	e.mu.Unlock()
	if dev == nil {
		return wgconf.Status{}, errors.New("tunnel is not running")
	}
	raw, err := dev.IpcGet()
	if err != nil {
		return wgconf.Status{}, err
	}
	return wgconf.ParseStatus(raw)
}

// refreshCoordinatorEndpoint resolves the coordinator's endpoint again and
// points the coordinator peer at it when it changed, for example after a
// failed lookup at start or a network change (dynamic DNS).
func (e *Engine) refreshCoordinatorEndpoint(ctx context.Context) error {
	doc := e.cfg.Store.Document()
	if doc.Coordinator == nil {
		return nil
	}
	ep, err := e.resolveEndpoint(ctx, doc.Coordinator.Endpoint)
	if err != nil {
		return err
	}
	e.relay.setCoordinator(ep.Addr())
	e.spaSetPrimary(ep)
	if e.tcp != nil {
		e.tcp.setCoordinator(ep)
	}
	e.mu.Lock()
	e.coordUnresolved = false
	dev := e.dev
	e.mu.Unlock()
	st, err := e.wgStatus()
	if err != nil || dev == nil {
		return err
	}
	if cur, ok := st.Peers[doc.Coordinator.WireGuardKey]; !ok || cur.Endpoint == ep {
		return nil
	}
	return dev.IpcSet(wgconf.SetEndpoint(doc.Coordinator.WireGuardKey, ep))
}

// sync runs one round: adopt a newer local document, exchange documents
// with the coordinator, then refresh peer endpoints.
func (e *Engine) sync(ctx context.Context) error {
	if e.cfg.NetworkDir != "" {
		e.adoptLocal(ctx)
	}
	e.retryFailedApply(ctx)
	e.adoptGossip(ctx) // #25
	doc, env, digest := e.cfg.Store.Snapshot()
	if !e.cfg.Now().Before(doc.ExpiresAt) {
		e.expire()
	}
	e.mu.Lock()
	unresolved := e.coordUnresolved
	e.mu.Unlock()
	if unresolved {
		if err := e.refreshCoordinatorEndpoint(ctx); err != nil {
			e.logger.Debug("coordinator endpoint still unresolved", "error", err.Error())
		}
	}
	// The client version goes first when the network has a minimum (F-027).
	hello, err := e.helloAny(ctx, control.Message{T: control.TypeHello, Version: doc.Version, Digest: hex.EncodeToString(digest[:])}) // #153
	if err != nil {
		return err
	}
	if ap, err := netip.ParseAddrPort(hello.Endpoint); err == nil {
		e.mu.Lock()
		e.publicIP = ap.Addr().Unmap().String()
		e.mu.Unlock()
		e.recordMapping(ap)
	}
	e.refreshCaps(ctx)
	e.afterCaps(ctx) // ADR-0111: relay session, other coordinators
	// Root key transitions (ADR-0027): follow a new root or publish ours.
	if applied, err := e.syncRoot(ctx, hello, doc, digest); err != nil {
		e.logger.Warn("root transition", "error", err.Error())
	} else if applied {
		e.reportCandidates(ctx)
		return e.refreshEndpoints(ctx)
	}
	switch {
	case hello.Version > doc.Version:
		if err := e.download(ctx, hello); err != nil {
			return err
		}
	case hello.Version < doc.Version:
		if err := e.upload(ctx, env, digest); err != nil {
			return err
		}
	}
	e.reportCandidates(ctx)
	return e.refreshEndpoints(ctx)
}

func (e *Engine) adoptLocal(ctx context.Context) {
	// network.json is not secret material: its integrity comes from the root
	// signature, which Store.Accept verifies. So it is read with a size
	// limit only; requiring owner-only permissions here silently broke
	// publishing from shared or Windows-mounted directories.
	data, err := securefile.ReadLimited(filepath.Join(e.cfg.NetworkDir, "network.json"), trust.MaxEnvelopeSize)
	if err != nil {
		e.logger.Warn("cannot read the network directory document", "error", err.Error())
		return
	}
	changed, err := e.cfg.Store.Accept(data, e.cfg.Now())
	if err != nil && (errors.Is(err, trust.ErrBadSignature) || errors.Is(err, trust.ErrEpochMismatch)) {
		// The owner rotated or recovered the root key (ADR-0027).
		changed, err = e.adoptLocalTransitions(data)
	}
	if err != nil {
		if !errors.Is(err, trust.ErrRollback) {
			e.logger.Warn("network dir document rejected", "error", err.Error())
		}
		return
	}
	if changed {
		if err := e.applyDoc(ctx, e.cfg.Store.Document()); err != nil {
			e.logger.Warn("apply document", "error", err.Error())
		}
	}
}

func (e *Engine) download(ctx context.Context, hello control.Message) error {
	buf, err := e.fetchDocument(ctx, hello)
	if err != nil {
		return err
	}
	changed, err := e.cfg.Store.Accept(buf, e.cfg.Now())
	if err != nil {
		return fmt.Errorf("coordinator document rejected: %w", err)
	}
	if changed {
		e.logger.Info("new network document", "version", e.cfg.Store.Document().Version)
		return e.applyDoc(ctx, e.cfg.Store.Document())
	}
	return nil
}

// fetchDocument downloads the document announced in hello and checks its
// size and digest. The caller still verifies the signature.
func fetchDocument(ctx context.Context, c *client, hello control.Message) ([]byte, error) {
	if hello.Size <= 0 || hello.Size > trust.MaxEnvelopeSize {
		return nil, errors.New("coordinator announced an invalid document size")
	}
	buf := make([]byte, 0, hello.Size)
	for len(buf) < hello.Size {
		resp, err := c.call(ctx, control.Message{T: control.TypeDoc, Version: hello.Version, Offset: len(buf)})
		if err != nil {
			return nil, err
		}
		if resp.Offset != len(buf) || resp.Total != hello.Size || len(resp.Data) == 0 || len(buf)+len(resp.Data) > hello.Size {
			return nil, errors.New("coordinator sent an unexpected document chunk")
		}
		buf = append(buf, resp.Data...)
	}
	sum := sha256.Sum256(buf)
	if hex.EncodeToString(sum[:]) != hello.Digest {
		return nil, errors.New("document digest mismatch")
	}
	return buf, nil
}

// PeerStats returns WireGuard's view of this device's peers: observed
// endpoint, last handshake and byte counters.
func (e *Engine) PeerStats() (map[trust.Key]wgconf.PeerStatus, error) {
	e.mu.Lock()
	dev := e.dev
	e.mu.Unlock()
	if dev == nil {
		return nil, errors.New("tunnel is not running")
	}
	raw, err := dev.IpcGet()
	if err != nil {
		return nil, err
	}
	st, err := wgconf.ParseStatus(raw)
	if err != nil {
		return nil, err
	}
	return st.Peers, nil
}

// maxPending bounds how many pending enrollments are fetched.
const maxPending = trust.MaxInvites

// Pending fetches the invite enrollments waiting at the coordinator. Only
// devices with the admin role get an answer. The results are unverified;
// admin.Network verifies them against the owner's document.
func (e *Engine) Pending(ctx context.Context) ([]trust.SignedInviteEnrollment, error) {
	var out []trust.SignedInviteEnrollment
	for offset := 0; len(out) < maxPending; {
		resp, err := e.client.call(ctx, control.Message{T: control.TypePending, Offset: offset})
		if err != nil {
			return nil, err
		}
		if resp.T != control.TypePending {
			return nil, errors.New("coordinator sent an unexpected reply")
		}
		if offset >= resp.Total {
			break
		}
		if resp.Offset != offset || resp.Next != offset+1 {
			return nil, errors.New("coordinator sent an unexpected page")
		}
		out = append(out, trust.SignedInviteEnrollment{Payload: resp.Data, DeviceSignature: resp.Sig, InviteSignature: resp.InviteSig})
		offset = resp.Next
	}
	return out, nil
}

func (e *Engine) upload(ctx context.Context, env []byte, digest [32]byte) error {
	hexDigest := hex.EncodeToString(digest[:])
	for off := 0; off < len(env); {
		end := min(off+control.ChunkSize, len(env))
		resp, err := e.client.call(ctx, control.Message{T: control.TypePut, Offset: off, Total: len(env), Digest: hexDigest, Data: env[off:end]})
		if err != nil {
			return err
		}
		if resp.Complete {
			e.logger.Info("published network document to coordinator", "version", e.cfg.Store.Document().Version)
			return nil
		}
		if resp.Offset != end {
			return errors.New("coordinator acknowledged an unexpected offset")
		}
		off = end
	}
	return nil
}

// apply reconfigures WireGuard and the filter for doc.
func (e *Engine) apply(ctx context.Context, doc *trust.Document) error {
	self, err := e.selfIn(doc)
	if err != nil {
		e.filter.Clear()
		e.removeAllPeers()
		return err
	}
	if doc.Coordinator == nil {
		return errors.New("the network document has no coordinator; run 'openscale network set-coordinator'")
	}
	coordEndpoint, err := e.resolveEndpoint(ctx, doc.Coordinator.Endpoint)
	unresolved := err != nil
	if unresolved {
		// Offline start (F-005): keep going with the last endpoint that
		// worked (or none); sync resolves the name again.
		e.logger.Warn("coordinator endpoint not resolved; using the cached one", "error", err.Error())
		coordEndpoint, _ = e.cachedCoordinator()
	}
	if coordEndpoint.IsValid() {
		e.relay.setCoordinator(coordEndpoint.Addr())
		e.spaSetPrimary(coordEndpoint)
		if e.tcp != nil {
			e.tcp.setCoordinator(coordEndpoint)
		}
	}
	e.mu.Lock()
	e.coordUnresolved = unresolved
	e.mu.Unlock()
	e.client.setAddrs(self.IPv4, e.activeCoordinatorIPv4(doc)) // #153

	now := e.cfg.Now()
	want := map[trust.Key]wgconf.Peer{
		doc.Coordinator.WireGuardKey: {
			PublicKey:  doc.Coordinator.WireGuardKey,
			AllowedIPs: wgconf.HostPrefixes(doc.Coordinator.IPv4, doc.Coordinator.IPv6),
			Endpoint:   coordEndpoint,
			Keepalive:  e.keepaliveFor(doc.Coordinator.WireGuardKey),
		},
	}
	extraCoords := e.coordinatorPeers(ctx, doc, want) // #153
	expired := !now.Before(doc.ExpiresAt) || !now.Before(self.ExpiresAt)
	exit := e.exitFor(doc, self)
	if !expired {
		for _, p := range doc.TunnelPeersOf(self.Name) {
			if now.Before(p.ExpiresAt) {
				// A subnet router also carries the routes a rule lets this
				// device reach (ADR-0133).
				allowed := append(wgconf.HostPrefixes(p.IPv4, p.IPv6), doc.RoutesVia(self.Name, p.Name)...)
				if exit != nil && p.Name == exit.Name {
					// The exit node carries every internet address.
					allowed = append(allowed, netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"))
				}
				want[p.WireGuardKey] = wgconf.Peer{PublicKey: p.WireGuardKey, AllowedIPs: allowed, Keepalive: e.keepaliveFor(p.WireGuardKey)}
			}
		}
		// A plain WireGuard exit node is not a member (ADR-0133, F-045).
		exit = e.addExternalExitPeer(ctx, doc, exit, want)
	} else {
		exit = nil
	}
	// fullWant keeps the lazy peers that are not configured right now
	// (F-020): they are still tunnel peers for probing, post-quantum
	// agreement, MagicDNS and the status.
	fullWant := maps.Clone(want)
	always := map[trust.Key]bool{doc.Coordinator.WireGuardKey: true}
	for _, k := range extraCoords {
		always[k] = true
	}
	if exit != nil {
		always[exit.WireGuardKey] = true
	}
	for _, k := range e.routerKeys(doc, self) { // ADR-0133
		always[k] = true
	}
	e.chainPeers(doc, self, expired, want, always) // #618
	e.splitLazy(want, doc.TunnelPeersOf(self.Name), always)
	if err := e.setPeers(want); err != nil {
		return err
	}
	if expired {
		e.filter.Clear()
	} else {
		e.filter.Update(doc, self)
	}
	e.applyExit(doc, self, exit, !expired && self.HasRole(trust.RoleExitNode))
	e.applyRoutes(doc, self, expired) // ADR-0133
	var probePeers []trust.Device
	if !expired {
		for _, p := range doc.TunnelPeersOf(self.Name) {
			if _, ok := fullWant[p.WireGuardKey]; ok {
				probePeers = append(probePeers, p)
			}
		}
	}
	e.probe.setPeers(self, probePeers)
	if e.pq != nil {
		e.pq.setPeers(self, probePeers)
	}
	dnsView := e.magicDNSView(doc, self, fullWant)
	admins := map[netip.Addr]bool{}
	for _, d := range doc.Devices {
		if d.HasRole(trust.RoleAdmin) && d.Name != self.Name {
			admins[d.IPv4] = true
		}
	}
	e.mu.Lock()
	e.admins = admins
	e.dnsView = dnsView
	e.self, e.applied = self, doc.Version
	e.status.DocumentVersion, e.status.DocumentExpires, e.status.Expired = doc.Version, doc.ExpiresAt, expired
	e.status.Peers = len(fullWant) - 1 - len(extraCoords)
	e.mu.Unlock()
	return nil
}

func (e *Engine) setPeers(want map[trust.Key]wgconf.Peer) error {
	raw, err := e.dev.IpcGet()
	if err != nil {
		return err
	}
	st, err := wgconf.ParseStatus(raw)
	if err != nil {
		return err
	}
	var uapi string
	for key := range st.Peers {
		if _, ok := want[key]; !ok {
			uapi += wgconf.Remove(key)
		}
	}
	for key, p := range want {
		if cur, ok := st.Peers[key]; ok && cur.Endpoint.IsValid() && !p.Endpoint.IsValid() {
			// Keep the endpoint WireGuard learned by roaming.
			p.Endpoint = cur.Endpoint
		}
		uapi += wgconf.AddOrUpdate(p)
	}
	if uapi == "" {
		return nil
	}
	// Prepare-validate-commit (#199): an invalid set changes nothing, a
	// half-applied one is put back (atomicapply.go).
	if err := validatePeerSet(want); err != nil {
		return err
	}
	if err := e.dev.IpcSet(uapi); err != nil {
		return e.rollbackPeers(raw, err)
	}
	return nil
}

// expire drops every device peer and blocks traffic when the document or
// this device's membership has expired (ADR-0003, #202). The coordinator
// stays configured so a renewed document can still arrive.
func (e *Engine) expire() {
	e.mu.Lock()
	already := e.status.Expired
	e.mu.Unlock()
	if already {
		return
	}
	e.logger.Warn("network document expired; device traffic blocked until it is renewed")
	if err := e.apply(context.Background(), e.cfg.Store.Document()); err != nil {
		e.logger.Warn("apply expired document", "error", err.Error())
	}
}

func (e *Engine) removeAllPeers() {
	if err := e.setPeers(map[trust.Key]wgconf.Peer{}); err != nil {
		e.logger.Warn("remove peers", "error", err.Error())
	}
}

// refreshEndpoints asks the coordinator for peer endpoints (with
// candidates when it supports them), moves peers between paths and probes
// the peers that need a better one (ADR-0017, ADR-0025).
func (e *Engine) refreshEndpoints(ctx context.Context) error {
	doc := e.cfg.Store.Document()
	infos, err := e.fetchPeers(ctx, doc)
	if err != nil {
		return err
	}
	for key, pi := range infos {
		e.probe.setInfo(key, pi.observed, pi.cands)
	}
	e.mu.Lock()
	e.peerInfo = infos
	e.mu.Unlock()
	st, err := e.wgStatus()
	if err != nil {
		return err
	}
	e.recordPeerEndpoints(st)
	self, err := e.selfIn(doc)
	if err != nil {
		return err
	}
	uapi := e.choosePaths(doc.TunnelPeersOf(self.Name), st, e.directEndpoints()) + e.adaptKeepalive(st)
	if uapi != "" {
		if err := e.dev.IpcSet(uapi); err != nil {
			return err
		}
	}
	if e.cfg.ForceRelay {
		return nil
	}
	for _, id := range e.probe.round(st, staleHandshake) {
		// Ask the peer to probe us at the same time (simultaneous hole
		// punching). Best effort and in the background: a lost call must
		// not hold up the sync.
		go func(id string) {
			cctx, cancel := context.WithTimeout(context.Background(), callTimeout*callRetries)
			defer cancel()
			if err := e.callPeer(cctx, id); err != nil {
				e.logger.Debug("call peer", "error", err.Error())
			}
		}(id)
	}
	return nil
}

// directEndpoints returns the endpoint the coordinator observed for each
// peer; choosePaths prefers a path validated by probing over it.
func (e *Engine) directEndpoints() map[trust.Key]netip.AddrPort {
	e.mu.Lock()
	defer e.mu.Unlock()
	direct := make(map[trust.Key]netip.AddrPort, len(e.peerInfo))
	for key, pi := range e.peerInfo {
		if pi.observed.IsValid() {
			direct[key] = pi.observed
		}
	}
	return direct
}

// repath applies validated probe results without asking the coordinator.
func (e *Engine) repath() {
	if e.cfg.ForceRelay {
		return
	}
	doc := e.cfg.Store.Document()
	self, err := e.selfIn(doc)
	if err != nil {
		return
	}
	st, err := e.wgStatus()
	if err != nil {
		return
	}
	uapi := e.choosePaths(doc.TunnelPeersOf(self.Name), st, e.directEndpoints())
	if uapi == "" {
		return
	}
	e.mu.Lock()
	dev := e.dev
	e.mu.Unlock()
	if dev != nil {
		if err := dev.IpcSet(uapi); err != nil {
			e.logger.Warn("apply probed path", "error", err.Error())
		}
	}
}

func (e *Engine) resolveEndpoint(ctx context.Context, endpoint string) (netip.AddrPort, error) {
	ap, err := resolveEndpoint(ctx, e.cfg.Resolve, endpoint)
	if err != nil {
		return ap, err
	}
	return e.viaNAT64(ctx, ap), nil // #384
}

func resolveEndpoint(ctx context.Context, resolve func(context.Context, string) ([]netip.Addr, error), endpoint string) (netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(endpoint); err == nil {
		return ap, nil
	}
	host, portStr, err := net.SplitHostPort(endpoint)
	if err != nil {
		return netip.AddrPort{}, err
	}
	port, err := net.LookupPort("udp", portStr)
	if err != nil {
		return netip.AddrPort{}, err
	}
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := resolve(rctx, host)
	if err != nil || len(addrs) == 0 {
		return netip.AddrPort{}, fmt.Errorf("resolve coordinator %s: %w", host, err)
	}
	return netip.AddrPortFrom(addrs[0].Unmap(), uint16(port)), nil //nolint:gosec // LookupPort returns 0-65535
}

func wgLogger(l *slog.Logger) *device.Logger {
	return &device.Logger{
		Verbosef: func(format string, args ...any) { l.Debug(fmt.Sprintf(format, args...)) },
		Errorf:   func(format string, args ...any) { l.Warn(fmt.Sprintf(format, args...)) },
	}
}
