package node

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"time"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/wgconf"
)

// Connection diagnostics (F-015 netcheck, F-016). Everything is measured
// against the owner's own coordinator and peers; no third-party server
// (STUN or otherwise) is ever contacted (ADR-0005, ADR-0025).

const (
	maxMappingSamples = 32
	maxEndpointEvents = 8
	// mappingWindow: endpoint changes older than this do not count as
	// mapping instability.
	mappingWindow = time.Hour
	// observationFresh: a peer's view of our address older than this is
	// not used for the NAT type.
	observationFresh = 10 * time.Minute
)

// NATType is the netcheck estimate of how this device's NAT maps ports.
type NATType string

const (
	// NATNone: the address the coordinator sees is on a local interface.
	NATNone NATType = "yok"
	// NATEasy: every observer sees the same address and port
	// (endpoint-independent mapping); hole punching usually works.
	NATEasy NATType = "kolay"
	// NATHard: observers see different ports (endpoint-dependent,
	// "symmetric" mapping); direct paths usually need the other side to be
	// easy, otherwise traffic goes through the relay.
	NATHard NATType = "zor"
	// NATUnknown: not enough observations yet.
	NATUnknown NATType = "bilinmiyor"
)

type mappingSample struct {
	at time.Time
	ep netip.AddrPort
}

// EndpointChange is one change of a peer's WireGuard endpoint.
type EndpointChange struct {
	At       time.Time `json:"at"`
	Endpoint string    `json:"endpoint"`
	Relayed  bool      `json:"relayed"`
}

// PeerObservation is this device's address as one peer saw it in a probe.
type PeerObservation struct {
	Peer   string    `json:"peer"`
	SeenAs string    `json:"seen_as"`
	At     time.Time `json:"at"`
}

// NetReport is the result of NetCheck.
type NetReport struct {
	At time.Time `json:"at"`
	// CoordinatorReachable: a control request through the tunnel was
	// answered now, so UDP to the coordinator works.
	CoordinatorReachable bool          `json:"coordinator_reachable"`
	CoordinatorRTT       time.Duration `json:"coordinator_rtt"`
	CoordinatorOverIPv6  bool          `json:"coordinator_over_ipv6"`
	CoordinatorFeatures  []string      `json:"coordinator_features"`
	// MappedEndpoint is this device's address as the coordinator sees it.
	MappedEndpoint string `json:"mapped_endpoint"`
	LocalPort      int    `json:"local_port"`
	PortPreserved  bool   `json:"port_preserved"`
	// MappingChanges counts changes of MappedEndpoint in the last hour
	// (unstable NAT mappings, changing networks).
	MappingChanges  int               `json:"mapping_changes"`
	NAT             NATType           `json:"nat"`
	Observations    []PeerObservation `json:"observations"`
	HaveIPv4        bool              `json:"have_ipv4"`
	HaveIPv6        bool              `json:"have_ipv6"`
	LocalCandidates []string          `json:"local_candidates"`
	DirectPeers     int               `json:"direct_peers"`
	RelayedPeers    int               `json:"relayed_peers"`
	IPv6Peers       int               `json:"ipv6_peers"`
	ForceRelay      bool              `json:"force_relay"`
	// CoordinatorOverTCP: UDP to the coordinator is blocked and the TCP
	// transport carries the tunnel (ADR-0032).
	CoordinatorOverTCP bool          `json:"coordinator_over_tcp"`
	CaptivePortal      CaptiveStatus `json:"captive_portal"`
	Notes              []string      `json:"notes"`
	LastSyncError      string        `json:"last_sync_error,omitempty"`
	DocumentVersion    uint64        `json:"document_version"`
	CoordinatorError   string        `json:"coordinator_error,omitempty"`
}

// recordMapping keeps the endpoint the coordinator saw in a hello.
func (e *Engine) recordMapping(ep netip.AddrPort) {
	ep = netip.AddrPortFrom(ep.Addr().Unmap(), ep.Port())
	now := e.cfg.Now()
	e.mu.Lock()
	defer e.mu.Unlock()
	if n := len(e.mapping); n > 0 && e.mapping[n-1].ep == ep {
		e.mapping[n-1].at = now
		return
	}
	e.mapping = append(e.mapping, mappingSample{at: now, ep: ep})
	if len(e.mapping) > maxMappingSamples {
		e.mapping = slices.Delete(e.mapping, 0, len(e.mapping)-maxMappingSamples)
	}
}

// recordPeerEndpoints remembers changes of every peer's endpoint (F-016).
func (e *Engine) recordPeerEndpoints(st wgconf.Status) {
	now := e.cfg.Now()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.epHistory == nil {
		e.epHistory, e.lastEP = map[trust.Key][]EndpointChange{}, map[trust.Key]string{}
	}
	for key, p := range st.Peers {
		cur := ""
		switch {
		case p.Relayed:
			cur = "aktarıcı"
		case p.Endpoint.IsValid():
			cur = p.Endpoint.String()
		}
		if cur == "" || e.lastEP[key] == cur {
			continue
		}
		e.lastEP[key] = cur
		h := append(e.epHistory[key], EndpointChange{At: now, Endpoint: cur, Relayed: p.Relayed})
		if len(h) > maxEndpointEvents {
			h = slices.Delete(h, 0, len(h)-maxEndpointEvents)
		}
		e.epHistory[key] = h
	}
	for key := range e.lastEP {
		if _, ok := st.Peers[key]; !ok {
			delete(e.lastEP, key)
			delete(e.epHistory, key)
		}
	}
}

// NetCheck examines this device's network conditions (F-015): UDP to the
// coordinator, the mapped address, NAT behaviour, IPv4/IPv6 and the paths
// to peers. It sends one control request to the coordinator and nothing to
// anyone else.
func (e *Engine) NetCheck(ctx context.Context) (NetReport, error) {
	if !e.running() {
		return NetReport{}, errors.New("tünel çalışmıyor")
	}
	now := e.cfg.Now()
	r := NetReport{At: now, NAT: NATUnknown, ForceRelay: e.cfg.ForceRelay, CoordinatorOverTCP: e.CoordinatorOverTCP()}
	doc := e.cfg.Store.Document()
	r.DocumentVersion = doc.Version
	start := time.Now()
	hello, err := e.client.call(ctx, control.Message{T: control.TypeHello, Version: doc.Version})
	if err == nil {
		r.CoordinatorReachable, r.CoordinatorRTT = true, time.Since(start)
		if ap, perr := netip.ParseAddrPort(hello.Endpoint); perr == nil {
			e.recordMapping(ap)
		}
	} else {
		r.CoordinatorError = err.Error()
	}
	st, stErr := e.wgStatus()
	if stErr == nil {
		r.LocalPort = st.ListenPort
		if doc.Coordinator != nil {
			if cp, ok := st.Peers[doc.Coordinator.WireGuardKey]; ok && cp.Endpoint.IsValid() {
				r.CoordinatorOverIPv6 = cp.Endpoint.Addr().Unmap().Is6()
			}
		}
		for key, p := range st.Peers {
			if doc.Coordinator != nil && key == doc.Coordinator.WireGuardKey {
				continue
			}
			switch {
			case p.Relayed:
				r.RelayedPeers++
			case p.Endpoint.IsValid() && p.LastHandshakeUnix > 0:
				r.DirectPeers++
				if p.Endpoint.Addr().Unmap().Is6() {
					r.IPv6Peers++
				}
			}
		}
	}
	r.CoordinatorFeatures = e.CoordinatorFeatures()

	addrs, _ := listInterfaceAddrs()
	local := map[netip.Addr]bool{}
	for _, ia := range addrs {
		local[ia.addr] = true
		switch {
		case ia.addr.Is4() && !ia.addr.IsLoopback() && !ia.addr.IsLinkLocalUnicast():
			r.HaveIPv4 = true
		case ia.addr.Is6() && ia.addr.IsGlobalUnicast() && !ia.addr.IsPrivate():
			r.HaveIPv6 = true
		}
	}

	e.mu.Lock()
	var mapped netip.AddrPort
	if n := len(e.mapping); n > 0 {
		mapped = e.mapping[n-1].ep
	}
	for i := 1; i < len(e.mapping); i++ {
		if now.Sub(e.mapping[i].at) <= mappingWindow {
			r.MappingChanges++
		}
	}
	for _, c := range e.localCands {
		r.LocalCandidates = append(r.LocalCandidates, c.String())
	}
	r.CaptivePortal = e.captive
	r.LastSyncError = e.status.LastSyncError
	e.mu.Unlock()

	// What the peers saw in their pongs.
	var observed []netip.AddrPort
	for _, d := range doc.TunnelPeersOf(e.selfName()) {
		snap, ok := e.probe.snapshot(d.WireGuardKey)
		if !ok || !snap.seenAs.IsValid() || now.Sub(snap.seenAt) > observationFresh {
			continue
		}
		r.Observations = append(r.Observations, PeerObservation{Peer: d.Name, SeenAs: snap.seenAs.String(), At: snap.seenAt})
		observed = append(observed, snap.seenAs)
	}

	if mapped.IsValid() {
		r.MappedEndpoint = mapped.String()
		r.PortPreserved = r.LocalPort > 0 && int(mapped.Port()) == r.LocalPort
	}
	r.NAT = estimateNAT(mapped, local, observed)
	r.Notes = netNotes(r)
	return r, nil
}

// estimateNAT compares the coordinator's and the peers' view of this
// device's address. Only observations of public addresses of the same
// family count: a peer on the same LAN sees the private address.
func estimateNAT(mapped netip.AddrPort, local map[netip.Addr]bool, observed []netip.AddrPort) NATType {
	if !mapped.IsValid() {
		return NATUnknown
	}
	if local[mapped.Addr()] {
		return NATNone
	}
	compared := false
	for _, o := range observed {
		a := o.Addr().Unmap()
		if a.IsPrivate() || a.IsLoopback() || a.Is4() != mapped.Addr().Is4() || a != mapped.Addr() {
			continue
		}
		if o.Port() != mapped.Port() {
			return NATHard
		}
		compared = true
	}
	if compared {
		return NATEasy
	}
	return NATUnknown
}

// netNotes explains a report in the owner's language.
func netNotes(r NetReport) []string {
	var notes []string
	if !r.CoordinatorReachable {
		notes = append(notes, "Koordinatöre UDP ile ulaşılamıyor; ağ UDP'yi engelliyor olabilir ya da bir giriş sayfası (captive portal) bekliyor olabilir.")
	}
	switch r.NAT {
	case NATNone:
		notes = append(notes, "Cihaz doğrudan genel bir adreste; NAT yok.")
	case NATEasy:
		notes = append(notes, "NAT her hedefe aynı portu veriyor; doğrudan bağlantı genellikle kurulur.")
	case NATHard:
		notes = append(notes, "NAT her hedefe farklı port veriyor (simetrik); karşı taraf da böyleyse trafik aktarıcıdan geçer. Bir statik uç nokta (port yönlendirme) tanımlamak yardımcı olur.")
	default:
		notes = append(notes, "NAT türünü kestirmek için yeterli gözlem yok; doğrudan bağlı bir eş yanıt verdikçe netleşir.")
	}
	if r.MappingChanges > 2 {
		notes = append(notes, "Dış adres son bir saatte birkaç kez değişti; NAT eşlemesi kararsız ya da ağ değişiyor.")
	}
	if r.HaveIPv6 && r.IPv6Peers == 0 {
		notes = append(notes, "Bu cihazın genel IPv6 adresi var ama hiçbir eşe IPv6 ile bağlı değil.")
	}
	if r.ForceRelay {
		notes = append(notes, "Aktarıcı zorunlu: doğrudan yol denenmiyor.")
	}
	if r.CoordinatorOverTCP {
		notes = append(notes, "Bu ağ UDP'yi engelliyor: koordinatöre TCP yedek taşıma ile bağlı, eşlere aktarıcı üzerinden ulaşılıyor.")
	}
	if r.CaptivePortal.Detected {
		notes = append(notes, "Giriş sayfası (captive portal) algılandı: "+r.CaptivePortal.Reason)
	}
	return notes
}

// PeerPath describes how one peer is reached (F-016).
type PeerPath struct {
	Name          string           `json:"name"`
	ID            string           `json:"id"`
	Endpoint      string           `json:"endpoint"`
	Relayed       bool             `json:"relayed"`
	Class         string           `json:"class"`
	LastHandshake time.Time        `json:"last_handshake"`
	Observed      string           `json:"observed,omitempty"`
	Candidates    []string         `json:"candidates,omitempty"`
	BestProbed    string           `json:"best_probed,omitempty"`
	ProbeRTT      time.Duration    `json:"probe_rtt,omitempty"`
	ProbedAt      time.Time        `json:"probed_at,omitempty"`
	NextProbe     time.Time        `json:"next_probe,omitempty"`
	History       []EndpointChange `json:"history,omitempty"`
	// PostQuantum is the PSK state (PQState*, ADR-0033): "pq" when the
	// pair uses a post-quantum PSK, "classical" or "unsupported" without.
	PostQuantum string    `json:"post_quantum"`
	PSKSince    time.Time `json:"psk_since,omitempty"`
	// RelayReason and RelayHint explain a relayed peer (#394,
	// relayreason.go); empty for a direct peer.
	RelayReason string `json:"relay_reason,omitempty"`
	RelayHint   string `json:"relay_hint,omitempty"`
}

// PeerPaths lists every tunnel peer with its endpoint, candidates, probe
// result and recent endpoint changes (F-016).
func (e *Engine) PeerPaths() ([]PeerPath, error) {
	st, err := e.wgStatus()
	if err != nil {
		return nil, err
	}
	doc := e.cfg.Store.Document()
	var out []PeerPath
	for _, d := range doc.TunnelPeersOf(e.selfName()) {
		p, ok := st.Peers[d.WireGuardKey]
		if !ok {
			continue
		}
		pp := PeerPath{Name: d.Name, ID: d.ID, Relayed: p.Relayed}
		switch {
		case p.Relayed:
			pp.Endpoint, pp.Class = "aktarıcı", classRelay.String()
		case p.Endpoint.IsValid():
			pp.Endpoint, pp.Class = p.Endpoint.String(), classify(p.Endpoint).String()
		default:
			pp.Class = classNone.String()
		}
		if p.LastHandshakeUnix > 0 {
			pp.LastHandshake = time.Unix(p.LastHandshakeUnix, 0)
		}
		snap, haveSnap := e.probe.snapshot(d.WireGuardKey)
		if p.Relayed {
			pp.RelayReason, pp.RelayHint = e.relayReasonFor(d.WireGuardKey, snap, haveSnap) // #394
		}
		if haveSnap {
			if snap.observed.IsValid() {
				pp.Observed = snap.observed.String()
			}
			for _, c := range snap.cands {
				pp.Candidates = append(pp.Candidates, c.String())
			}
			if snap.best.IsValid() {
				pp.BestProbed, pp.ProbeRTT, pp.ProbedAt = snap.best.String(), snap.bestRTT, snap.bestAt
			}
			pp.NextProbe = snap.next
		}
		pp.PostQuantum, pp.PSKSince = e.PostQuantumState(d.WireGuardKey)
		e.mu.Lock()
		pp.History = slices.Clone(e.epHistory[d.WireGuardKey])
		e.mu.Unlock()
		out = append(out, pp)
	}
	return out, nil
}

// ForceReconnect drops the current paths and starts over as after a
// network change (F-016): the coordinator is resolved again, every peer
// is probed and handshakes are restarted, then the device syncs at once.
func (e *Engine) ForceReconnect() {
	e.signalNetwork(netChanged)
}

// TestRelay sends a signed probe to the named peer through the
// coordinator's relay and returns the round-trip time (F-016). The peer
// must run a version that answers probes.
func (e *Engine) TestRelay(ctx context.Context, peer string) (time.Duration, error) {
	if !e.running() {
		return 0, errors.New("tünel çalışmıyor")
	}
	doc := e.cfg.Store.Document()
	d, ok := doc.DeviceByName(peer)
	if !ok {
		return 0, errors.New("böyle bir cihaz yok")
	}
	return e.probe.pingRelay(ctx, d.ID)
}

func (e *Engine) running() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.dev != nil
}

func (e *Engine) selfName() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.self.Name
}
