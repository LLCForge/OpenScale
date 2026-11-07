package upstream

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/openscale/openscale/internal/osnet"
)

// Tor exit (ADR-0142, Tor appendix; proposal #406): members' internet TCP
// goes into the Tor client the owner installed on the exit node (its
// TransPort), their DNS to Tor's DNSPort; UDP, ICMP and IPv6 bound for the
// internet are dropped. Tor is never embedded, started or configured by
// OpenScale; the owner adds the lines "tor torrc" prints to /etc/tor/torrc.
// When Tor does not listen, members' traffic is dropped: it never leaves
// with this host's own address.

// KindTor is Settings.Kind and Status.Kind of the Tor exit.
const KindTor = "tor"

// Default Tor ports: Tor's documented TransPort example and a DNSPort
// above 1024.
const (
	DefaultTorTransPort = 9040
	DefaultTorDNSPort   = 5353
)

// TorVirtualNetwork is the address range Tor hands out for .onion names
// (VirtualAddrNetworkIPv4). It must not be private: members route only
// public destinations to the exit node, and the exit node redirects only
// those to Tor. It is the benchmarking range (RFC 2544), never used on
// the internet.
var TorVirtualNetwork = netip.PrefixFrom(netip.AddrFrom4([4]byte{198, 18, 0, 0}), 15)

// TorSettings are the owner's Tor exit choices.
type TorSettings struct {
	Enabled   bool `json:"enabled"`
	TransPort int  `json:"trans_port,omitempty"`
	DNSPort   int  `json:"dns_port,omitempty"`
}

// Ports returns the ports with defaults filled in.
func (t TorSettings) Ports() (trans, dns uint16) {
	trans, dns = DefaultTorTransPort, DefaultTorDNSPort
	if t.TransPort != 0 {
		trans = uint16(t.TransPort)
	}
	if t.DNSPort != 0 {
		dns = uint16(t.DNSPort)
	}
	return trans, dns
}

func (t TorSettings) validate() error {
	for _, p := range []int{t.TransPort, t.DNSPort} {
		if p < 0 || p > 65535 {
			return fmt.Errorf("Tor portu %d geçersiz (1-65535)", p)
		}
	}
	if trans, dns := t.Ports(); trans == dns {
		return errors.New("Tor TransPort ve DNSPort farklı olmalı")
	}
	return nil
}

// TorEnabled reports whether the Tor exit is chosen.
func (s Settings) TorEnabled() bool { return s.Tor != nil && s.Tor.Enabled }

// EnableTor chooses the Tor exit with the given ports (0: default). It
// turns an active WireGuard profile off and returns its name ("" none).
func (s *Store) EnableTor(transPort, dnsPort int) (previous string, err error) {
	t := TorSettings{Enabled: true, TransPort: transPort, DNSPort: dnsPort}
	if err := t.validate(); err != nil {
		return "", err
	}
	err = s.UpdateSettings(func(st *Settings) error {
		previous = st.Active
		st.Active = ""
		st.Tor = &t
		return nil
	})
	return previous, err
}

// DisableTor turns the Tor exit off; it reports whether it was on.
func (s *Store) DisableTor() (bool, error) {
	was := false
	err := s.UpdateSettings(func(st *Settings) error {
		was = st.TorEnabled()
		st.Tor = nil
		return nil
	})
	return was, err
}

// TorStatus is the Tor exit's part of status.json.
type TorStatus struct {
	TransPort int `json:"trans_port"`
	DNSPort   int `json:"dns_port"`
	// Listen is the OpenScale address TransPort must listen on ("" unknown).
	Listen string `json:"listen,omitempty"`
	// TransUp and DNSUp: something listens where members are sent.
	TransUp bool `json:"trans_up"`
	DNSUp   bool `json:"dns_up"`
	// TransLoopbackOnly: TransPort listens only on loopback, which
	// redirected connections never reach (a torrc mistake).
	TransLoopbackOnly bool `json:"trans_loopback_only,omitempty"`
}

// TorRouter installs the Tor exit filter (osnet.TorRouter).
type TorRouter interface {
	Apply(ctx context.Context, r osnet.TorRoute) error
	Remove(ctx context.Context) error
	Probe(r osnet.TorRoute) osnet.TorHealth
}

// torState is the Manager's Tor exit state, guarded by Manager.mu.
type torState struct {
	routed bool
	route  osnet.TorRoute
	health osnet.TorHealth
	up     bool
}

// torRouteLocked builds the filter state from the settings and network.
func (m *Manager) torRouteLocked() (osnet.TorRoute, error) {
	ov, err := m.cfg.Overlay()
	if err != nil {
		return osnet.TorRoute{}, fmt.Errorf("ağ bilgisi alınamadı: %w", err)
	}
	trans, dns := m.settings.Tor.Ports()
	return osnet.TorRoute{Overlay: ov.Interface, OverlayV4: ov.V4, OverlayV6: ov.V6, Self4: ov.Self4,
		TransPort: trans, DNSPort: dns}, nil
}

// torReconcileLocked installs the filter when needed and checks Tor's
// listeners. Without the filter the exit node stays off (Ready).
func (m *Manager) torReconcileLocked() {
	if m.cfg.Deps.Tor == nil {
		m.errText = "Tor çıkışı bu sistemde desteklenmiyor"
		m.tor.routed = false
		return
	}
	r, err := m.torRouteLocked()
	if err != nil {
		m.errText = err.Error()
		return
	}
	if !m.tor.routed || r != m.tor.route {
		ctx, cancel := context.WithTimeout(context.Background(), routeTimeout)
		err := m.cfg.Deps.Tor.Apply(ctx, r)
		cancel()
		if err != nil {
			m.errText = "Tor çıkışı kuralları kurulamadı: " + err.Error()
			m.log.Warn("tor exit filter", "error", err.Error())
			if m.tor.routed {
				// The old filter still drops members' traffic; keep it.
				return
			}
			m.tor.routed = false
			return
		}
		m.tor.routed, m.tor.route = true, r
		m.log.Info("tor exit filter installed", "trans_port", r.TransPort, "dns_port", r.DNSPort)
	}
	h := m.cfg.Deps.Tor.Probe(r)
	m.tor.health = h
	was := m.tor.up
	m.tor.up = h.Up()
	switch {
	case m.tor.up:
		m.errText = ""
		if !was {
			m.log.Info("tor exit: Tor listens; members' TCP and DNS go through Tor")
		}
	case h.Err != nil:
		m.errText = "Tor portları denetlenemedi: " + h.Err.Error()
	case h.TransLoopbackOnly:
		m.errText = "Tor TransPort yalnızca 127.0.0.1'de dinliyor; torrc'de OpenScale adresi gerekli ('openscale exit-node upstream tor torrc')"
	case !h.Trans:
		m.errText = fmt.Sprintf("Tor TransPort %d dinlemiyor; üyelerin TCP trafiği kesiliyor", r.TransPort)
	default:
		m.errText = fmt.Sprintf("Tor DNSPort 127.0.0.1:%d dinlemiyor; üyelerin DNS sorguları düşürülüyor", r.DNSPort)
	}
	if was && !m.tor.up {
		m.log.Warn("tor exit: Tor does not listen; members' traffic is dropped", "error", m.errText)
	}
}

// torTeardownLocked removes the Tor exit filter.
func (m *Manager) torTeardownLocked() {
	if m.tor.routed && m.cfg.Deps.Tor != nil {
		ctx, cancel := context.WithTimeout(context.Background(), routeTimeout)
		if err := m.cfg.Deps.Tor.Remove(ctx); err != nil {
			m.log.Warn("tor exit filter removal", "error", err.Error())
		}
		cancel()
	}
	m.tor = torState{}
}

// torReadyLocked: forwarding may start only with the filter in place.
func (m *Manager) torReadyLocked() error {
	if m.tor.routed {
		return nil
	}
	if m.errText != "" {
		return errors.New(m.errText)
	}
	return errors.New("Tor çıkışı kuralları kurulamadı")
}

// torDNSLocked sends members' DNS to Tor's DNSPort on loopback, or drops it
// while the filter or Tor's DNSPort is missing.
func (m *Manager) torDNSLocked() (netip.AddrPort, netip.Addr, bool) {
	if !m.tor.routed || !m.tor.health.DNS {
		return netip.AddrPort{}, netip.Addr{}, true
	}
	lo := netip.AddrFrom4([4]byte{127, 0, 0, 1})
	return netip.AddrPortFrom(lo, m.tor.route.DNSPort), lo, true
}

// torStatusLocked fills the Tor exit's status.
func (m *Manager) torStatusLocked(st *Status) {
	trans, dns := m.settings.Tor.Ports()
	ts := &TorStatus{TransPort: int(trans), DNSPort: int(dns),
		TransUp: m.tor.health.Trans, DNSUp: m.tor.health.DNS, TransLoopbackOnly: m.tor.health.TransLoopbackOnly}
	if m.tor.route.Self4.IsValid() {
		ts.Listen = m.tor.route.Self4.String()
	}
	st.Tor, st.Label, st.Connected, st.OnDown = ts, "Tor", m.tor.up, OnDownDrop
	switch {
	case !m.tor.routed:
		st.Mode = ModeOff
	case m.tor.up:
		st.Mode = ModeTunnel
	default:
		st.Mode = ModeBlocked
	}
}

// statusEqual compares two statuses, the Tor part by value.
func statusEqual(a, b Status) bool {
	at, bt := a.Tor, b.Tor
	a.Tor, b.Tor = nil, nil
	if a != b {
		return false
	}
	if at == nil || bt == nil {
		return at == bt
	}
	return *at == *bt
}
