// Package leaktest checks, while an exit node is in use, whether traffic
// really leaves through it (#77): the address the coordinator sees, the
// DNS path, IPv6 and what WebRTC could reveal (#76). It asks only this
// network's own coordinator (the who-am-I echo on its UDP port) and the
// exit node's own resolver; no third-party test service is contacted.
package leaktest

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// Check levels.
const (
	LevelOK   = "ok"
	LevelInfo = "info"
	LevelWarn = "warn"
	LevelLeak = "leak"
)

// Check IDs.
const (
	CheckIP         = "ip"
	CheckIPv6       = "ipv6"
	CheckDNS        = "dns"
	CheckKillSwitch = "killswitch"
	CheckWebRTC     = "webrtc"
)

// Schema is the report's JSON schema version.
const Schema = 1

// Check is one line of the report.
type Check struct {
	ID     string `json:"id"`
	Level  string `json:"level"`
	Title  string `json:"title"`
	Detail string `json:"detail,omitempty"`
}

// Report is the result of a leak test.
type Report struct {
	Schema   int       `json:"schema"`
	At       time.Time `json:"at"`
	ExitNode string    `json:"exit_node"`
	// SeenIPv4 and SeenIPv6 are what the coordinator saw.
	SeenIPv4 string  `json:"seen_ipv4,omitempty"`
	SeenIPv6 string  `json:"seen_ipv6,omitempty"`
	Leak     bool    `json:"leak"`
	Checks   []Check `json:"checks"`
}

// Resolver is one DNS server the system uses.
type Resolver struct {
	Link string     `json:"link,omitempty"`
	Addr netip.Addr `json:"addr"`
}

// Input is what the test knows about this device.
type Input struct {
	ExitNode string
	// CoordinatorEndpoint is the document's "host:port" (UDP).
	CoordinatorEndpoint string
	Overlay4, Overlay6  netip.Prefix
	// ExitPublic is the exit node's address as WireGuard reaches it on a
	// direct path; invalid when unknown or relayed.
	ExitPublic netip.Addr
	// OwnPublic is this device's address as the coordinator sees its
	// WireGuard socket, which never uses the tunnel.
	OwnPublic netip.Addr
	// ExitDNS is the exit node's overlay address, where its resolver
	// answers members.
	ExitDNS netip.Addr
	// TunnelLink is the tunnel interface name.
	TunnelLink string
	// Resolvers are the system's DNS servers; nil when unknown.
	Resolvers []Resolver
	// DNSGuard: DNS outside the tunnel is blocked (Linux leak guard or the
	// kill switch). IPv6Guard: global IPv6 outside the tunnel is blocked.
	DNSGuard, IPv6Guard bool
	// KillSwitch: the persistent kill switch is installed; KillSwitchKnown
	// is false when its state could not be read.
	KillSwitch, KillSwitchKnown bool
	// LocalAddrs are the addresses of the non-tunnel interfaces.
	LocalAddrs []netip.Addr
}

// Prober performs the network side of the test.
type Prober interface {
	// WhoAmI asks the coordinator at addr which source it sees, from an
	// ordinary socket that follows the exit node routes.
	WhoAmI(ctx context.Context, addr netip.AddrPort) (netip.AddrPort, error)
	// Resolve looks a host name up through the system resolver.
	Resolve(ctx context.Context, host string) ([]netip.Addr, error)
	// Query sends one DNS query for name to server:53.
	Query(ctx context.Context, server netip.Addr, name string) error
}

// ErrNoExitNode is returned when no exit node is in use.
var ErrNoExitNode = errors.New("çıkış düğümü kullanılmıyor; sızıntı testi yalnızca bir çıkış düğümü etkinken anlamlıdır")

// Run performs the test.
func Run(ctx context.Context, in Input, p Prober, now time.Time) (Report, error) {
	if in.ExitNode == "" {
		return Report{}, ErrNoExitNode
	}
	rep := Report{Schema: Schema, At: now, ExitNode: in.ExitNode}
	host, port, err := splitEndpoint(in.CoordinatorEndpoint)
	if err != nil {
		return Report{}, err
	}
	addrs, resolveErr := coordinatorAddrs(ctx, p, host)
	var v4, v6 []netip.Addr
	for _, a := range addrs {
		if a.Unmap().Is4() {
			v4 = append(v4, a.Unmap())
		} else {
			v6 = append(v6, a)
		}
	}

	rep.add(ipCheck(ctx, in, p, v4, port, resolveErr, &rep))
	rep.add(ipv6Check(ctx, in, p, v6, port, &rep))
	rep.add(dnsCheck(ctx, in, p, host))
	rep.add(killSwitchCheck(in))
	rep.add(webRTCCheck(in))
	return rep, nil
}

func (r *Report) add(c Check) {
	r.Checks = append(r.Checks, c)
	if c.Level == LevelLeak {
		r.Leak = true
	}
}

func splitEndpoint(ep string) (string, uint16, error) {
	host, portStr, err := net.SplitHostPort(strings.TrimSpace(ep))
	if err != nil || host == "" {
		return "", 0, fmt.Errorf("koordinatör adresi okunamadı: %q", ep)
	}
	var port uint16
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil || port == 0 {
		return "", 0, fmt.Errorf("koordinatör portu geçersiz: %q", ep)
	}
	return host, port, nil
}

func coordinatorAddrs(ctx context.Context, p Prober, host string) ([]netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{a}, nil
	}
	return p.Resolve(ctx, host)
}

// whoAmI tries each address until one answers.
func whoAmI(ctx context.Context, p Prober, addrs []netip.Addr, port uint16) (netip.AddrPort, error) {
	var last error
	for _, a := range addrs {
		seen, err := p.WhoAmI(ctx, netip.AddrPortFrom(a, port))
		if err == nil {
			return seen, nil
		}
		last = err
	}
	if last == nil {
		last = errors.New("adres yok")
	}
	return netip.AddrPort{}, last
}

func ipCheck(ctx context.Context, in Input, p Prober, v4 []netip.Addr, port uint16, resolveErr error, rep *Report) Check {
	c := Check{ID: CheckIP, Title: "Görünen IPv4 adresi"}
	if len(v4) == 0 {
		c.Level = LevelWarn
		c.Detail = "Koordinatörün IPv4 adresi bulunamadı"
		if resolveErr != nil {
			c.Detail += " (ad çözülemedi: " + resolveErr.Error() + ")"
		}
		return c
	}
	seen, err := whoAmI(ctx, p, v4, port)
	if err != nil {
		c.Level = LevelWarn
		c.Detail = "Koordinatör yanıt vermedi (koordinatör sürümü eski olabilir ya da çıkış düğümü bu trafiği iletmiyor): " + err.Error()
		return c
	}
	a := seen.Addr().Unmap()
	rep.SeenIPv4 = a.String()
	return judgeSeen(c, a, in, in.Overlay4)
}

func judgeSeen(c Check, a netip.Addr, in Input, overlay netip.Prefix) Check {
	switch {
	case overlay.IsValid() && overlay.Contains(a):
		c.Level = LevelOK
		c.Detail = fmt.Sprintf("Koordinatör isteği ağın içinden (%s) gördü: trafik tünelden çıkıyor", a)
	case in.ExitPublic.IsValid() && in.OwnPublic.IsValid() && in.ExitPublic.Unmap() == in.OwnPublic.Unmap() && a == in.OwnPublic.Unmap():
		c.Level = LevelWarn
		c.Detail = fmt.Sprintf("Koordinatör %s adresini gördü; bu cihaz ile çıkış düğümü aynı genel adresi paylaştığı için ayırt edilemiyor", a)
	case in.ExitPublic.IsValid() && a == in.ExitPublic.Unmap():
		c.Level = LevelOK
		c.Detail = fmt.Sprintf("Koordinatör çıkış düğümünün adresini (%s) gördü", a)
	case in.OwnPublic.IsValid() && a == in.OwnPublic.Unmap():
		c.Level = LevelLeak
		c.Detail = fmt.Sprintf("Koordinatör bu cihazın kendi genel adresini (%s) gördü: trafik çıkış düğümünü atlıyor", a)
	case containsAddr(in.LocalAddrs, a):
		c.Level = LevelLeak
		c.Detail = fmt.Sprintf("Koordinatör bu cihazın yerel bir adresini (%s) gördü: trafik çıkış düğümünü atlıyor", a)
	default:
		c.Level = LevelOK
		c.Detail = fmt.Sprintf("Koordinatör %s adresini gördü; bu adres bu cihaza ait değil (çıkış düğümünün internete çıktığı adres)", a)
	}
	return c
}

func containsAddr(list []netip.Addr, a netip.Addr) bool {
	for _, x := range list {
		if x.Unmap() == a.Unmap() {
			return true
		}
	}
	return false
}

// globalV6 returns the global unicast IPv6 addresses (not ULA, not
// link-local) of the list.
func globalV6(list []netip.Addr) []netip.Addr {
	var out []netip.Addr
	for _, a := range list {
		if a.Is6() && !a.Is4In6() && a.IsGlobalUnicast() && !a.IsPrivate() {
			out = append(out, a)
		}
	}
	return out
}

func ipv6Check(ctx context.Context, in Input, p Prober, v6 []netip.Addr, port uint16, rep *Report) Check {
	c := Check{ID: CheckIPv6, Title: "IPv6"}
	global := globalV6(in.LocalAddrs)
	if len(v6) > 0 {
		seen, err := whoAmI(ctx, p, v6, port)
		if err == nil {
			a := seen.Addr()
			rep.SeenIPv6 = a.String()
			return judgeSeen(c, a, in, in.Overlay6)
		}
		if in.IPv6Guard {
			c.Level = LevelOK
			c.Detail = "Koordinatöre IPv6 ile ulaşılamadı ve tünel dışı IPv6 engelli: IPv6 sızamaz"
			return c
		}
		if len(global) == 0 {
			c.Level = LevelOK
			c.Detail = "Bu cihazda genel IPv6 adresi yok"
			return c
		}
		c.Level = LevelWarn
		c.Detail = "Koordinatöre IPv6 ile ulaşılamadı ve tünel dışı IPv6 engeli kurulu değil"
		return c
	}
	switch {
	case len(global) == 0:
		c.Level = LevelOK
		c.Detail = "Bu cihazda genel IPv6 adresi yok"
	case in.IPv6Guard:
		c.Level = LevelOK
		c.Detail = "Tünel dışı IPv6 engelli (koordinatörün IPv6 adresi olmadığı için görünen adres sorulamadı)"
	default:
		c.Level = LevelWarn
		c.Detail = fmt.Sprintf("Bu cihazın genel IPv6 adresi var (%s) ve tünel dışı IPv6 engeli kurulu değil", joinAddrs(global))
	}
	return c
}

func dnsCheck(ctx context.Context, in Input, p Prober, coordHost string) Check {
	c := Check{ID: CheckDNS, Title: "DNS"}
	var outside []string
	for _, r := range in.Resolvers {
		a := r.Addr.Unmap()
		switch {
		case a.IsLoopback(), in.Overlay4.IsValid() && in.Overlay4.Contains(a), in.Overlay6.IsValid() && in.Overlay6.Contains(a), a == in.ExitDNS:
			continue
		case in.TunnelLink != "" && r.Link == in.TunnelLink:
			continue
		}
		name := a.String()
		if r.Link != "" {
			name += " (" + r.Link + ")"
		}
		outside = append(outside, name)
	}
	var parts []string
	level := LevelOK
	switch {
	case len(outside) > 0 && in.DNSGuard:
		parts = append(parts, "Tünel dışındaki çözücüler ("+strings.Join(outside, ", ")+") yapılandırılmış ama 53/853 portları tünel dışında engelli")
	case len(outside) > 0:
		level = LevelLeak
		parts = append(parts, "Tünel dışındaki çözücüler ("+strings.Join(outside, ", ")+") kullanılabilir ve tünel dışı DNS engeli yok")
	case in.DNSGuard:
		parts = append(parts, "Tünel dışı DNS (53/853) engelli")
	case in.Resolvers == nil:
		level = LevelWarn
		parts = append(parts, "Sistem çözücüleri okunamadı ve tünel dışı DNS engeli yok")
	default:
		parts = append(parts, "Sistem çözücüleri yalnızca tünel üzerinden")
	}
	if in.ExitDNS.IsValid() {
		if _, err := netip.ParseAddr(coordHost); err != nil {
			if err := p.Query(ctx, in.ExitDNS, coordHost); err != nil {
				if level == LevelOK {
					level = LevelWarn
				}
				parts = append(parts, "çıkış düğümünün çözücüsü ("+in.ExitDNS.String()+") yanıt vermedi: "+err.Error())
			} else {
				parts = append(parts, "çıkış düğümünün çözücüsü ("+in.ExitDNS.String()+") yanıt veriyor")
			}
		}
	}
	c.Level = level
	c.Detail = strings.Join(parts, "; ")
	return c
}

func killSwitchCheck(in Input) Check {
	c := Check{ID: CheckKillSwitch, Title: "Kalıcı kill switch"}
	switch {
	case !in.KillSwitchKnown:
		c.Level = LevelInfo
		c.Detail = "Durum okunamadı (komutu yönetici/root olarak çalıştırın)"
	case in.KillSwitch:
		c.Level = LevelOK
		c.Detail = "Kurulu: OpenScale durursa veya çökerse de trafik tünel dışına çıkmaz"
	default:
		c.Level = LevelWarn
		c.Detail = "Kurulu değil: OpenScale durursa veya çökerse trafik doğrudan çıkabilir"
	}
	return c
}

// WebRTCAdvice tells the owner how to keep browsers from revealing local
// addresses (#76).
const WebRTCAdvice = "Firefox: about:config içinde media.peerconnection.ice.default_address_only=true (WebRTC'yi tümden kapatmak için media.peerconnection.enabled=false). " +
	"Chrome ve Edge: WebRtcIPHandling ilkesini disable_non_proxied_udp ya da default_public_interface_only yapın. " +
	"Safari: Geliştirici menüsünde WebRTC ayarlarından yerel adres paylaşımını kapatın."

func webRTCCheck(in Input) Check {
	c := Check{ID: CheckWebRTC, Title: "WebRTC (tarayıcılar)"}
	global := globalV6(in.LocalAddrs)
	var private []netip.Addr
	for _, a := range in.LocalAddrs {
		if a.Unmap().Is4() && a.Unmap().IsPrivate() {
			private = append(private, a.Unmap())
		}
	}
	switch {
	case len(global) > 0:
		c.Level = LevelWarn
		c.Detail = fmt.Sprintf("Tarayıcılar WebRTC ile bu cihazın genel IPv6 adreslerini (%s) sitelere gösterebilir; çıkış düğümü bunları gizlemez. %s", joinAddrs(global), WebRTCAdvice)
	case len(private) > 0:
		c.Level = LevelInfo
		c.Detail = fmt.Sprintf("Tarayıcılar WebRTC ile yerel ağ adreslerini (%s) gösterebilir; genel adresiniz görünmez. %s", joinAddrs(private), WebRTCAdvice)
	default:
		c.Level = LevelOK
		c.Detail = "Tünel dışında gösterilebilecek bir adres yok"
	}
	return c
}

func joinAddrs(list []netip.Addr) string {
	s := make([]string, len(list))
	for i, a := range list {
		s[i] = a.String()
	}
	sort.Strings(s)
	return strings.Join(s, ", ")
}
