package service

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/filter"
	"github.com/openscale/openscale/internal/node"
)

// wave2Options are the connection preferences of connection wave 2
// (ADR-0110): router port mapping (ADR-0042), padding, cover traffic and
// priority queues (ADR-0043), Tor (ADR-0044) and the exit node resolver
// and threat detection (ADR-0102). They live in settings.json under
// "tunnel" with the other preferences; zero values are the engine
// defaults, so older settings files keep their behaviour.
type wave2Options struct {
	PortMap             bool     `json:"port_map,omitempty"`
	PortMapDisable      []string `json:"port_map_disable,omitempty"`
	Padding             string   `json:"padding,omitempty"`
	CoverTraffic        int      `json:"cover_traffic,omitempty"`
	InteractivePriority bool     `json:"interactive_priority,omitempty"`
	TorSOCKS            string   `json:"tor_socks,omitempty"`
	ExitDNSUpstream     string   `json:"exit_dns_upstream,omitempty"`
	ExitDNSBlocklist    string   `json:"exit_dns_blocklist,omitempty"`
	DNSSECTrustAnchors  string   `json:"dnssec_trust_anchors,omitempty"`
	// Threats tunes scan detection and canaries; the zero value is on
	// with the defaults.
	Threats filter.ThreatConfig `json:"threats,omitzero"`
	// ExitDNSGuard hardens the exit node resolver (P05,
	// exitdns_guard.go); the zero value is the default.
	ExitDNSGuard node.ExitDNSGuardConfig `json:"exit_dns_guard,omitzero"`
	DNSEnforce   dnsEnforceOptions       `json:"dns_enforce,omitzero"` // #717 (dnsenforce.go)
}

// Port mapping protocol names of "port-map-disable".
var portMapProtocols = []string{"pcp", "natpmp", "upnp"}

const maxPathPref = 1024

func (w wave2Options) clone() wave2Options {
	w.PortMapDisable = slices.Clone(w.PortMapDisable)
	w.Threats.CanaryAddrs = slices.Clone(w.Threats.CanaryAddrs)
	w.Threats.CanaryPorts = slices.Clone(w.Threats.CanaryPorts)
	w.ExitDNSGuard = cloneExitDNSGuard(w.ExitDNSGuard)
	return w
}

func (w wave2Options) equal(o wave2Options) bool {
	return reflect.DeepEqual(w.normalized(), o.normalized())
}

// normalized maps empty lists to nil so a saved and a parsed value compare
// equal.
func (w wave2Options) normalized() wave2Options {
	w = w.clone()
	if len(w.PortMapDisable) == 0 {
		w.PortMapDisable = nil
	}
	if len(w.Threats.CanaryAddrs) == 0 {
		w.Threats.CanaryAddrs = nil
	}
	if len(w.Threats.CanaryPorts) == 0 {
		w.Threats.CanaryPorts = nil
	}
	return w
}

// ParsePadding maps a padding setting to the engine mode.
func ParsePadding(s string) (node.PaddingMode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "off", "kapali", "kapalı":
		return node.PaddingOff, nil
	case "buckets", "kovalar":
		return node.PaddingBuckets, nil
	case "mtu":
		return node.PaddingMTU, nil
	}
	return node.PaddingOff, fmt.Errorf("dolgu kipi %q geçersiz; off, buckets veya mtu yazın", s)
}

// PaddingName is the setting name of a mode ("" for off).
func PaddingName(m node.PaddingMode) string {
	switch m {
	case node.PaddingBuckets:
		return "buckets"
	case node.PaddingMTU:
		return "mtu"
	}
	return ""
}

// ValidCoverTraffic checks a cover traffic rate; 0 is off.
func ValidCoverTraffic(n int) error {
	if n != 0 && (n < node.MinCoverTraffic || n > node.MaxCoverTraffic) {
		return fmt.Errorf("sahte trafik hızı 0 (kapalı) veya %d ile %d B/sn arasında olmalı", node.MinCoverTraffic, node.MaxCoverTraffic)
	}
	return nil
}

// ValidTorSOCKS checks the Tor SOCKS5 address: empty or a loopback
// address with a port (the Tor client already running on this system).
func ValidTorSOCKS(s string) error {
	if s == "" {
		return nil
	}
	ap, err := netip.ParseAddrPort(s)
	if err != nil || ap.Port() == 0 || !ap.Addr().Unmap().IsLoopback() {
		return fmt.Errorf("Tor SOCKS adresi %q geçersiz; yalnızca bu makinedeki bir adres yazılabilir, ör. 127.0.0.1:9050", s)
	}
	return nil
}

// ValidPortMapDisable checks the protocols to turn off.
func ValidPortMapDisable(in []string) error {
	for _, p := range in {
		if !slices.Contains(portMapProtocols, p) {
			return fmt.Errorf("port eşleme protokolü %q geçersiz; pcp, natpmp veya upnp yazın", p)
		}
	}
	return nil
}

// ValidLocalFile checks a path setting: empty or an absolute path of a
// regular file that exists now.
func ValidLocalFile(what, p string) error {
	if p == "" {
		return nil
	}
	if len(p) > maxPathPref || !filepath.IsAbs(p) || strings.ContainsAny(p, "\x00\r\n") {
		return fmt.Errorf("%s mutlak bir dosya yolu olmalı", what)
	}
	info, err := os.Stat(p)
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("%s bulunamadı: %s", what, p)
	}
	return nil
}

func (w wave2Options) validate(t transportOptions) error {
	if err := ValidPortMapDisable(w.PortMapDisable); err != nil {
		return err
	}
	if w.PortMap && len(w.PortMapDisable) == len(portMapProtocols) {
		return errors.New("port eşleme açık ama bütün protokoller kapalı")
	}
	if _, err := ParsePadding(w.Padding); err != nil {
		return err
	}
	if err := ValidCoverTraffic(w.CoverTraffic); err != nil {
		return err
	}
	if err := ValidTorSOCKS(w.TorSOCKS); err != nil {
		return err
	}
	if w.TorSOCKS != "" && t.DisableTCPFallback {
		return errors.New("Tor kipi TCP taşımasını kullanır; disable-tcp-fallback açıkken açılamaz")
	}
	if err := node.ValidateExitDNSUpstream(w.ExitDNSUpstream); err != nil {
		return fmt.Errorf("çıkış DNS üst çözücüsü: %w", err)
	}
	if err := ValidLocalFile("engel listesi", w.ExitDNSBlocklist); err != nil {
		return err
	}
	if err := ValidLocalFile("DNSSEC güven çapası dosyası", w.DNSSECTrustAnchors); err != nil {
		return err
	}
	if _, err := w.Threats.WithDefaults(); err != nil {
		return fmt.Errorf("tehdit algılama: %w", err)
	}
	return validExitDNSGuard(w.ExitDNSGuard) // P05
}

// portMapConfig is the engine form of the port mapping settings.
func (w wave2Options) portMapConfig() node.PortMapConfig {
	return node.PortMapConfig{
		Enabled:       w.PortMap,
		DisablePCP:    slices.Contains(w.PortMapDisable, "pcp"),
		DisableNATPMP: slices.Contains(w.PortMapDisable, "natpmp"),
		DisableUPnP:   slices.Contains(w.PortMapDisable, "upnp"),
	}
}

// withWave2Options copies the saved wave 2 options into the engine
// configuration. A value the engine would refuse is left out with a
// warning, so the tunnel still starts with the default (off).
func (r *Runtime) withWave2Options(w wave2Options, t transportOptions, cfg node.Config) node.Config {
	if err := ValidPortMapDisable(w.PortMapDisable); err == nil && !(w.PortMap && len(w.PortMapDisable) == len(portMapProtocols)) {
		cfg.PortMap = w.portMapConfig()
	} else {
		r.logger.Warn("saved port mapping settings are not usable")
	}
	if m, err := ParsePadding(w.Padding); err == nil {
		cfg.Padding = m
	} else {
		r.logger.Warn("saved padding is not usable", "error", err.Error())
	}
	if err := ValidCoverTraffic(w.CoverTraffic); err == nil {
		cfg.CoverTraffic = w.CoverTraffic
	} else {
		r.logger.Warn("saved cover traffic rate is not usable", "error", err.Error())
	}
	cfg.InteractivePriority = w.InteractivePriority
	if err := ValidTorSOCKS(w.TorSOCKS); err == nil && !(w.TorSOCKS != "" && t.DisableTCPFallback) {
		cfg.TorSOCKS = w.TorSOCKS
	} else if w.TorSOCKS != "" {
		r.logger.Warn("saved Tor address is not usable; Tor stays off")
	}
	if err := node.ValidateExitDNSUpstream(w.ExitDNSUpstream); err == nil {
		cfg.ExitDNSUpstream = w.ExitDNSUpstream
	} else {
		r.logger.Warn("saved exit DNS upstream is not usable", "error", err.Error())
	}
	cfg.ExitDNSBlocklist = w.ExitDNSBlocklist
	cfg.ExitDNSGuard = r.usableExitDNSGuard(w.ExitDNSGuard) // P05
	cfg.DNSSECTrustAnchors = w.DNSSECTrustAnchors
	if _, err := w.Threats.WithDefaults(); err == nil {
		cfg.Threats = w.Threats
	} else {
		r.logger.Warn("saved threat detection settings are not usable; defaults are used", "error", err.Error())
	}
	cfg.OnThreat = r.onThreat
	return cfg
}

// applyWave2Pref changes one wave 2 key of "openscale set"; ok is false
// for other keys.
func applyWave2Pref(w *wave2Options, key, v string) (bool, error) {
	var err error
	v = strings.TrimSpace(v)
	switch key {
	case "port-map":
		w.PortMap, err = parseBoolPref(key, v)
	case "port-map-disable":
		list := splitList(strings.ToLower(v))
		if err = ValidPortMapDisable(list); err == nil {
			w.PortMapDisable = list
		}
	case "padding":
		var m node.PaddingMode
		if m, err = ParsePadding(v); err == nil {
			w.Padding = PaddingName(m)
		}
	case "cover-traffic":
		var n int64
		if n, err = parseIntPref(key, v, 32); err == nil {
			w.CoverTraffic = int(n)
		}
	case "interactive-priority":
		w.InteractivePriority, err = parseBoolPref(key, v)
	case "tor-socks":
		w.TorSOCKS = v
	case "exit-dns-upstream":
		w.ExitDNSUpstream = v
	case "exit-dns-blocklist":
		w.ExitDNSBlocklist = v
	case "dnssec-trust-anchors":
		w.DNSSECTrustAnchors = v
	case "threat-scan":
		var on bool
		on, err = parseBoolPref(key, v)
		w.Threats.DisableScan = !on
	case "threat-block":
		var on bool
		on, err = parseBoolPref(key, v)
		w.Threats.DisableBlock = !on
	case "threat-block-for":
		w.Threats.BlockFor, err = parseDurPref(key, v)
	case "canary-ports":
		var ports []uint16
		for _, s := range splitList(v) {
			n, perr := strconv.ParseUint(s, 10, 16)
			if perr != nil || n == 0 {
				return true, fmt.Errorf("%s: 1-65535 arası port numaraları yazın", key)
			}
			ports = append(ports, uint16(n))
		}
		w.Threats.CanaryPorts = ports
	case "canary-addrs":
		var addrs []netip.Addr
		for _, s := range splitList(v) {
			a, perr := netip.ParseAddr(s)
			if perr != nil {
				return true, fmt.Errorf("%s: IP adresleri yazın", key)
			}
			addrs = append(addrs, a)
		}
		w.Threats.CanaryAddrs = addrs
	default:
		return applyWave2ExtraPref(w, key, v) // #717 DNS zorlama, ardından P05 (dnsenforce.go)
	}
	return true, err
}

func joinPorts(ps []uint16) string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, strconv.Itoa(int(p)))
	}
	return strings.Join(out, ",")
}

func joinAddrs(as []netip.Addr) string {
	out := make([]string, 0, len(as))
	for _, a := range as {
		out = append(out, a.String())
	}
	return strings.Join(out, ",")
}

func orOff(s string) string {
	if s == "" {
		return "off"
	}
	return s
}

// wave2PrefSpecs are appended to prefSpecs (diag_prefs.go).
var wave2PrefSpecs = []prefSpec{
	{"port-map", "false", "Yönlendiricide WireGuard portunu aç: PCP, NAT-PMP, UPnP (ADR-0042)", func(s settings) string { return boolText(s.tunnel().PortMap) }},
	{"port-map-disable", "", "Port eşlemede kullanılmayacak protokoller, virgülle: pcp,natpmp,upnp", func(s settings) string { return strings.Join(s.tunnel().PortMapDisable, ",") }},
	{"padding", "off", "Paket dolgusu: off, buckets (128/256/512/1024) veya mtu; ek bant genişliği harcar (ADR-0043)", func(s settings) string { return orOff(s.tunnel().Padding) }},
	{"cover-traffic", "0", fmt.Sprintf("Koordinatöre sahte trafik, B/sn (0: kapalı; %d-%d); veri ve pil harcar", node.MinCoverTraffic, node.MaxCoverTraffic), func(s settings) string { return strconv.Itoa(s.tunnel().CoverTraffic) }},
	{"interactive-priority", "false", "ICMP, SSH, uzak masaüstü ve DNS paketlerini toplu aktarımlardan önce gönder", func(s settings) string { return boolText(s.tunnel().InteractivePriority) }},
	{"tor-socks", "", "Koordinatöre bu makinedeki Tor istemcisi üzerinden bağlan, ör. 127.0.0.1:9050 (bütün eşler aktarıcıdan; ADR-0044)", func(s settings) string { return s.tunnel().TorSOCKS }},
	{"exit-dns-upstream", "", "Çıkış düğümüyken üyelerin DNS'i: IP[:port], DoT (tls önekiyle), DoH (https önekiyle), recursive veya recursive-dnssec (boş: sistem çözücüsü)", func(s settings) string { return s.tunnel().ExitDNSUpstream }},
	{"exit-dns-blocklist", "", "Çıkış düğümünde NXDOMAIN ile yanıtlanacak adların yerel listesi (mutlak dosya yolu; indirilmez)", func(s settings) string { return s.tunnel().ExitDNSBlocklist }},
	{"dnssec-trust-anchors", "", "recursive-dnssec için kök DS kayıtları dosyası (boş: gömülü çapalar)", func(s settings) string { return s.tunnel().DNSSECTrustAnchors }},
	{"threat-scan", "true", "Eşlerden port taramasını algıla (ADR-0102)", func(s settings) string { return boolText(!s.tunnel().Threats.DisableScan) }},
	{"threat-block", "true", "Tarama yapan eşin yeni bağlantılarını bir süre reddet", func(s settings) string { return boolText(!s.tunnel().Threats.DisableBlock) }},
	{"threat-block-for", "0", "Tarama yapan eşin engelli kalma süresi (0: 10m; 1m-24h)", func(s settings) string { return durText(s.tunnel().Threats.BlockFor) }},
	{"canary-ports", "", "Hiçbir kuralın açmadığı tuzak portlar, virgülle; dokunan eş bildirilir", func(s settings) string { return joinPorts(s.tunnel().Threats.CanaryPorts) }},
	{"canary-addrs", "", "Hiçbir cihazın kullanmadığı tuzak ağ içi adresler, virgülle", func(s settings) string { return joinAddrs(s.tunnel().Threats.CanaryAddrs) }},
}

func init() { prefSpecs = append(prefSpecs, wave2PrefSpecs...) }

// ShapingCostText describes what padding and cover traffic cost, for the
// command line; the panel shows the same numbers before they can be
// turned on (ADR-0043 roadmap condition).
func ShapingCostText(padding node.PaddingMode, cover, mtu int) []string {
	if mtu == 0 {
		mtu = node.DefaultMTU
	}
	var out []string
	if padding != node.PaddingOff {
		if pct, err := node.PaddingCost(padding, mtu); err == nil {
			out = append(out, fmt.Sprintf("Dolgu (%s): tipik trafikte yaklaşık %%%.0f ek bant genişliği.", padding, pct))
		}
	}
	if cover > 0 {
		if c, err := node.CoverTrafficCost(cover, mtu); err == nil {
			out = append(out, fmt.Sprintf("Sahte trafik %d B/sn: saatte %d paket (telefonda radyo uyanması), günde %.1f MiB, 30 günde %.2f GiB veri.",
				cover, c.PacketsPerHour, float64(c.WireBytesPerDay)/(1<<20), float64(c.WireBytesPer30Days)/(1<<30)))
		}
	}
	return out
}

// guardSince bounds how far back threat alerts look.
const guardSince = time.Hour

// UpWave2Config are the wave 2 options of "openscale up".
type UpWave2Config struct {
	PortMap             node.PortMapConfig
	Padding             node.PaddingMode
	CoverTraffic        int
	InteractivePriority bool
	TorSOCKS            string
	Blocklist           string
	Anchors             string
	Threats             filter.ThreatConfig
}

// Apply copies the options into the engine configuration; node.New checks
// them again.
func (c UpWave2Config) Apply(cfg node.Config) node.Config {
	cfg.PortMap = c.PortMap
	cfg.Padding = c.Padding
	cfg.CoverTraffic = c.CoverTraffic
	cfg.InteractivePriority = c.InteractivePriority
	cfg.TorSOCKS = c.TorSOCKS
	cfg.ExitDNSBlocklist = c.Blocklist
	cfg.DNSSECTrustAnchors = c.Anchors
	cfg.Threats = c.Threats
	return cfg
}
