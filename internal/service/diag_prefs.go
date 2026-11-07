package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/filter"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/osnet"
	"github.com/openscale/openscale/internal/panel"
)

// tunnelOptions are the connection preferences of "openscale set" (F-171)
// that map to node.Config fields (F-002, F-012, F-024, F-069, F-084,
// F-018) and the service's log level (F-188). Zero values are the
// defaults.
type tunnelOptions struct {
	StaticEndpoints         []string      `json:"static_endpoints,omitempty"`
	HideLocalCandidates     bool          `json:"hide_local_candidates,omitempty"`
	CandidateSkipInterfaces []string      `json:"candidate_skip_interfaces,omitempty"`
	DisableUDPOffload       bool          `json:"disable_udp_offload,omitempty"`
	MagicDNSAllDevices      bool          `json:"magicdns_all_devices,omitempty"`
	DisableCaptiveCheck     bool          `json:"disable_captive_check,omitempty"`
	ConnTrack               filter.Limits `json:"conntrack"`
	LogLevel                string        `json:"log_level,omitempty"`
	// Transport holds the Faz 4 engine options (transport_prefs.go).
	transportOptions
	// wave2Options holds port mapping, shaping, Tor, exit DNS and threat
	// detection (wave2_prefs.go, ADR-0110).
	wave2Options
}

// Limits of the lists in tunnelOptions.
const (
	maxSkipInterfaces = 16
	maxIfacePrefix    = 32
)

func (s settings) tunnel() tunnelOptions {
	if s.Tunnel == nil {
		return tunnelOptions{}
	}
	t := *s.Tunnel
	t.StaticEndpoints = slices.Clone(t.StaticEndpoints)
	t.CandidateSkipInterfaces = slices.Clone(t.CandidateSkipInterfaces)
	t.wave2Options = t.wave2Options.clone()
	return t
}

// ParseStaticEndpoints parses and checks static endpoints like node.New
// does, so a bad value is refused when it is saved.
func ParseStaticEndpoints(in []string) ([]netip.AddrPort, error) {
	if len(in) > control.MaxCandidates {
		return nil, fmt.Errorf("en fazla %d statik uç nokta tanımlanabilir", control.MaxCandidates)
	}
	out := make([]netip.AddrPort, 0, len(in))
	for _, s := range in {
		ap, err := netip.ParseAddrPort(strings.TrimSpace(s))
		if err != nil {
			return nil, fmt.Errorf("statik uç nokta %q IP:port biçiminde olmalı", s)
		}
		ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
		a := ap.Addr()
		if ap.Port() == 0 || a.Zone() != "" || a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() || a.IsLinkLocalUnicast() {
			return nil, fmt.Errorf("statik uç nokta %s kullanılamaz", ap)
		}
		out = append(out, ap)
	}
	return out, nil
}

// ValidSkipInterfaces checks interface name prefixes.
func ValidSkipInterfaces(in []string) error {
	if len(in) > maxSkipInterfaces {
		return fmt.Errorf("en fazla %d arayüz öneki yazılabilir", maxSkipInterfaces)
	}
	for _, p := range in {
		if p == "" || len(p) > maxIfacePrefix || strings.ContainsAny(p, " \t\r\n") {
			return fmt.Errorf("arayüz öneki %q geçersiz", p)
		}
	}
	return nil
}

// ValidConnTrack checks connection tracking limits (F-084).
func ValidConnTrack(l filter.Limits) error {
	return filter.New(time.Now).SetLimits(l)
}

func (t tunnelOptions) validate() error {
	if _, _, err := SplitStaticEndpoints(t.StaticEndpoints); err != nil { // #387: names too
		return err
	}
	if err := ValidSkipInterfaces(t.CandidateSkipInterfaces); err != nil {
		return err
	}
	if err := ValidConnTrack(t.ConnTrack); err != nil {
		return fmt.Errorf("bağlantı takibi sınırı: %w", err)
	}
	if t.LogLevel != "" {
		if _, err := ParseLogLevel(t.LogLevel); err != nil {
			return err
		}
	}
	if err := t.wave2Options.validate(t.transportOptions); err != nil {
		return err
	}
	return t.transportOptions.validate()
}

type tunOptionsKey struct{}

// withTUNOptions passes the interface options to Hooks.OpenTunnel.
func withTUNOptions(ctx context.Context, o osnet.TUNOptions) context.Context {
	return context.WithValue(ctx, tunOptionsKey{}, o)
}

func tunOptionsFrom(ctx context.Context) osnet.TUNOptions {
	o, _ := ctx.Value(tunOptionsKey{}).(osnet.TUNOptions)
	return o
}

func tunOptionsFor(st settings) osnet.TUNOptions {
	return osnet.TUNOptions{DisableOffload: st.tunnel().DisableUDPOffload}
}

// withTunnelOptions adds the saved preferences and the kill switch state
// to the engine configuration. A saved value the engine would refuse is
// left out with a warning, so the tunnel still starts.
func (r *Runtime) withTunnelOptions(st settings, cfg node.Config) node.Config {
	t := st.tunnel()
	if eps, names, err := SplitStaticEndpoints(t.StaticEndpoints); err != nil {
		r.logger.Warn("saved static endpoints are not usable", "error", err.Error())
	} else {
		cfg.StaticEndpoints, cfg.StaticEndpointNames = eps, names
	}
	if err := ValidSkipInterfaces(t.CandidateSkipInterfaces); err != nil {
		r.logger.Warn("saved interface prefixes are not usable", "error", err.Error())
	} else {
		cfg.CandidateSkipInterfaces = t.CandidateSkipInterfaces
	}
	if err := ValidConnTrack(t.ConnTrack); err != nil {
		r.logger.Warn("saved connection tracking limits are not usable", "error", err.Error())
	} else {
		cfg.ConnTrack = t.ConnTrack
	}
	cfg.HideLocalCandidates = t.HideLocalCandidates
	cfg.DisableUDPOffload = t.DisableUDPOffload
	cfg.MagicDNSAllDevices = t.MagicDNSAllDevices
	cfg.DisableCaptiveCheck = t.DisableCaptiveCheck
	cfg.KillSwitchActive = func() bool { return r.killSwitchSnapshot().installed }
	cfg = r.withWave2Options(t.wave2Options, t.transportOptions, cfg)
	return r.withTransportOptions(t.transportOptions, cfg)
}

// ParseLogLevel accepts debug, info, warn and error.
func ParseLogLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info", "":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("günlük seviyesi %q geçersiz; debug, info, warn veya error yazın", s)
}

// LevelName is the lower-case name of a log level.
func LevelName(l slog.Level) string {
	switch {
	case l <= slog.LevelDebug:
		return "debug"
	case l <= slog.LevelInfo:
		return "info"
	case l <= slog.LevelWarn:
		return "warn"
	}
	return "error"
}

// prefSpec describes one key of "openscale get/set".
type prefSpec struct {
	key, def, desc string
	get            func(settings) string
}

func boolText(b bool) string { return strconv.FormatBool(b) }

func durText(d time.Duration) string {
	if d == 0 {
		return "0"
	}
	return d.String()
}

func intText(n int64) string { return strconv.FormatInt(n, 10) }

// prefSpecs is the documented list of preferences, in display order.
var prefSpecs = []prefSpec{
	{"connected", "true", "Tünel açık mı (false: 'openscale down' ile aynı)", func(s settings) string { return boolText(!s.Disconnected) }},
	{"exit-node", "", "İnternet trafiğinin çıktığı çıkış düğümü (boş: yok)", func(s settings) string { return s.ExitNode }},
	{"kill-switch", "true", "Çıkış düğümü kullanılırken kalıcı kill switch", func(s settings) string { return boolText(s.killSwitchOn()) }},
	{"exit-allow-lan", "false", "Çıkış düğümü kullanılırken yerel ağa izin", func(s settings) string { return boolText(s.ExitAllowLAN) }},
	{"shields", "false", "Diğer cihazların bu cihaza açtığı bağlantıları reddet", func(s settings) string { return boolText(s.Shields) }},
	{"accept-dns", "true", "Ağ belgesindeki DNS ayarlarını uygula", func(s settings) string { return boolText(!s.IgnoreNetworkDNS) }},
	{"mtu", "0", "Tünel MTU (0: 1280; 1280-1420)", func(s settings) string { return strconv.Itoa(s.MTU) }},
	{"force-relay", "false", "Bütün eşlere aktarıcı üzerinden ulaş", func(s settings) string { return boolText(s.ForceRelay) }},
	{"relay-rate", "0", "Bu bilgisayardaki koordinatörün cihaz başına aktarıcı hızı, bayt/sn (0: varsayılan)", func(s settings) string { return intText(s.CoordinatorRelayRate) }},
	{"relay-burst", "0", "Koordinatör aktarıcısının ani yük sınırı, bayt (0: varsayılan)", func(s settings) string { return intText(s.CoordinatorRelayBurst) }},
	{"static-endpoints", "", "Bu cihaza ulaşılabilen sabit adresler, virgülle: IP:port (port yönlendirme) veya dinamik DNS için ad:port", func(s settings) string { return strings.Join(s.tunnel().StaticEndpoints, ",") }},
	{"hide-local-candidates", "false", "Yerel ağ ve IPv6 adreslerini koordinatöre bildirme", func(s settings) string { return boolText(s.tunnel().HideLocalCandidates) }},
	{"candidate-skip-interfaces", "", "Adresleri hiç bildirilmeyecek arayüz önekleri, virgülle", func(s settings) string { return strings.Join(s.tunnel().CandidateSkipInterfaces, ",") }},
	{"disable-udp-offload", "false", "Linux UDP/TUN offload'u kapat (sorunlu sürücüler için)", func(s settings) string { return boolText(s.tunnel().DisableUDPOffload) }},
	{"magicdns-all-devices", "false", "MagicDNS bütün cihaz adlarını yanıtlasın (yalnızca tünel kurulanlar değil)", func(s settings) string { return boolText(s.tunnel().MagicDNSAllDevices) }},
	{"disable-captive-check", "false", "Giriş sayfası (captive portal) denetimini kapat", func(s settings) string { return boolText(s.tunnel().DisableCaptiveCheck) }},
	{"conntrack-tcp-timeout", "0", "TCP bağlantı takibi zaman aşımı (0: varsayılan; 30s-24h)", func(s settings) string { return durText(s.tunnel().ConnTrack.TCPTimeout) }},
	{"conntrack-udp-timeout", "0", "UDP akış zaman aşımı (0: varsayılan; 10s-1h)", func(s settings) string { return durText(s.tunnel().ConnTrack.UDPTimeout) }},
	{"conntrack-icmp-timeout", "0", "ICMP akış zaman aşımı (0: varsayılan; 5s-10m)", func(s settings) string { return durText(s.tunnel().ConnTrack.ICMPTimeout) }},
	{"conntrack-other-timeout", "0", "Diğer protokoller için zaman aşımı (0: varsayılan; 10s-1h)", func(s settings) string { return durText(s.tunnel().ConnTrack.OtherTimeout) }},
	{"conntrack-max-flows", "0", "En fazla izlenen akış (0: varsayılan; 1024-1048576)", func(s settings) string { return strconv.Itoa(s.tunnel().ConnTrack.MaxFlows) }},
	{"conntrack-max-fragments", "0", "En fazla bekleyen parça (0: varsayılan; 64-65536)", func(s settings) string { return strconv.Itoa(s.tunnel().ConnTrack.MaxFragments) }},
	{"post-quantum", "true", "Eşlerle kuantum sonrası (ML-KEM-768) ön paylaşımlı anahtar anlaş (ADR-0033)", func(s settings) string { return boolText(!s.tunnel().PostQuantumOff) }},
	{"psk-rotation", "0", "Kuantum sonrası anahtarın yenilenme aralığı (0: 10m; 2m-24h)", func(s settings) string { return durText(s.tunnel().PSKRotation) }},
	{"tcp-fallback", "", "UDP engelliyken koordinatörün TCP adresi, ana-makine:port (boş: koordinatör:443; ADR-0032)", func(s settings) string { return s.tunnel().TCPFallback }},
	{"disable-tcp-fallback", "false", "Koordinatöre TCP yedeğini hiç kullanma", func(s settings) string { return boolText(s.tunnel().DisableTCPFallback) }},
	{"keepalive", "0", "WireGuard keepalive aralığı (0: 25s; 10s-120s, tam saniye)", func(s settings) string { return durText(s.tunnel().Keepalive) }},
	{"adaptive-keepalive", "false", "Bağlantı kopunca keepalive'ı kısalt, uzun süre sorunsuzsa geri uzat", func(s settings) string { return boolText(s.tunnel().AdaptiveKeepalive) }},
	{"lazy-peers", "false", "Eşleri yalnızca trafik olunca WireGuard'a ekle (büyük ağlar için)", func(s settings) string { return boolText(s.tunnel().LazyPeers) }},
	{"lazy-idle", "0", "Tembel eşin trafiksiz kalınca çıkarılma süresi (0: 10m; 1m-24h)", func(s settings) string { return durText(s.tunnel().LazyIdle) }},
	{"sealed-candidates", "auto", "Uç nokta adaylarını eşe uçtan uca şifreli gönder: auto, only (yalnızca şifreli), off (ADR-0230)", func(s settings) string { return sealedModeText(s.tunnel().SealedCandidates) }},
	{"birthday-scan", "true", "İki taraf da simetrik NAT arkasındaysa sınırlı rastgele port taraması (ADR-0231)", func(s settings) string { return boolText(!s.tunnel().BirthdayScanOff) }},
	{"parser-sandbox", "auto", "Ağdan gelen belgeleri ayrıcalıksız yardımcı süreçte ayrıştır: auto, required, off (ADR-0233)", func(s settings) string { return parserModeText(s.tunnel().ParserSandbox) }},
	{"coordinator-tcp-listen", "", "Bu bilgisayardaki koordinatörün TCP dinleme adresi, ör. :443 (boş: kapalı; ADR-0032)", func(s settings) string { return s.CoordinatorTCPListen }},
	{"coordinator-tcp-max-conns", "0", "Koordinatör TCP bağlantı sınırı (0: 256; en fazla 4096)", func(s settings) string { return strconv.Itoa(s.CoordinatorTCPMaxConns) }},
	{"coordinator-tcp-max-conns-per-ip", "0", "Koordinatör TCP adres başına bağlantı sınırı (0: 8)", func(s settings) string { return strconv.Itoa(s.CoordinatorTCPMaxConnsPerIP) }},
	{"log-level", "info", "Servis günlük seviyesi: debug, info, warn, error", func(s settings) string {
		if l := s.tunnel().LogLevel; l != "" {
			return l
		}
		return "info"
	}},
}

func findPref(key string) (prefSpec, bool) {
	for _, p := range prefSpecs {
		if p.key == key {
			return p, true
		}
	}
	return prefSpec{}, false
}

// PrefKeys lists the keys "openscale set" accepts.
func PrefKeys() []string {
	out := make([]string, 0, len(prefSpecs))
	for _, p := range prefSpecs {
		out = append(out, p.key)
	}
	return out
}

func prefsOf(st settings) []panel.Pref {
	out := make([]panel.Pref, 0, len(prefSpecs))
	for _, p := range prefSpecs {
		out = append(out, panel.Pref{Key: p.key, Value: p.get(st), Default: p.def, Description: p.desc, RestartsConnection: restartsConnection(p.key)})
	}
	return out
}

// DiagPrefs implements panel.Diagnostics.
func (r *Runtime) DiagPrefs() ([]panel.Pref, error) {
	st, err := r.currentSettings()
	if err != nil {
		return nil, err
	}
	return prefsOf(st), nil
}

func parseBoolPref(key, v string) (bool, error) {
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	if err != nil {
		return false, fmt.Errorf("%s: true veya false yazın", key)
	}
	return b, nil
}

func splitList(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func parseDurPref(key, v string) (time.Duration, error) {
	v = strings.TrimSpace(v)
	if v == "" || v == "0" {
		return 0, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("%s: süre yazın, ör. 90s, 5m, 2h (0: varsayılan)", key)
	}
	return d, nil
}

func parseIntPref(key, v string, bits int) (int64, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(v, 10, bits)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("%s: sıfır veya pozitif bir tam sayı yazın", key)
	}
	return n, nil
}

// applyTunnelPref changes one tunnelOptions key; ok is false for keys that
// are not tunnel options.
func applyTunnelPref(t *tunnelOptions, key, v string) (bool, error) {
	var err error
	switch key {
	case "static-endpoints":
		t.StaticEndpoints = splitList(v)
	case "candidate-skip-interfaces":
		t.CandidateSkipInterfaces = splitList(v)
	case "hide-local-candidates":
		t.HideLocalCandidates, err = parseBoolPref(key, v)
	case "disable-udp-offload":
		t.DisableUDPOffload, err = parseBoolPref(key, v)
	case "magicdns-all-devices":
		t.MagicDNSAllDevices, err = parseBoolPref(key, v)
	case "disable-captive-check":
		t.DisableCaptiveCheck, err = parseBoolPref(key, v)
	case "conntrack-tcp-timeout":
		t.ConnTrack.TCPTimeout, err = parseDurPref(key, v)
	case "conntrack-udp-timeout":
		t.ConnTrack.UDPTimeout, err = parseDurPref(key, v)
	case "conntrack-icmp-timeout":
		t.ConnTrack.ICMPTimeout, err = parseDurPref(key, v)
	case "conntrack-other-timeout":
		t.ConnTrack.OtherTimeout, err = parseDurPref(key, v)
	case "conntrack-max-flows":
		var n int64
		n, err = parseIntPref(key, v, 32)
		t.ConnTrack.MaxFlows = int(n)
	case "conntrack-max-fragments":
		var n int64
		n, err = parseIntPref(key, v, 32)
		t.ConnTrack.MaxFragments = int(n)
	case "log-level":
		var l slog.Level
		if l, err = ParseLogLevel(v); err == nil {
			t.LogLevel = LevelName(l)
		}
	default:
		if ok, err := applyWave2Pref(&t.wave2Options, key, v); ok {
			return true, err
		}
		return applyTransportPref(&t.transportOptions, key, v)
	}
	return true, err
}

// DiagSetPrefs implements panel.Diagnostics (F-171). Every value is
// checked before anything is saved; then the settings are applied through
// the same paths as the panel and the tray, in a fixed order.
func (r *Runtime) DiagSetPrefs(change map[string]string) ([]panel.Pref, error) {
	cur, err := r.currentSettings()
	if err != nil {
		return nil, err
	}
	for k := range change {
		if _, ok := findPref(k); !ok {
			return nil, fmt.Errorf("bilinmeyen ayar %q; geçerli ayarlar: %s", k, strings.Join(PrefKeys(), ", "))
		}
	}
	// Check every value first.
	topt := cur.tunnel()
	tunnelChanged := false
	var adv panel.AdvancedSettings
	var connected, shields, acceptDNS *bool
	var exitNode *string
	ks, lan := cur.killSwitchOn(), cur.ExitAllowLAN
	exitOpts := false
	for _, spec := range prefSpecs {
		v, ok := change[spec.key]
		if !ok {
			continue
		}
		if handled, err := applyTunnelPref(&topt, spec.key, v); handled {
			if err != nil {
				return nil, err
			}
			tunnelChanged = true
			continue
		}
		switch spec.key {
		case "connected", "shields", "accept-dns", "force-relay", "kill-switch", "exit-allow-lan":
			b, err := parseBoolPref(spec.key, v)
			if err != nil {
				return nil, err
			}
			switch spec.key {
			case "connected":
				connected = &b
			case "shields":
				shields = &b
			case "accept-dns":
				acceptDNS = &b
			case "force-relay":
				adv.ForceRelay = &b
			case "kill-switch":
				ks, exitOpts = b, true
			case "exit-allow-lan":
				lan, exitOpts = b, true
			}
		case "exit-node":
			name := strings.TrimSpace(v)
			exitNode = &name
		case "mtu":
			n, err := parseIntPref(spec.key, v, 32)
			if err != nil {
				return nil, err
			}
			m := int(n)
			if m != 0 {
				if err := node.ValidateMTU(m); err != nil {
					return nil, err
				}
			}
			adv.MTU = &m
		case "relay-rate", "relay-burst":
			n, err := parseIntPref(spec.key, v, 64)
			if err != nil {
				return nil, err
			}
			if spec.key == "relay-rate" {
				adv.RelayRate = &n
			} else {
				adv.RelayBurst = &n
			}
		case "coordinator-tcp-listen", "coordinator-tcp-max-conns", "coordinator-tcp-max-conns-per-ip":
			if err := applyCoordinatorTCPPref(&adv, spec.key, v); err != nil {
				return nil, err
			}
		}
	}
	if tunnelChanged {
		if err := topt.validate(); err != nil {
			return nil, err
		}
		if _, err := member.Open(r.path(DeviceDir)); err != nil && !tunnelEqualIgnoringLog(cur.tunnel(), topt) {
			return nil, errors.New("bu bilgisayar henüz bir ağa bağlı değil")
		}
	}

	// Apply.
	if tunnelChanged {
		restart := false
		err := r.updateSettings(func(st *settings) (bool, error) {
			old := st.tunnel()
			next := topt
			st.Tunnel = &next
			restart = !tunnelEqualIgnoringLog(old, next)
			return true, nil
		})
		if err != nil {
			return nil, err
		}
		if l, err := ParseLogLevel(topt.LogLevel); err == nil {
			LogLevel.Set(l)
		}
		if restart {
			if st, err := r.currentSettings(); err == nil && !st.Disconnected {
				r.logger.Info("connection preferences changed; restarting the tunnel")
				r.startDevice()
			}
		}
	}
	if adv.MTU != nil || adv.ForceRelay != nil || adv.RelayRate != nil || adv.RelayBurst != nil || advancedHasCoordinatorTCP(adv) {
		if err := r.SetAdvanced(adv); err != nil {
			return nil, err
		}
	}
	if acceptDNS != nil {
		if err := r.SetAcceptNetworkDNS(*acceptDNS); err != nil {
			return nil, err
		}
	}
	if shields != nil {
		if err := r.SetShields(*shields); err != nil {
			return nil, err
		}
	}
	if exitOpts {
		if err := r.SetExitOptions(ks, lan); err != nil {
			return nil, err
		}
	}
	if exitNode != nil {
		if err := r.SetExitNode(*exitNode); err != nil {
			return nil, err
		}
	}
	if connected != nil {
		if err := r.SetConnected(*connected); err != nil {
			return nil, err
		}
	}
	r.auditLocal("preferences_changed", "Komut satırından tercih değiştirildi: "+strings.Join(slices.Sorted(maps.Keys(change)), ", ")+".") // #187
	return r.DiagPrefs()
}

func tunnelEqualIgnoringLog(a, b tunnelOptions) bool {
	a.LogLevel, b.LogLevel = "", ""
	return slices.Equal(a.StaticEndpoints, b.StaticEndpoints) &&
		slices.Equal(a.CandidateSkipInterfaces, b.CandidateSkipInterfaces) &&
		a.HideLocalCandidates == b.HideLocalCandidates && a.DisableUDPOffload == b.DisableUDPOffload &&
		a.MagicDNSAllDevices == b.MagicDNSAllDevices && a.DisableCaptiveCheck == b.DisableCaptiveCheck &&
		a.ConnTrack == b.ConnTrack && a.transportOptions == b.transportOptions && a.wave2Options.equal(b.wave2Options)
}
