package service

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/coordinator"
	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/panel"
)

// transportOptions are the Faz 4 engine options (ADR-0032 TCP transport,
// ADR-0033 post-quantum PSK, F-020 lazy peers, F-021 keepalive), saved in
// settings.json under "tunnel" next to the other connection preferences.
// Zero values are the engine defaults, so an older settings file keeps
// its behaviour.
type transportOptions struct {
	// PostQuantumOff turns the post-quantum PSK off; the default is on.
	PostQuantumOff     bool          `json:"post_quantum_off,omitempty"`
	PSKRotation        time.Duration `json:"psk_rotation,omitempty"`
	TCPFallback        string        `json:"tcp_fallback,omitempty"`
	DisableTCPFallback bool          `json:"disable_tcp_fallback,omitempty"`
	Keepalive          time.Duration `json:"keepalive,omitempty"`
	AdaptiveKeepalive  bool          `json:"adaptive_keepalive,omitempty"`
	LazyPeers          bool          `json:"lazy_peers,omitempty"`
	LazyIdle           time.Duration `json:"lazy_idle,omitempty"`
	// Network and privilege separation (netsep_prefs.go, ADR-0230, ADR-0231, ADR-0233).
	SealedCandidates string `json:"sealed_candidates,omitempty"`
	BirthdayScanOff  bool   `json:"birthday_scan_off,omitempty"`
	ParserSandbox    string `json:"parser_sandbox,omitempty"`
}

// maxHostPort bounds a host:port option.
const maxHostPort = 255

// ValidPSKRotation checks a post-quantum PSK rotation interval; 0 is the
// default.
func ValidPSKRotation(d time.Duration) error {
	if d != 0 && (d < node.MinPSKRotation || d > node.MaxPSKRotation) {
		return fmt.Errorf("PSK yenileme aralığı %s ile %s arasında olmalı (0: varsayılan %s)", node.MinPSKRotation, node.MaxPSKRotation, node.DefaultPSKRotation)
	}
	return nil
}

// ValidKeepalive checks a keepalive interval; 0 is the default.
func ValidKeepalive(d time.Duration) error {
	if d == 0 {
		return nil
	}
	return node.ValidateKeepalive(d)
}

// ValidLazyIdle checks the lazy peer idle time; 0 is the default.
func ValidLazyIdle(d time.Duration) error {
	if d != 0 && (d < node.MinLazyIdle || d > node.MaxLazyIdle) {
		return fmt.Errorf("tembel eş boşta kalma süresi %s ile %s arasında olmalı (0: varsayılan %s)", node.MinLazyIdle, node.MaxLazyIdle, node.DefaultLazyIdle)
	}
	return nil
}

// ValidTCPFallback checks the coordinator's TCP transport address the way
// node.New does, plus a numeric port; "" uses the coordinator's host on
// port 443.
func ValidTCPFallback(s string) error {
	if s == "" {
		return nil
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil || host == "" || len(s) > maxHostPort || strings.ContainsAny(s, " \t\r\n/") {
		return fmt.Errorf("TCP yedek adresi %q geçersiz; ana-makine:port biçiminde olmalı", s)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("TCP yedek adresinin portu 1 ile 65535 arasında olmalı")
	}
	return nil
}

// ValidCoordinatorTCP checks the coordinator's TCP listener settings: the
// address is "" (off) or [IP]:port, never a host name, so it cannot bind
// somewhere a name lookup chose.
func ValidCoordinatorTCP(listen string, maxConns, perIP int) error {
	if listen != "" {
		host, port, err := net.SplitHostPort(listen)
		if err != nil || len(listen) > maxHostPort {
			return fmt.Errorf("koordinatör TCP adresi %q geçersiz; :443 veya IP:port yazın", listen)
		}
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return errors.New("koordinatör TCP portu 1 ile 65535 arasında olmalı")
		}
		if host != "" {
			if _, err := netip.ParseAddr(host); err != nil {
				return fmt.Errorf("koordinatör TCP adresinde ana makine bir IP adresi olmalı: %q", host)
			}
		}
	}
	if maxConns < 0 || maxConns > coordinator.MaxTCPMaxConns {
		return fmt.Errorf("koordinatör TCP bağlantı sınırı 0 ile %d arasında olmalı", coordinator.MaxTCPMaxConns)
	}
	if perIP < 0 || perIP > coordinator.MaxTCPMaxConns {
		return fmt.Errorf("koordinatör TCP adres başına sınırı 0 ile %d arasında olmalı", coordinator.MaxTCPMaxConns)
	}
	if maxConns != 0 && perIP > maxConns {
		return errors.New("adres başına TCP bağlantı sınırı toplam sınırdan büyük olamaz")
	}
	return nil
}

func (t transportOptions) validate() error {
	if err := ValidPSKRotation(t.PSKRotation); err != nil {
		return err
	}
	if err := ValidTCPFallback(t.TCPFallback); err != nil {
		return err
	}
	if err := ValidKeepalive(t.Keepalive); err != nil {
		return err
	}
	if err := ValidLazyIdle(t.LazyIdle); err != nil {
		return err
	}
	return t.validateNetSep()
}

// withTransportOptions copies the saved Faz 4 options into the engine
// configuration. A value the engine would refuse is left out with a
// warning, so the tunnel still starts with the default.
func (r *Runtime) withTransportOptions(t transportOptions, cfg node.Config) node.Config {
	if t.PostQuantumOff {
		cfg.PostQuantum = node.PostQuantumOff
	} else {
		cfg.PostQuantum = node.PostQuantumOn
	}
	if err := ValidPSKRotation(t.PSKRotation); err != nil {
		r.logger.Warn("saved PSK rotation is not usable", "error", err.Error())
	} else {
		cfg.PSKRotation = t.PSKRotation
	}
	if err := ValidTCPFallback(t.TCPFallback); err != nil {
		r.logger.Warn("saved TCP fallback address is not usable", "error", err.Error())
	} else {
		cfg.TCPFallback = t.TCPFallback
	}
	cfg.DisableTCPFallback = t.DisableTCPFallback
	if err := ValidKeepalive(t.Keepalive); err != nil {
		r.logger.Warn("saved keepalive is not usable", "error", err.Error())
	} else {
		cfg.Keepalive = t.Keepalive
	}
	cfg.AdaptiveKeepalive = t.AdaptiveKeepalive
	cfg.LazyPeers = t.LazyPeers
	if err := ValidLazyIdle(t.LazyIdle); err != nil {
		r.logger.Warn("saved lazy peer idle time is not usable", "error", err.Error())
	} else {
		cfg.LazyIdle = t.LazyIdle
	}
	return r.withNetSepOptions(t, cfg)
}

// applyTransportPref changes one Faz 4 key of "openscale set"; ok is false
// for other keys.
func applyTransportPref(t *transportOptions, key, v string) (bool, error) {
	var err error
	switch key {
	case "post-quantum":
		var on bool
		on, err = parseBoolPref(key, v)
		t.PostQuantumOff = !on
	case "psk-rotation":
		t.PSKRotation, err = parseDurPref(key, v)
	case "tcp-fallback":
		t.TCPFallback = strings.TrimSpace(v)
	case "disable-tcp-fallback":
		t.DisableTCPFallback, err = parseBoolPref(key, v)
	case "keepalive":
		t.Keepalive, err = parseDurPref(key, v)
	case "adaptive-keepalive":
		t.AdaptiveKeepalive, err = parseBoolPref(key, v)
	case "lazy-peers":
		t.LazyPeers, err = parseBoolPref(key, v)
	case "lazy-idle":
		t.LazyIdle, err = parseDurPref(key, v)
	default:
		return applyNetSepPref(t, key, v)
	}
	return true, err
}

// applyCoordinatorTCPPref turns a coordinator TCP key of "openscale set"
// into a panel.AdvancedSettings change.
func applyCoordinatorTCPPref(a *panel.AdvancedSettings, key, v string) error {
	switch key {
	case "coordinator-tcp-listen":
		s := strings.TrimSpace(v)
		a.CoordinatorTCPListen = &s
	case "coordinator-tcp-max-conns", "coordinator-tcp-max-conns-per-ip":
		n, err := parseIntPref(key, v, 32)
		if err != nil {
			return err
		}
		m := int(n)
		if key == "coordinator-tcp-max-conns" {
			a.CoordinatorTCPMaxConns = &m
		} else {
			a.CoordinatorTCPMaxConnsPerIP = &m
		}
	}
	return nil
}

func advancedHasTransport(a panel.AdvancedSettings) bool {
	return a.PostQuantum != nil || a.PSKRotationSec != nil || a.TCPFallback != nil || a.DisableTCPFallback != nil ||
		a.KeepaliveSec != nil || a.AdaptiveKeepalive != nil || a.LazyPeers != nil || a.LazyIdleSec != nil
}

func advancedHasCoordinatorTCP(a panel.AdvancedSettings) bool {
	return a.CoordinatorTCPListen != nil || a.CoordinatorTCPMaxConns != nil || a.CoordinatorTCPMaxConnsPerIP != nil
}

// seconds converts a panel duration; negative values are refused by the
// checks that follow.
func seconds(n int64) time.Duration { return time.Duration(n) * time.Second }

// applyAdvancedTransport applies the Faz 4 fields of a panel or CLI change
// to next and checks the result.
func applyAdvancedTransport(next *settings, a panel.AdvancedSettings) error {
	if advancedHasTransport(a) {
		t := next.tunnel()
		if a.PostQuantum != nil {
			t.PostQuantumOff = !*a.PostQuantum
		}
		if a.PSKRotationSec != nil {
			t.PSKRotation = seconds(*a.PSKRotationSec)
		}
		if a.TCPFallback != nil {
			t.TCPFallback = strings.TrimSpace(*a.TCPFallback)
		}
		if a.DisableTCPFallback != nil {
			t.DisableTCPFallback = *a.DisableTCPFallback
		}
		if a.KeepaliveSec != nil {
			t.Keepalive = seconds(*a.KeepaliveSec)
		}
		if a.AdaptiveKeepalive != nil {
			t.AdaptiveKeepalive = *a.AdaptiveKeepalive
		}
		if a.LazyPeers != nil {
			t.LazyPeers = *a.LazyPeers
		}
		if a.LazyIdleSec != nil {
			t.LazyIdle = seconds(*a.LazyIdleSec)
		}
		if err := t.transportOptions.validate(); err != nil {
			return err
		}
		next.Tunnel = &t
	}
	if advancedHasCoordinatorTCP(a) {
		if a.CoordinatorTCPListen != nil {
			next.CoordinatorTCPListen = strings.TrimSpace(*a.CoordinatorTCPListen)
		}
		if a.CoordinatorTCPMaxConns != nil {
			next.CoordinatorTCPMaxConns = *a.CoordinatorTCPMaxConns
		}
		if a.CoordinatorTCPMaxConnsPerIP != nil {
			next.CoordinatorTCPMaxConnsPerIP = *a.CoordinatorTCPMaxConnsPerIP
		}
		if err := ValidCoordinatorTCP(next.CoordinatorTCPListen, next.CoordinatorTCPMaxConns, next.CoordinatorTCPMaxConnsPerIP); err != nil {
			return err
		}
	}
	return nil
}

// coordinatorTCPChanged reports whether the coordinator must restart.
func coordinatorTCPChanged(a, b settings) bool {
	return a.CoordinatorTCPListen != b.CoordinatorTCPListen || a.CoordinatorTCPMaxConns != b.CoordinatorTCPMaxConns ||
		a.CoordinatorTCPMaxConnsPerIP != b.CoordinatorTCPMaxConnsPerIP
}

// coordinatorTCPConfig returns the saved TCP transport settings, or none
// with a warning when they are not usable.
func (r *Runtime) coordinatorTCPConfig(st settings) (listen string, maxConns, perIP int) {
	if err := ValidCoordinatorTCP(st.CoordinatorTCPListen, st.CoordinatorTCPMaxConns, st.CoordinatorTCPMaxConnsPerIP); err != nil {
		r.logger.Warn("saved coordinator TCP settings are not usable; TCP transport stays off", "error", err.Error())
		return "", 0, 0
	}
	return st.CoordinatorTCPListen, st.CoordinatorTCPMaxConns, st.CoordinatorTCPMaxConnsPerIP
}

// transportStatus is what the panel shows of the saved options.
func transportStatus(st settings) panel.TransportSettings {
	t := st.tunnel()
	return panel.TransportSettings{
		PostQuantum:        !t.PostQuantumOff,
		PSKRotationSec:     int64(t.PSKRotation / time.Second),
		TCPFallback:        t.TCPFallback,
		DisableTCPFallback: t.DisableTCPFallback,
		KeepaliveSec:       int64(t.Keepalive / time.Second),
		AdaptiveKeepalive:  t.AdaptiveKeepalive,
		LazyPeers:          t.LazyPeers,
		LazyIdleSec:        int64(t.LazyIdle / time.Second),
	}
}
