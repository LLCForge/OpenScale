package node

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"slices"
	"strconv"
	"time"

	"github.com/openscale/openscale/internal/obfs"
)

// Exit node MITM canary (#628, ADR-0188). An exit node sees members'
// internet traffic; a malicious or compromised one could terminate TLS
// with its own certificate. While an exit node is in use, this device
// opens TLS connections to owner-chosen servers and compares their keys
// with the pins the owner gave or, without pins, with the keys this device
// saw while no exit node was in use (trust on first use). A different key
// or a chain the system does not trust raises an alarm.
//
// No server is built in (ADR-0008, tools/telemetrycheck): the owner names
// the targets. Only the handshake is made; no request is sent.

// ExitCanaryConfig configures the canary.
type ExitCanaryConfig struct {
	// Targets are "host:port" TLS servers with optional pins.
	Targets []CanaryTarget `json:"targets,omitempty"`
	// Interval between checks while an exit node is in use; zero uses
	// DefaultCanaryInterval.
	Interval time.Duration `json:"interval,omitempty"`
}

// CanaryTarget is one TLS server.
type CanaryTarget struct {
	Address string   `json:"address"`
	Pins    []string `json:"pins,omitempty"`
}

// Canary bounds.
const (
	DefaultCanaryInterval = 30 * time.Minute
	MinCanaryInterval     = 5 * time.Minute
	MaxCanaryInterval     = 24 * time.Hour
	MaxCanaryTargets      = 8
	canaryTimeout         = 10 * time.Second
)

// Canary results.
const (
	CanaryOK          = "ok"
	CanaryLearned     = "learned"
	CanaryMITM        = "mitm"
	CanaryUntrusted   = "untrusted"
	CanaryUnreachable = "unreachable"
)

// CanaryResult is the outcome for one target.
type CanaryResult struct {
	Address string    `json:"address"`
	Status  string    `json:"status"`
	Pin     string    `json:"pin,omitempty"`
	ViaExit string    `json:"via_exit,omitempty"`
	At      time.Time `json:"at"`
	Detail  string    `json:"detail,omitempty"`
}

type canaryState struct {
	baseline map[string][]obfs.Pin
	results  map[string]CanaryResult
	next     time.Time
}

func (c ExitCanaryConfig) validate() error {
	if len(c.Targets) > MaxCanaryTargets {
		return fmt.Errorf("en fazla %d kanarya sunucusu", MaxCanaryTargets)
	}
	if c.Interval != 0 && (c.Interval < MinCanaryInterval || c.Interval > MaxCanaryInterval) {
		return fmt.Errorf("kanarya aralığı %s ile %s arasında olmalı", MinCanaryInterval, MaxCanaryInterval)
	}
	for _, t := range c.Targets {
		host, port, err := net.SplitHostPort(t.Address)
		if err != nil || host == "" || len(host) > 253 {
			return fmt.Errorf("kanarya adresi %q geçersiz; sunucu:port olmalı", t.Address)
		}
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("kanarya adresinin portu %q geçersiz", port)
		}
		if _, err := obfs.ParsePins(t.Pins); err != nil {
			return err
		}
	}
	return nil
}

func (c ExitCanaryConfig) interval() time.Duration {
	if c.Interval == 0 {
		return DefaultCanaryInterval
	}
	return c.Interval
}

// canaryDial opens a TCP connection; tests replace it.
type canaryDial func(ctx context.Context, address string) (net.Conn, error)

// probeCanary makes one TLS handshake and classifies it against expected
// (empty: learn). roots nil uses the system CAs.
func probeCanary(ctx context.Context, dial canaryDial, address string, expected []obfs.Pin, roots *x509.CertPool, now time.Time) CanaryResult {
	res := CanaryResult{Address: address, At: now.Truncate(time.Minute)}
	host, _, _ := net.SplitHostPort(address)
	cctx, cancel := context.WithTimeout(ctx, canaryTimeout)
	defer cancel()
	raw, err := dial(cctx, address)
	if err != nil {
		res.Status, res.Detail = CanaryUnreachable, "bağlantı kurulamadı"
		return res
	}
	defer raw.Close()
	if d, ok := cctx.Deadline(); ok {
		_ = raw.SetDeadline(d)
	}
	// Verification runs by hand below, so an untrusted chain is reported
	// as such instead of just failing the handshake.
	tc := tls.Client(raw, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}) //nolint:gosec // verified below
	if err := tc.HandshakeContext(cctx); err != nil {
		res.Status, res.Detail = CanaryUnreachable, "TLS el sıkışması başarısız"
		return res
	}
	certs := tc.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		res.Status, res.Detail = CanaryUnreachable, "sertifika yok"
		return res
	}
	leaf := certs[0]
	pin := obfs.SPKIPin(leaf)
	res.Pin = pin.String()
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	_, verr := leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: roots, Intermediates: inter, CurrentTime: now})
	switch {
	case len(expected) > 0 && !slices.Contains(expected, pin):
		res.Status, res.Detail = CanaryMITM, "sunucu anahtarı beklenenden farklı"
	case verr != nil:
		res.Status, res.Detail = CanaryUntrusted, "sertifika zinciri sistemce güvenilir değil"
	case len(expected) == 0:
		res.Status = CanaryLearned
	default:
		res.Status = CanaryOK
	}
	return res
}

// runCanary checks the targets when due: with an exit node in use against
// the pins or baseline, without one to learn the baseline.
func (e *Engine) runCanary(ctx context.Context, dial canaryDial, roots *x509.CertPool) {
	cfg := e.cfg.G3.ExitCanary
	if len(cfg.Targets) == 0 {
		return
	}
	now := e.cfg.Now()
	exit := e.ExitNode()
	s := &e.g3
	s.mu.Lock()
	if now.Before(s.canary.next) {
		s.mu.Unlock()
		return
	}
	s.canary.next = now.Add(cfg.interval())
	if s.canary.baseline == nil {
		s.canary.baseline, s.canary.results = map[string][]obfs.Pin{}, map[string]CanaryResult{}
	}
	s.mu.Unlock()
	for _, t := range cfg.Targets {
		pins, _ := obfs.ParsePins(t.Pins)
		s.mu.Lock()
		base := s.canary.baseline[t.Address]
		s.mu.Unlock()
		expected := pins
		if len(expected) == 0 {
			expected = base
		}
		if exit == "" {
			if len(pins) > 0 || len(base) > 0 {
				continue // nothing to learn without an exit node
			}
			r := probeCanary(ctx, dial, t.Address, nil, roots, now)
			s.mu.Lock()
			if r.Status == CanaryLearned {
				p, _ := obfs.ParsePin(r.Pin)
				s.canary.baseline[t.Address] = []obfs.Pin{p}
			}
			s.canary.results[t.Address] = r
			s.mu.Unlock()
			continue
		}
		if len(expected) == 0 {
			continue // no pin and no baseline: cannot judge
		}
		r := probeCanary(ctx, dial, t.Address, expected, roots, now)
		r.ViaExit = exit
		s.mu.Lock()
		s.canary.results[t.Address] = r
		s.mu.Unlock()
		if r.Status == CanaryMITM || r.Status == CanaryUntrusted {
			e.raiseG3(G3Alert{Kind: "exit_mitm", Peer: exit,
				Text: fmt.Sprintf("Çıkış düğümü %s üzerinden %s için %s: TLS trafiğine müdahale ediliyor olabilir.", exit, t.Address, r.Detail)})
		}
	}
}

// ExitCanaryResults returns the last result per target.
func (e *Engine) ExitCanaryResults() []CanaryResult {
	s := &e.g3
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]CanaryResult, 0, len(s.canary.results))
	for _, r := range s.canary.results {
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b CanaryResult) int { return compareStrings(a.Address, b.Address) })
	return out
}

// defaultCanaryDial dials with the OS routes: through the exit node while
// one is in use.
func defaultCanaryDial(ctx context.Context, address string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", address)
}
