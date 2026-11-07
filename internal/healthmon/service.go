package healthmon

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
)

// Probe kinds.
const (
	ProbeTCP   = "tcp"
	ProbeHTTP  = "http"
	ProbeHTTPS = "https"
)

// Limits of service monitoring.
const (
	MaxTargets      = 64
	MinInterval     = 30 * time.Second
	DefaultInterval = time.Minute
	DefaultTimeout  = 5 * time.Second
	MaxTimeout      = 30 * time.Second
	DefaultFall     = 3
	DefaultRise     = 2
	maxParallel     = 8
	maxProbeBody    = 64 << 10
	maxPath         = 256
	maxName         = 64
)

// Target is one owner-defined service to watch.
type Target struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
	// Addr is the service's tunnel address (or an address inside a prefix
	// the owner listed) and port.
	Addr netip.AddrPort `json:"addr"`
	// Host is the HTTP Host header and TLS server name (a MagicDNS name).
	Host string `json:"host,omitempty"`
	// Path is the HTTP path (default "/").
	Path string `json:"path,omitempty"`
	// StatusMin and StatusMax bound an accepted HTTP status (default
	// 200-399).
	StatusMin int           `json:"status_min,omitempty"`
	StatusMax int           `json:"status_max,omitempty"`
	Interval  time.Duration `json:"interval,omitempty"`
	Timeout   time.Duration `json:"timeout,omitempty"`
	// Fall consecutive failures mark the service down; Rise consecutive
	// successes mark it up again.
	Fall int `json:"fall,omitempty"`
	Rise int `json:"rise,omitempty"`
}

// Scope is where probes may go: the tunnel's prefixes from the signed
// document plus prefixes the owner added (a home LAN behind a subnet
// router). Nothing outside it is ever dialed.
type Scope struct {
	Prefixes []netip.Prefix
}

// Allows reports whether a may be probed.
func (s Scope) Allows(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || a.IsUnspecified() || a.IsMulticast() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() {
		return false
	}
	for _, p := range s.Prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// ErrOutOfScope is returned for a target outside the scope.
var ErrOutOfScope = errors.New("hedef tünel adresi veya sahibin eklediği bir ağ içinde olmalı")

func validName(s string) bool {
	if s == "" || len(s) > maxName {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return strings.TrimSpace(s) == s
}

// withDefaults returns t with defaults applied.
func (t Target) withDefaults() Target {
	if t.Interval == 0 {
		t.Interval = DefaultInterval
	}
	if t.Timeout == 0 {
		t.Timeout = DefaultTimeout
	}
	if t.Fall == 0 {
		t.Fall = DefaultFall
	}
	if t.Rise == 0 {
		t.Rise = DefaultRise
	}
	if t.Kind != ProbeTCP {
		if t.Path == "" {
			t.Path = "/"
		}
		if t.StatusMin == 0 && t.StatusMax == 0 {
			t.StatusMin, t.StatusMax = 200, 399
		}
	}
	return t
}

// Validate checks t against scope.
func (t Target) Validate(scope Scope) error {
	t = t.withDefaults()
	if !validName(t.Name) {
		return fmt.Errorf("servis adı 1-%d karakter olmalı", maxName)
	}
	switch t.Kind {
	case ProbeTCP, ProbeHTTP, ProbeHTTPS:
	default:
		return fmt.Errorf("%s: yoklama türü tcp, http veya https olmalı", t.Name)
	}
	if !t.Addr.IsValid() || t.Addr.Port() == 0 {
		return fmt.Errorf("%s: adres ve port gerekli", t.Name)
	}
	if !scope.Allows(t.Addr.Addr()) {
		return fmt.Errorf("%s: %w", t.Name, ErrOutOfScope)
	}
	if t.Interval < MinInterval || t.Interval > 24*time.Hour {
		return fmt.Errorf("%s: yoklama aralığı en az %s olmalı", t.Name, MinInterval)
	}
	if t.Timeout <= 0 || t.Timeout > MaxTimeout || t.Timeout >= t.Interval {
		return fmt.Errorf("%s: zaman aşımı 0-%s arasında ve aralıktan kısa olmalı", t.Name, MaxTimeout)
	}
	if t.Fall < 1 || t.Fall > 20 || t.Rise < 1 || t.Rise > 20 {
		return fmt.Errorf("%s: düşme ve kalkma eşikleri 1-20 olmalı", t.Name)
	}
	if t.Kind != ProbeTCP {
		if len(t.Path) > maxPath || !strings.HasPrefix(t.Path, "/") || strings.ContainsAny(t.Path, " \r\n#") {
			return fmt.Errorf("%s: HTTP yolu / ile başlamalı", t.Name)
		}
		if t.Host != "" && (len(t.Host) > 253 || strings.ContainsAny(t.Host, " /\r\n@")) {
			return fmt.Errorf("%s: Host geçersiz", t.Name)
		}
		if t.StatusMin < 100 || t.StatusMax > 599 || t.StatusMin > t.StatusMax {
			return fmt.Errorf("%s: kabul edilen durum aralığı geçersiz", t.Name)
		}
	}
	return nil
}

// ProbeResult is one probe's outcome.
type ProbeResult struct {
	OK      bool          `json:"ok"`
	Latency time.Duration `json:"latency"`
	Status  int           `json:"status,omitempty"`
	Error   string        `json:"error,omitempty"`
	At      time.Time     `json:"at"`
}

// Prober performs probes. Dial is replaced in tests; RootCAs verifies
// HTTPS services (the internal CA of ADR-0138; nil uses the system roots).
type Prober struct {
	Scope   Scope
	RootCAs *x509.CertPool
	Now     func() time.Time
	// dialAllowLoopback lets tests probe 127.0.0.1.
	dialAllowLoopback bool
}

func (p *Prober) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p *Prober) dialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{
		Timeout: timeout,
		Control: func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil {
				return ErrOutOfScope
			}
			if p.dialAllowLoopback && ap.Addr().IsLoopback() {
				return nil
			}
			if !p.Scope.Allows(ap.Addr()) {
				return ErrOutOfScope
			}
			return nil
		},
	}
}

// Probe runs one probe of t.
func (p *Prober) Probe(ctx context.Context, t Target) ProbeResult {
	t = t.withDefaults()
	start := p.now()
	res := ProbeResult{At: start}
	if !p.dialAllowLoopback || !t.Addr.Addr().IsLoopback() {
		if !p.Scope.Allows(t.Addr.Addr()) {
			res.Error = ErrOutOfScope.Error()
			return res
		}
	}
	ctx, cancel := context.WithTimeout(ctx, t.Timeout)
	defer cancel()
	begin := time.Now()
	switch t.Kind {
	case ProbeTCP:
		c, err := p.dialer(t.Timeout).DialContext(ctx, "tcp", t.Addr.String())
		if err != nil {
			res.Error = shortErr(err)
			return res
		}
		_ = c.Close()
		res.OK = true
	default:
		status, err := p.httpProbe(ctx, t)
		res.Status = status
		if err != nil {
			res.Error = shortErr(err)
			return res
		}
		res.OK = status >= t.StatusMin && status <= t.StatusMax
		if !res.OK {
			res.Error = "beklenmeyen HTTP durumu " + strconv.Itoa(status)
		}
	}
	res.Latency = time.Since(begin)
	return res
}

func (p *Prober) httpProbe(ctx context.Context, t Target) (int, error) {
	scheme := "http"
	tlsConf := &tls.Config{RootCAs: p.RootCAs, MinVersion: tls.VersionTLS12}
	if t.Kind == ProbeHTTPS {
		scheme = "https"
		tlsConf.ServerName = t.Host
		if tlsConf.ServerName == "" {
			tlsConf.ServerName = t.Addr.Addr().String()
		}
	}
	tr := &http.Transport{
		Proxy:               nil,
		DialContext:         p.dialer(t.Timeout).DialContext,
		TLSClientConfig:     tlsConf,
		TLSHandshakeTimeout: t.Timeout,
		DisableKeepAlives:   true,
		DisableCompression:  true,
	}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+t.Addr.String()+t.Path, nil)
	if err != nil {
		return 0, err
	}
	if t.Host != "" {
		req.Host = t.Host
	}
	req.Header.Set("User-Agent", "OpenScale-Health/1")
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxProbeBody))
	return resp.StatusCode, nil
}

func shortErr(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "zaman aşımı"
	case errors.Is(err, ErrOutOfScope):
		return ErrOutOfScope.Error()
	case errors.Is(err, syscall.ECONNREFUSED):
		return "bağlantı reddedildi"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "zaman aşımı"
	}
	s := err.Error()
	if len(s) > 160 {
		s = s[:160]
	}
	return s
}

// State is a service's current state.
type State string

// Service states.
const (
	StateUnknown State = "unknown"
	StateUp      State = "up"
	StateDown    State = "down"
)

// ServiceStatus is what the panel shows for one target.
type ServiceStatus struct {
	Name      string      `json:"name"`
	State     State       `json:"state"`
	Since     time.Time   `json:"since"`
	Last      ProbeResult `json:"last"`
	Downtime  time.Duration
	fails     int
	successes int
	next      time.Time
}

// Monitor tracks targets with hysteresis. It is safe for concurrent use.
type Monitor struct {
	prober  *Prober
	mu      sync.Mutex
	targets []Target
	status  map[string]*ServiceStatus
}

// NewMonitor validates targets against the prober's scope.
func NewMonitor(p *Prober, targets []Target) (*Monitor, error) {
	if p == nil {
		return nil, errors.New("yoklayıcı gerekli")
	}
	if len(targets) > MaxTargets {
		return nil, fmt.Errorf("en fazla %d servis izlenebilir", MaxTargets)
	}
	seen := map[string]bool{}
	m := &Monitor{prober: p, status: map[string]*ServiceStatus{}}
	for _, t := range targets {
		if !(p.dialAllowLoopback && t.Addr.Addr().IsLoopback()) {
			if err := t.Validate(p.Scope); err != nil {
				return nil, err
			}
		}
		if seen[t.Name] {
			return nil, fmt.Errorf("servis adı iki kez kullanılmış: %q", t.Name)
		}
		seen[t.Name] = true
		t = t.withDefaults()
		m.targets = append(m.targets, t)
		m.status[t.Name] = &ServiceStatus{Name: t.Name, State: StateUnknown}
	}
	return m, nil
}

// Tick probes every target that is due at now and returns state changes.
func (m *Monitor) Tick(ctx context.Context, now time.Time) []Event {
	m.mu.Lock()
	var due []Target
	for _, t := range m.targets {
		if st := m.status[t.Name]; !now.Before(st.next) {
			st.next = now.Add(t.Interval)
			due = append(due, t)
		}
	}
	m.mu.Unlock()
	if len(due) == 0 {
		return nil
	}
	results := make([]ProbeResult, len(due))
	sem := make(chan struct{}, maxParallel)
	var wg sync.WaitGroup
	for i, t := range due {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = m.prober.Probe(ctx, t)
		}()
	}
	wg.Wait()
	m.mu.Lock()
	defer m.mu.Unlock()
	var events []Event
	for i, t := range due {
		if ev, ok := m.apply(t, results[i], now); ok {
			events = append(events, ev)
		}
	}
	return events
}

func (m *Monitor) apply(t Target, r ProbeResult, now time.Time) (Event, bool) {
	st := m.status[t.Name]
	st.Last = r
	if st.State == StateDown {
		st.Downtime += t.Interval
	}
	if r.OK {
		st.successes++
		st.fails = 0
		if st.State != StateUp && (st.State == StateUnknown || st.successes >= t.Rise) {
			was := st.State
			st.State, st.Since = StateUp, now
			if was == StateDown {
				return Event{Kind: KindServiceUp, Severity: SeverityInfo, Subject: t.Name, At: now,
					Title: t.Name + " yeniden yanıt veriyor"}, true
			}
		}
		return Event{}, false
	}
	st.fails++
	st.successes = 0
	if st.State != StateDown && st.fails >= t.Fall {
		st.State, st.Since = StateDown, now
		return Event{Kind: KindServiceDown, Severity: SeverityCritical, Subject: t.Name, At: now,
			Title:  t.Name + " yanıt vermiyor",
			Detail: fmt.Sprintf("Art arda %d yoklama başarısız: %s", st.fails, r.Error)}, true
	}
	return Event{}, false
}

// Status returns every target's status in configuration order.
func (m *Monitor) Status() []ServiceStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]ServiceStatus, 0, len(m.targets))
	for _, t := range m.targets {
		out = append(out, *m.status[t.Name])
	}
	return out
}

// Downtime returns each target's accumulated downtime (for the weekly
// report) and resets it when reset is true.
func (m *Monitor) Downtime(reset bool) map[string]time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]time.Duration{}
	for name, st := range m.status {
		if st.Downtime > 0 {
			out[name] = st.Downtime
		}
		if reset {
			st.Downtime = 0
		}
	}
	return out
}

// Run ticks every step until ctx ends, passing events to emit.
func (m *Monitor) Run(ctx context.Context, step time.Duration, emit func(Event)) {
	if step <= 0 {
		step = 5 * time.Second
	}
	t := time.NewTicker(step)
	defer t.Stop()
	for {
		for _, ev := range m.Tick(ctx, m.prober.now()) {
			emit(ev)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
