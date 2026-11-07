// Package webhook forwards selected local events to an HTTP endpoint on
// the owner's own network (F-189, ADR-0108). It is off by default: the
// owner writes a configuration with "openscale webhook init" and runs the
// forwarder with "openscale webhook run", which reads the documented local
// API's event stream.
//
// Destinations are limited to loopback and private networks, checked on
// the address actually dialed, so a name that later resolves to a public
// address (DNS rebinding) is refused too. Every delivery is signed with
// HMAC-SHA256 over the timestamp and the body.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/openscale/openscale/internal/securefile"
)

const (
	// ConfigFile is the default configuration file name.
	ConfigFile = "webhook.json"

	configSchema  = 1
	maxConfigFile = 16 << 10
	maxURL        = 512
	maxKinds      = 64
	maxKindLen    = 64
	secretBytes   = 32

	// QueueSize bounds the events waiting for delivery.
	QueueSize = 256
	// Attempts is the number of tries per event.
	Attempts = 3
	// Timeout bounds one delivery.
	Timeout = 5 * time.Second
	// Tolerance is how far a signature's time may be from the receiver's.
	Tolerance = 5 * time.Minute

	maxResponse = 4 << 10
	userAgent   = "OpenScale-Webhook/1"

	// Header names of a delivery.
	HeaderSignature = "X-OpenScale-Signature"
	HeaderEvent     = "X-OpenScale-Event"
	HeaderDelivery  = "X-OpenScale-Delivery"
)

// Config is the webhook configuration file.
type Config struct {
	Schema int    `json:"schema"`
	URL    string `json:"url"`
	// Secret is the hex HMAC key shared with the receiver.
	Secret string `json:"secret"`
	// Events lists event kinds or categories to send; empty sends all.
	Events []string `json:"events,omitempty"`
}

// Event is what is delivered: the event stream's fields (ADR-0105), which
// never hold addresses or endpoints.
type Event struct {
	Seq      uint64    `json:"seq"`
	At       time.Time `json:"at"`
	Kind     string    `json:"kind"`
	Category string    `json:"category"`
	Severity string    `json:"severity"`
	Peer     string    `json:"peer,omitempty"`
	Message  string    `json:"message"`
}

// Payload is the JSON body of one delivery.
type Payload struct {
	Schema   int    `json:"schema"`
	Delivery string `json:"delivery"`
	// Device is the name of the device that saw the event.
	Device string `json:"device,omitempty"`
	Event  Event  `json:"event"`
}

// Errors of the configuration.
var (
	ErrDestination = errors.New("webhook hedefi yalnızca bu bilgisayar (loopback) veya özel ağdaki bir adres olabilir (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7)")
	ErrDisabled    = errors.New("webhook yapılandırılmamış (openscale webhook init)")
)

// privateNets are the destinations a webhook may reach.
var privateNets = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
}

// AllowedAddr reports whether a may receive webhooks. Link-local (the
// cloud metadata address among them), multicast, unspecified and public
// addresses are refused.
func AllowedAddr(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || a.Zone() != "" || a.IsUnspecified() || a.IsMulticast() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() {
		return false
	}
	for _, p := range privateNets {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// ParseURL checks a destination URL. A literal address must be allowed;
// a name is checked again on every connection.
func ParseURL(raw string) (*url.URL, error) {
	if raw == "" || len(raw) > maxURL || strings.ContainsFunc(raw, func(r rune) bool { return r < 0x21 || r == 0x7f }) {
		return nil, errors.New("webhook adresi geçersiz")
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Fragment != "" {
		return nil, errors.New("webhook adresi http:// veya https:// ile başlamalı, kullanıcı bilgisi ve # içermemeli")
	}
	host := u.Hostname()
	if a, err := netip.ParseAddr(host); err == nil {
		if !AllowedAddr(a) {
			return nil, ErrDestination
		}
	} else if !validHostName(host) {
		return nil, errors.New("webhook sunucu adı geçersiz")
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return nil, errors.New("webhook portu geçersiz")
		}
	}
	return u, nil
}

func validHostName(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(h, "."), ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func validKind(k string) bool {
	if k == "" || len(k) > maxKindLen {
		return false
	}
	for _, c := range k {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

// Validate checks a loaded or new configuration.
func (c Config) Validate() error {
	if c.Schema != configSchema {
		return errors.New("webhook yapılandırma sürümü bilinmiyor")
	}
	if _, err := ParseURL(c.URL); err != nil {
		return err
	}
	key, err := hex.DecodeString(c.Secret)
	if err != nil || len(key) < 16 || len(key) > 64 {
		return errors.New("webhook sırrı bozuk")
	}
	if len(c.Events) > maxKinds {
		return fmt.Errorf("en çok %d olay türü seçilebilir", maxKinds)
	}
	for _, k := range c.Events {
		if !validKind(k) {
			return fmt.Errorf("olay türü geçersiz: %q", k)
		}
	}
	return nil
}

// NewConfig returns a configuration with a fresh random secret.
func NewConfig(rawURL string, events []string, random io.Reader) (Config, error) {
	if random == nil {
		random = rand.Reader
	}
	key := make([]byte, secretBytes)
	if _, err := io.ReadFull(random, key); err != nil {
		return Config{}, err
	}
	c := Config{Schema: configSchema, URL: rawURL, Secret: hex.EncodeToString(key), Events: events}
	return c, c.Validate()
}

// Load reads and checks the configuration at path.
func Load(path string) (Config, error) {
	data, err := securefile.ReadPrivate(path, maxConfigFile)
	if errors.Is(err, fs.ErrNotExist) {
		return Config{}, ErrDisabled
	}
	if err != nil {
		return Config{}, err
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return Config{}, errors.New("webhook yapılandırması bozuk")
	}
	return c, c.Validate()
}

// Save writes the configuration (0600) atomically.
func Save(path string, c Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return securefile.Replace(path, data)
}

// Wants reports whether the configuration sends ev.
func (c Config) Wants(ev Event) bool {
	return len(c.Events) == 0 || slices.Contains(c.Events, ev.Kind) || slices.Contains(c.Events, ev.Category)
}

// Sign returns the signature header value for body at t.
func Sign(secret []byte, t time.Time, body []byte) string {
	ts := strconv.FormatInt(t.Unix(), 10)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(ts))
	mac.Write([]byte{'.'})
	mac.Write(body)
	return "t=" + ts + ",v1=" + hex.EncodeToString(mac.Sum(nil))
}

// Verify checks a signature header for body against secret, accepting a
// timestamp within tolerance of now.
func Verify(secret []byte, header string, body []byte, now time.Time, tolerance time.Duration) error {
	var ts, sig string
	for _, part := range strings.Split(header, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		switch k {
		case "t":
			ts = v
		case "v1":
			sig = v
		}
	}
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || sig == "" {
		return errors.New("webhook: malformed signature")
	}
	t := time.Unix(sec, 0)
	if d := now.Sub(t); d > tolerance || d < -tolerance {
		return errors.New("webhook: signature too old or from the future")
	}
	want := Sign(secret, t, body)
	_, wantSig, _ := strings.Cut(want, ",v1=")
	got, err1 := hex.DecodeString(sig)
	exp, err2 := hex.DecodeString(wantSig)
	if err1 != nil || err2 != nil || !hmac.Equal(got, exp) {
		return errors.New("webhook: signature mismatch")
	}
	return nil
}

// Sender delivers events to one destination.
type Sender struct {
	cfg    Config
	url    *url.URL
	secret []byte
	device string
	client *http.Client
	logger *slog.Logger
	now    func() time.Time
	random io.Reader
	// backoff is the wait before attempt n (1-based, n >= 2).
	backoff func(n int) time.Duration

	mu      sync.Mutex
	queue   []Event
	wake    chan struct{}
	dropped uint64
}

// Options configures a Sender.
type Options struct {
	// Device is the name of this device, put into every payload.
	Device string
	Logger *slog.Logger
	Now    func() time.Time
	Random io.Reader
	// AllowAddr overrides AllowedAddr (tests only).
	AllowAddr func(netip.Addr) bool
	// Backoff overrides the retry waits (tests only).
	Backoff func(n int) time.Duration
}

// NewSender checks cfg and prepares the HTTP client: no proxy, no
// redirects, the destination address checked on every connection.
func NewSender(cfg Config, opts Options) (*Sender, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	u, _ := ParseURL(cfg.URL)
	secret, _ := hex.DecodeString(cfg.Secret)
	allow := opts.AllowAddr
	if allow == nil {
		allow = AllowedAddr
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Random == nil {
		opts.Random = rand.Reader
	}
	if opts.Backoff == nil {
		opts.Backoff = func(n int) time.Duration { return time.Duration(n*n) * time.Second }
	}
	dialer := &net.Dialer{
		Timeout: Timeout,
		// SECURITY FIX: CWE-918 The address is checked after resolution,
		// on the socket actually connected, so DNS cannot redirect a
		// delivery to a public or metadata address.
		Control: func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil || !allow(ap.Addr()) {
				return ErrDestination
			}
			return nil
		},
	}
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   Timeout,
		ResponseHeaderTimeout: Timeout,
		MaxIdleConns:          2,
		IdleConnTimeout:       30 * time.Second,
		ForceAttemptHTTP2:     false,
	}
	return &Sender{
		cfg: cfg, url: u, secret: secret, device: opts.Device, logger: opts.Logger, now: opts.Now, random: opts.Random, backoff: opts.Backoff,
		client: &http.Client{Transport: tr, Timeout: Timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		wake: make(chan struct{}, 1),
	}, nil
}

// Enqueue adds an event if the configuration wants it. When the queue is
// full the oldest event is dropped and counted.
func (s *Sender) Enqueue(ev Event) {
	if !s.cfg.Wants(ev) {
		return
	}
	s.mu.Lock()
	if len(s.queue) >= QueueSize {
		s.queue = s.queue[1:]
		s.dropped++
	}
	s.queue = append(s.queue, ev)
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// Dropped returns how many events were dropped because the queue was full.
func (s *Sender) Dropped() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dropped
}

func (s *Sender) next() (Event, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.queue) == 0 {
		return Event{}, false
	}
	ev := s.queue[0]
	s.queue = s.queue[1:]
	return ev, true
}

// Run delivers queued events until ctx ends.
func (s *Sender) Run(ctx context.Context) {
	for {
		for {
			ev, ok := s.next()
			if !ok {
				break
			}
			if err := s.Deliver(ctx, ev); err != nil && ctx.Err() == nil {
				s.logger.Warn("webhook delivery failed", "kind", ev.Kind, "seq", ev.Seq, "error", err.Error())
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-s.wake:
		}
	}
}

// Deliver sends one event, retrying up to Attempts times.
func (s *Sender) Deliver(ctx context.Context, ev Event) error {
	var id [12]byte
	if _, err := io.ReadFull(s.random, id[:]); err != nil {
		return err
	}
	body, err := json.Marshal(Payload{Schema: 1, Delivery: hex.EncodeToString(id[:]), Device: s.device, Event: ev})
	if err != nil {
		return err
	}
	var last error
	for attempt := 1; attempt <= Attempts; attempt++ {
		if attempt > 1 {
			t := time.NewTimer(s.backoff(attempt))
			select {
			case <-ctx.Done():
				t.Stop()
				return ctx.Err()
			case <-t.C:
			}
		}
		last = s.post(ctx, hex.EncodeToString(id[:]), ev.Kind, body)
		if last == nil {
			return nil
		}
		if errors.Is(last, ErrDestination) {
			return last
		}
	}
	return last
}

func (s *Sender) post(ctx context.Context, delivery, kind string, body []byte) error {
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set(HeaderEvent, kind)
	req.Header.Set(HeaderDelivery, delivery)
	req.Header.Set(HeaderSignature, Sign(s.secret, s.now(), body))
	resp, err := s.client.Do(req)
	if err != nil {
		if errors.Is(err, ErrDestination) || strings.Contains(err.Error(), ErrDestination.Error()) {
			return ErrDestination
		}
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponse))
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("hedef %d döndü", resp.StatusCode)
	}
	return nil
}
