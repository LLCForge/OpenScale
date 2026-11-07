package notify

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// HTTP delivery limits.
const (
	httpTimeout = 10 * time.Second
	maxReply    = 4 << 10
	maxURLLen   = 512
	maxToken    = 512
	userAgent   = "OpenScale-Notify/1"
)

// Destination errors.
var (
	// ErrDestination is returned for a URL the policy refuses.
	ErrDestination = errors.New("bildirim adresi kabul edilmedi: https olmalı (düz http yalnızca bu bilgisayar, özel ağ veya tünel adresinde), kullanıcı bilgisi ve parça içermemeli")
	// ErrDialRefused is returned when the dialed address is link-local,
	// multicast or unspecified (cloud metadata among them).
	ErrDialRefused = errors.New("bildirim adresi yerel bağlantı, çok noktaya yayın veya belirsiz bir adrese çözüldü")
)

// privateNets are the destinations plain HTTP and SMTP without TLS may
// reach: this computer, private networks and the tunnel's ranges.
var privateNets = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
}

// IsPrivate reports whether a is loopback, private or a tunnel address.
func IsPrivate(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range privateNets {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// dialable refuses addresses no notification should ever reach.
func dialable(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsValid() && !a.IsUnspecified() && !a.IsMulticast() && !a.IsLinkLocalUnicast() && !a.IsLinkLocalMulticast() && !a.IsInterfaceLocalMulticast()
}

// ParseDestination checks an owner-configured channel URL: https, or plain
// http to a literal private address or "localhost". Names under https are
// checked again on every connection.
func ParseDestination(raw string) (*url.URL, error) {
	if len(raw) == 0 || len(raw) > maxURLLen {
		return nil, ErrDestination
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return nil, ErrDestination
	}
	host := u.Hostname()
	switch u.Scheme {
	case "https":
	case "http":
		if host == "localhost" {
			break
		}
		a, err := netip.ParseAddr(host)
		if err != nil || !IsPrivate(a) {
			return nil, ErrDestination
		}
	default:
		return nil, ErrDestination
	}
	if a, err := netip.ParseAddr(host); err == nil && !dialable(a) {
		return nil, ErrDestination
	}
	return u, nil
}

// guardedDialer refuses link-local, multicast and unspecified addresses
// on the address actually dialed, so a name that later resolves there
// (DNS rebinding) is refused too. When privateOnly is set, only private
// addresses pass (plain HTTP and SMTP without TLS).
func guardedDialer(privateOnly bool) *net.Dialer {
	return &net.Dialer{
		Timeout: httpTimeout,
		Control: func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil {
				return ErrDialRefused
			}
			a := ap.Addr()
			if !dialable(a) || (privateOnly && !IsPrivate(a)) {
				return ErrDialRefused
			}
			return nil
		},
	}
}

// newHTTPClient returns a client without proxy, redirects or cookies.
func newHTTPClient(u *url.URL) *http.Client {
	privateOnly := u.Scheme == "http"
	return &http.Client{
		Timeout: httpTimeout,
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           guardedDialer(privateOnly).DialContext,
			TLSHandshakeTimeout:   httpTimeout,
			ResponseHeaderTimeout: httpTimeout,
			MaxIdleConns:          2,
			IdleConnTimeout:       30 * time.Second,
			DisableCompression:    true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func doRequest(ctx context.Context, c *http.Client, method string, u *url.URL, hdr http.Header, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("bildirim gönderilemedi: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxReply))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("bildirim sunucusu %d döndürdü", resp.StatusCode)
	}
	return nil
}

func checkToken(tok string) error {
	if len(tok) > maxToken || strings.ContainsAny(tok, "\r\n") {
		return errors.New("erişim belirteci geçersiz")
	}
	return nil
}

// Ntfy publishes to an ntfy topic URL (the owner's own server or a hosted
// one the owner chose).
type Ntfy struct {
	Label string
	URL   *url.URL
	// Token is an optional access token (sent as a bearer token).
	Token  string
	client *http.Client
}

// NewNtfy checks the topic URL and token.
func NewNtfy(label, topicURL, token string) (*Ntfy, error) {
	u, err := ParseDestination(topicURL)
	if err != nil {
		return nil, err
	}
	if strings.Trim(u.Path, "/") == "" {
		return nil, errors.New("ntfy adresi bir konu içermeli (https://sunucu/konu)")
	}
	if err := checkToken(token); err != nil {
		return nil, err
	}
	return &Ntfy{Label: label, URL: u, Token: token, client: newHTTPClient(u)}, nil
}

// Name implements Channel.
func (n *Ntfy) Name() string { return n.Label }

// ntfyPriority maps to ntfy's 1-5 scale.
func ntfyPriority(p Priority) string {
	switch p {
	case PriorityLow:
		return "2"
	case PriorityHigh:
		return "4"
	case PriorityUrgent:
		return "5"
	default:
		return "3"
	}
}

// Send implements Channel.
func (n *Ntfy) Send(ctx context.Context, m Message) error {
	m = m.normalized()
	hdr := http.Header{}
	hdr.Set("Content-Type", "text/plain; charset=utf-8")
	if m.Title != "" {
		// ntfy reads RFC 2047 encoded titles, so non-ASCII text survives.
		hdr.Set("Title", encodeHeaderWord(m.Title))
	}
	hdr.Set("Priority", ntfyPriority(m.Priority))
	if m.Kind != "" {
		hdr.Set("Tags", cleanLine(m.Kind))
	}
	if n.Token != "" {
		hdr.Set("Authorization", "Bearer "+n.Token)
	}
	body := m.Body
	if body == "" {
		body = m.Title
	}
	return doRequest(ctx, n.client, http.MethodPost, n.URL, hdr, []byte(body))
}

// Gotify posts to a Gotify server's message endpoint with an application
// token.
type Gotify struct {
	Label  string
	URL    *url.URL
	Token  string
	client *http.Client
}

// NewGotify checks the server URL and application token.
func NewGotify(label, serverURL, token string) (*Gotify, error) {
	u, err := ParseDestination(serverURL)
	if err != nil {
		return nil, err
	}
	if token == "" {
		return nil, errors.New("Gotify uygulama belirteci gerekli")
	}
	if err := checkToken(token); err != nil {
		return nil, err
	}
	msg := *u
	msg.Path = strings.TrimSuffix(u.Path, "/") + "/message"
	msg.RawQuery = ""
	return &Gotify{Label: label, URL: &msg, Token: token, client: newHTTPClient(u)}, nil
}

// Name implements Channel.
func (g *Gotify) Name() string { return g.Label }

// gotifyPriority maps to Gotify's 0-10 scale.
func gotifyPriority(p Priority) int {
	switch p {
	case PriorityLow:
		return 2
	case PriorityHigh:
		return 7
	case PriorityUrgent:
		return 9
	default:
		return 5
	}
}

// Send implements Channel.
func (g *Gotify) Send(ctx context.Context, m Message) error {
	m = m.normalized()
	body, err := json.Marshal(struct {
		Title    string `json:"title"`
		Message  string `json:"message"`
		Priority int    `json:"priority"`
	}{m.Title, firstNonEmpty(m.Body, m.Title), gotifyPriority(m.Priority)})
	if err != nil {
		return err
	}
	hdr := http.Header{}
	hdr.Set("Content-Type", "application/json")
	hdr.Set("X-Gotify-Key", g.Token)
	return doRequest(ctx, g.client, http.MethodPost, g.URL, hdr, body)
}

// Matrix sends an m.text message to a room with an access token.
type Matrix struct {
	Label  string
	Server *url.URL
	RoomID string
	Token  string
	client *http.Client
}

// NewMatrix checks the homeserver URL, room ID and access token.
func NewMatrix(label, homeserver, roomID, token string) (*Matrix, error) {
	u, err := ParseDestination(homeserver)
	if err != nil {
		return nil, err
	}
	if !validRoomID(roomID) {
		return nil, errors.New("Matrix oda kimliği !kimlik:sunucu biçiminde olmalı")
	}
	if token == "" {
		return nil, errors.New("Matrix erişim belirteci gerekli")
	}
	if err := checkToken(token); err != nil {
		return nil, err
	}
	return &Matrix{Label: label, Server: u, RoomID: roomID, Token: token, client: newHTTPClient(u)}, nil
}

func validRoomID(s string) bool {
	if len(s) < 4 || len(s) > 255 || s[0] != '!' || !strings.Contains(s, ":") {
		return false
	}
	for _, r := range s {
		if r <= 0x20 || r == 0x7f || r == '/' || r == '?' || r == '#' {
			return false
		}
	}
	return true
}

// Name implements Channel.
func (x *Matrix) Name() string { return x.Label }

// Send implements Channel.
func (x *Matrix) Send(ctx context.Context, m Message) error {
	m = m.normalized()
	var txn [12]byte
	if _, err := rand.Read(txn[:]); err != nil {
		return err
	}
	u := *x.Server
	u.RawQuery = ""
	u.Path = strings.TrimSuffix(x.Server.Path, "/") + "/_matrix/client/v3/rooms/" + x.RoomID + "/send/m.room.message/os" + hex.EncodeToString(txn[:])
	u.RawPath = strings.TrimSuffix(x.Server.EscapedPath(), "/") + "/_matrix/client/v3/rooms/" + url.PathEscape(x.RoomID) + "/send/m.room.message/os" + hex.EncodeToString(txn[:])
	text := m.Title
	if m.Body != "" {
		text = m.Title + "\n" + m.Body
	}
	body, err := json.Marshal(struct {
		MsgType string `json:"msgtype"`
		Body    string `json:"body"`
	}{"m.text", text})
	if err != nil {
		return err
	}
	hdr := http.Header{}
	hdr.Set("Content-Type", "application/json")
	hdr.Set("Authorization", "Bearer "+x.Token)
	return doRequest(ctx, x.client, http.MethodPut, &u, hdr, body)
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
