package mqttpub

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/openscale/openscale/internal/securefile"
)

const (
	// ConfigFile is the default configuration file name.
	ConfigFile = "mqtt.json"
	// DefaultPrefix starts every topic.
	DefaultPrefix = "openscale"
	// DefaultPort is MQTT's plain TCP port.
	DefaultPort = 1883

	configSchema  = 1
	maxConfigFile = 16 << 10
	maxBroker     = 255
	maxPrefix     = 100
	maxUser       = 128
	maxPassword   = 256
	maxKinds      = 64
	maxKindLen    = 64

	// Timeout bounds dialing, the handshake and one write.
	Timeout = 5 * time.Second
	// KeepAlive is the keep alive announced to the broker.
	KeepAlive = 60 * time.Second
)

// Errors.
var (
	ErrDestination = errors.New("MQTT aracısı yalnızca loopback veya özel ağ adresinde olabilir (127/8, 10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7)")
	ErrConfig      = errors.New("MQTT yapılandırması geçersiz")
	ErrNotRunning  = errors.New("MQTT bağlantısı yok")
)

// Config is the MQTT configuration file. The password is stored in the
// owner-only file like the webhook secret.
type Config struct {
	Schema int `json:"schema"`
	// Broker is host:port of the owner's broker.
	Broker   string `json:"broker"`
	Prefix   string `json:"prefix"`
	ClientID string `json:"client_id"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	// Events lists event kinds or categories to publish; empty: all.
	Events []string `json:"events,omitempty"`
}

// validTopicPart: no wildcards, separators or control characters.
func validTopicPart(s string, maxLen int, slash bool) bool {
	if s == "" || len(s) > maxLen || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		switch {
		case r == '+' || r == '#' || r == 0 || r < 0x20 || r == 0x7f:
			return false
		case r == '/' && !slash:
			return false
		}
	}
	return !strings.HasPrefix(s, "/") && !strings.HasSuffix(s, "/") && !strings.HasPrefix(s, "$")
}

// Validate checks the configuration.
func (c *Config) Validate() error {
	if c.Schema != configSchema {
		return fmt.Errorf("%w: şema %d", ErrConfig, c.Schema)
	}
	if len(c.Broker) == 0 || len(c.Broker) > maxBroker {
		return fmt.Errorf("%w: aracı adresi ana-makine:port olmalı", ErrConfig)
	}
	host, port, err := net.SplitHostPort(c.Broker)
	if err != nil || host == "" {
		return fmt.Errorf("%w: aracı adresi ana-makine:port olmalı", ErrConfig)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("%w: port 1-65535 olmalı", ErrConfig)
	}
	if !validTopicPart(c.Prefix, maxPrefix, true) {
		return fmt.Errorf("%w: konu öneki boş olamaz, '+', '#', '$' ve denetim karakteri içeremez", ErrConfig)
	}
	if !validTopicPart(c.ClientID, 23, false) {
		return fmt.Errorf("%w: istemci kimliği 1-23 karakter olmalı", ErrConfig)
	}
	if len(c.Username) > maxUser || len(c.Password) > maxPassword || (c.Password != "" && c.Username == "") {
		return fmt.Errorf("%w: kullanıcı adı en çok %d, parola en çok %d karakter; parola için kullanıcı adı gerekir", ErrConfig, maxUser, maxPassword)
	}
	if len(c.Events) > maxKinds {
		return fmt.Errorf("%w: en çok %d olay türü", ErrConfig, maxKinds)
	}
	for _, k := range c.Events {
		if k == "" || len(k) > maxKindLen {
			return fmt.Errorf("%w: olay türü %q", ErrConfig, k)
		}
	}
	return nil
}

// NewConfig makes a configuration with a random client id.
func NewConfig(broker, prefix, user, password string, events []string, rnd io.Reader) (*Config, error) {
	if rnd == nil {
		rnd = rand.Reader
	}
	if prefix == "" {
		prefix = DefaultPrefix
	}
	if _, _, err := net.SplitHostPort(broker); err != nil && broker != "" {
		broker = net.JoinHostPort(broker, strconv.Itoa(DefaultPort))
	}
	id := make([]byte, 6)
	if _, err := io.ReadFull(rnd, id); err != nil {
		return nil, err
	}
	c := &Config{Schema: configSchema, Broker: broker, Prefix: prefix, ClientID: "openscale-" + hex.EncodeToString(id), Username: user, Password: password, Events: events}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Save writes the configuration to an owner-only file.
func Save(path string, c *Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return securefile.Replace(path, data)
}

// Load reads and checks a configuration file.
func Load(path string) (*Config, error) {
	data, err := securefile.ReadPrivate(path, maxConfigFile)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConfig, err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// allowed is the destination rule shared with the webhook (ADR-0108).
func allowed(a netip.Addr) bool {
	a = a.Unmap()
	if a.IsLoopback() || a.IsPrivate() {
		return true
	}
	return netip.MustParsePrefix("100.64.0.0/10").Contains(a)
}

// Dialer opens the TCP connection; tests replace Control for loopback.
func dialer() *net.Dialer {
	return &net.Dialer{
		Timeout: Timeout,
		Control: func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil || !allowed(ap.Addr()) {
				return ErrDestination
			}
			return nil
		},
	}
}

// Client is one connection to the broker.
type Client struct {
	mu   sync.Mutex
	conn net.Conn
	r    *bufio.Reader
	now  func() time.Time
	last time.Time
}

// Topics are the topic names of a device.
type Topics struct {
	Availability string
	Status       string
	Event        string
}

// TopicsFor returns the topics of device under the configured prefix.
func TopicsFor(c *Config, device string) Topics {
	d := sanitizeDevice(device)
	base := c.Prefix + "/" + d
	return Topics{Availability: base + "/availability", Status: base + "/status", Event: base + "/event"}
}

func sanitizeDevice(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + 32)
		default:
			b.WriteByte('_')
		}
		if b.Len() >= 63 {
			break
		}
	}
	if b.Len() == 0 {
		return "cihaz"
	}
	return b.String()
}

// Connect dials the broker and sends CONNECT with a last will that marks
// the device offline.
func Connect(ctx context.Context, c *Config, device string, now func() time.Time) (*Client, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	conn, err := dialer().DialContext(ctx, "tcp", c.Broker)
	if err != nil {
		if errors.Is(err, ErrDestination) {
			return nil, ErrDestination
		}
		return nil, fmt.Errorf("MQTT aracısına bağlanılamadı: %w", err)
	}
	t := TopicsFor(c, device)
	pkt, err := encodeConnect(connectOptions{
		ClientID: c.ClientID, Username: c.Username, Password: c.Password,
		KeepAlive: uint16(KeepAlive / time.Second), WillTopic: t.Availability, WillMessage: []byte("offline"), WillRetain: true,
	})
	if err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(now().Add(Timeout))
	if _, err := conn.Write(pkt); err != nil {
		conn.Close()
		return nil, fmt.Errorf("MQTT bağlantısı kurulamadı: %w", err)
	}
	r := bufio.NewReader(conn)
	typ, _, body, err := readPacket(r, maxIncoming)
	if err != nil || typ != typeConnack || len(body) != 2 {
		conn.Close()
		if err == nil {
			err = errMalformed
		}
		return nil, fmt.Errorf("MQTT aracısı yanıt vermedi: %w", err)
	}
	if err := connackError(body[1]); err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	cl := &Client{conn: conn, r: r, now: now, last: now()}
	go cl.drain()
	return cl, nil
}

// drain reads and drops what the broker sends (PINGRESP); a read error
// closes the connection so the next publish fails and reconnects.
func (c *Client) drain() {
	for {
		_, _, _, err := readPacket(c.r, maxIncoming)
		if err != nil {
			c.mu.Lock()
			if c.conn != nil {
				c.conn.Close()
			}
			c.mu.Unlock()
			return
		}
	}
}

func (c *Client) write(pkt []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return ErrNotRunning
	}
	_ = c.conn.SetWriteDeadline(c.now().Add(Timeout))
	if _, err := c.conn.Write(pkt); err != nil {
		c.conn.Close()
		c.conn = nil
		return fmt.Errorf("MQTT yayını gönderilemedi: %w", err)
	}
	c.last = c.now()
	return nil
}

// Publish sends one message at QoS 0.
func (c *Client) Publish(topic string, payload []byte, retain bool) error {
	if !validTopicPart(topic, 512, true) {
		return fmt.Errorf("%w: konu %q", ErrConfig, topic)
	}
	pkt, err := encodePublish(topic, payload, retain)
	if err != nil {
		return err
	}
	return c.write(pkt)
}

// Ping sends PINGREQ when nothing was sent for half the keep alive.
func (c *Client) Ping() error {
	c.mu.Lock()
	idle := c.now().Sub(c.last)
	c.mu.Unlock()
	if idle < KeepAlive/2 {
		return nil
	}
	return c.write([]byte{typePingreq << 4, 0})
}

// Close sends DISCONNECT and closes. The broker then does not publish
// the last will, so callers publish "offline" before closing.
func (c *Client) Close() error {
	_ = c.write([]byte{typeDisconnect << 4, 0})
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn = nil
	return err
}

// Wants reports whether an event of kind and category is published.
func (c *Config) Wants(kind, category string) bool {
	if len(c.Events) == 0 {
		return true
	}
	for _, k := range c.Events {
		if k == kind || k == category {
			return true
		}
	}
	return false
}
