package notify

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/netip"
	"net/smtp"
	"strings"
	"time"
)

const (
	smtpTimeout   = 20 * time.Second
	maxRecipients = 10
)

// SMTP sends e-mail through the owner's own mail server. Without TLS it
// only talks to a private or tunnel address; elsewhere STARTTLS (or
// implicit TLS on port 465) is required, and credentials are only ever
// sent over TLS.
type SMTP struct {
	Label string
	// Addr is host:port of the submission server.
	Addr string
	From string
	To   []string
	// Username and Password are optional; the caller reads the password
	// from the operating system's credential store or the protected
	// configuration and never logs it.
	Username string
	Password string
	// ServerName overrides the TLS server name (defaults to Addr's host).
	ServerName string
	// RootCAs verifies the server (nil uses the system roots).
	TLSConfig *tls.Config

	host string
	port string
	// dial is replaced in tests.
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// NewSMTP checks the server address and the addresses.
func NewSMTP(label, addr, from string, to []string) (*SMTP, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host == "" || port == "" {
		return nil, errors.New("SMTP sunucusu sunucu:port biçiminde olmalı")
	}
	if a, err := netip.ParseAddr(host); err == nil && !dialable(a) {
		return nil, ErrDestination
	}
	if _, err := mail.ParseAddress(from); err != nil || strings.ContainsAny(from, "\r\n") {
		return nil, errors.New("gönderen e-posta adresi geçersiz")
	}
	if len(to) == 0 || len(to) > maxRecipients {
		return nil, fmt.Errorf("1 ile %d arasında alıcı gerekli", maxRecipients)
	}
	for _, r := range to {
		if _, err := mail.ParseAddress(r); err != nil || strings.ContainsAny(r, "\r\n") {
			return nil, fmt.Errorf("alıcı adresi geçersiz: %q", r)
		}
	}
	return &SMTP{Label: label, Addr: addr, From: from, To: append([]string(nil), to...), host: host, port: port}, nil
}

// Name implements Channel.
func (s *SMTP) Name() string { return s.Label }

func bareAddress(a string) string {
	p, err := mail.ParseAddress(a)
	if err != nil {
		return a
	}
	return p.Address
}

// Send implements Channel.
func (s *SMTP) Send(ctx context.Context, m Message) error {
	m = m.normalized()
	if !strings.HasPrefix(m.Title, "[OpenScale]") {
		m.Title = "[OpenScale] " + m.Title
	}
	msg, err := BuildMail(s.From, s.To, m.Title, firstNonEmpty(m.Body, m.Title), m.HTML, m.At)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, smtpTimeout)
	defer cancel()
	dial := s.dial
	implicitTLS := s.port == "465"
	if dial == nil {
		dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return guardedDialer(false).DialContext(ctx, network, addr)
		}
	}
	conn, err := dial(ctx, "tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("SMTP sunucusuna bağlanılamadı: %w", err)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	_ = conn.SetDeadline(time.Now().Add(smtpTimeout))
	remotePrivate := false
	if ap, err := netip.ParseAddrPort(conn.RemoteAddr().String()); err == nil {
		remotePrivate = IsPrivate(ap.Addr())
	}
	tlsConf := s.tlsConfig()
	if implicitTLS {
		tc := tls.Client(conn, tlsConf)
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return fmt.Errorf("SMTP TLS el sıkışması başarısız: %w", err)
		}
		conn = tc
	}
	c, err := smtp.NewClient(conn, s.host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("SMTP oturumu açılamadı: %w", err)
	}
	defer c.Close()
	secure := implicitTLS
	if !secure {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(tlsConf); err != nil {
				return fmt.Errorf("STARTTLS başarısız: %w", err)
			}
			secure = true
		}
	}
	if !secure && !remotePrivate {
		return errors.New("SMTP sunucusu TLS sunmuyor; şifresiz e-posta yalnızca özel ağ veya tünel adresine gönderilir")
	}
	if s.Username != "" {
		if !secure {
			return errors.New("SMTP kimlik bilgisi yalnızca TLS üzerinden gönderilir")
		}
		if err := c.Auth(smtp.PlainAuth("", s.Username, s.Password, s.host)); err != nil {
			return fmt.Errorf("SMTP kimlik doğrulaması başarısız: %w", err)
		}
	}
	if err := c.Mail(bareAddress(s.From)); err != nil {
		return fmt.Errorf("SMTP gönderen reddedildi: %w", err)
	}
	for _, r := range s.To {
		if err := c.Rcpt(bareAddress(r)); err != nil {
			return fmt.Errorf("SMTP alıcı reddedildi: %w", err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("SMTP veri aşaması başarısız: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		_ = w.Close()
		return fmt.Errorf("e-posta yazılamadı: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("SMTP sunucusu e-postayı kabul etmedi: %w", err)
	}
	return c.Quit()
}

func (s *SMTP) tlsConfig() *tls.Config {
	var c *tls.Config
	if s.TLSConfig != nil {
		c = s.TLSConfig.Clone()
	} else {
		c = &tls.Config{}
	}
	if c.ServerName == "" {
		c.ServerName = firstNonEmpty(s.ServerName, s.host)
	}
	if c.MinVersion < tls.VersionTLS12 {
		c.MinVersion = tls.VersionTLS12
	}
	return c
}

// encodeHeaderWord encodes non-ASCII header text (RFC 2047).
func encodeHeaderWord(s string) string {
	return mime.QEncoding.Encode("utf-8", cleanLine(s))
}

// BuildMail returns an RFC 5322 message: plain text, or multipart/
// alternative with an HTML part when html is not empty. Header values are
// stripped of line breaks, so no field can inject another header.
func BuildMail(from string, to []string, subject, text, html string, at time.Time) ([]byte, error) {
	if at.IsZero() {
		at = time.Now()
	}
	var b bytes.Buffer
	hdr := func(k, v string) { fmt.Fprintf(&b, "%s: %s\r\n", k, v) }
	hdr("From", cleanLine(from))
	cleanTo := make([]string, 0, len(to))
	for _, r := range to {
		cleanTo = append(cleanTo, cleanLine(r))
	}
	hdr("To", strings.Join(cleanTo, ", "))
	hdr("Subject", encodeHeaderWord(subject))
	hdr("Date", at.Format(time.RFC1123Z))
	var id [12]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	domain := "openscale.invalid"
	if i := strings.LastIndexByte(bareAddress(from), '@'); i >= 0 {
		domain = cleanLine(bareAddress(from)[i+1:])
	}
	hdr("Message-ID", "<"+hex.EncodeToString(id[:])+"@"+domain+">")
	hdr("MIME-Version", "1.0")
	hdr("Auto-Submitted", "auto-generated")
	if html == "" {
		hdr("Content-Type", "text/plain; charset=utf-8")
		hdr("Content-Transfer-Encoding", "base64")
		b.WriteString("\r\n")
		writeBase64(&b, []byte(text))
		return b.Bytes(), nil
	}
	boundary := "os-" + hex.EncodeToString(id[:])
	hdr("Content-Type", `multipart/alternative; boundary="`+boundary+`"`)
	b.WriteString("\r\n")
	part := func(ct, body string) {
		fmt.Fprintf(&b, "--%s\r\nContent-Type: %s; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n", boundary, ct)
		writeBase64(&b, []byte(body))
	}
	part("text/plain", text)
	part("text/html", html)
	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return b.Bytes(), nil
}

func writeBase64(b *bytes.Buffer, data []byte) {
	enc := base64.StdEncoding.EncodeToString(data)
	for len(enc) > 76 {
		b.WriteString(enc[:76])
		b.WriteString("\r\n")
		enc = enc[76:]
	}
	b.WriteString(enc)
	b.WriteString("\r\n")
}
