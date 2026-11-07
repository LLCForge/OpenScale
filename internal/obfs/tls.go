package obfs

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/openscale/openscale/internal/securefile"
)

// TLS camouflage for the coordinator TCP transport (#613, ADR-0186). The
// stream that already carries framed WireGuard datagrams (ADR-0032) runs
// inside a real TLS 1.3 session on port 443, so a middlebox that only
// lets TLS through sees a TLS server. WireGuard still authenticates every
// datagram: TLS adds no trust. A client that does not open with the
// transport preamble after the handshake gets an ordinary HTTP 404, so an
// active prober sees a web server, not a VPN.

// Certificate file names in the coordinator's state directory.
const (
	CertFile = "obfs-tls-cert.pem"
	KeyFile  = "obfs-tls-key.pem"
	// certValidity is the lifetime of a generated certificate.
	certValidity = 10 * 365 * 24 * time.Hour
	maxPEM       = 64 << 10
)

// decoyResponse is what a prober gets.
const decoyResponse = "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 9\r\nConnection: close\r\n\r\nNot Found"

// alpn makes the handshake look like a web client and server.
var alpn = []string{"h2", "http/1.1"}

// GenerateCertificate makes a self-signed ECDSA P-256 certificate for the
// given names and returns it with its pin.
func GenerateCertificate(names []string, now time.Time) (tls.Certificate, Pin, error) {
	if len(names) == 0 {
		return tls.Certificate{}, Pin{}, errors.New("obfs: certificate needs a name")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, Pin{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return tls.Certificate{}, Pin{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: names[0]},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(certValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, Pin{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, Pin{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, SPKIPin(leaf), nil
}

// LoadOrCreateCertificate reads CertFile and KeyFile from dir, creating a
// self-signed pair for names when both are missing. The key file is
// private to the owner (securefile).
func LoadOrCreateCertificate(dir string, names []string, now time.Time) (tls.Certificate, Pin, error) {
	certPath, keyPath := filepath.Join(dir, CertFile), filepath.Join(dir, KeyFile)
	certPEM, cerr := securefile.ReadLimited(certPath, maxPEM)
	keyPEM, kerr := securefile.ReadPrivate(keyPath, maxPEM)
	switch {
	case cerr == nil && kerr == nil:
		c, err := tls.X509KeyPair(certPEM, keyPEM)
		clear(keyPEM)
		if err != nil {
			return tls.Certificate{}, Pin{}, fmt.Errorf("TLS gizleme sertifikası okunamadı: %w", err)
		}
		leaf, err := x509.ParseCertificate(c.Certificate[0])
		if err != nil {
			return tls.Certificate{}, Pin{}, err
		}
		c.Leaf = leaf
		return c, SPKIPin(leaf), nil
	case errors.Is(cerr, os.ErrNotExist) && errors.Is(kerr, os.ErrNotExist):
	default:
		return tls.Certificate{}, Pin{}, fmt.Errorf("TLS gizleme sertifikası eksik veya okunamıyor (%s, %s)", CertFile, KeyFile)
	}
	c, pin, err := GenerateCertificate(names, now)
	if err != nil {
		return tls.Certificate{}, Pin{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(c.PrivateKey)
	if err != nil {
		return tls.Certificate{}, Pin{}, err
	}
	keyOut := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	clear(keyDER)
	defer clear(keyOut)
	if err := securefile.WriteNew(keyPath, keyOut); err != nil {
		return tls.Certificate{}, Pin{}, err
	}
	if err := securefile.WriteNew(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Certificate[0]})); err != nil {
		return tls.Certificate{}, Pin{}, err
	}
	return c, pin, nil
}

// ServerConfig returns the coordinator's TLS settings for cert.
func ServerConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   alpn,
	}
}

// ClientTLS is what a device needs to open the camouflaged transport.
type ClientTLS struct {
	// ServerName is sent as SNI and checked against the certificate when
	// no pin is given. Required.
	ServerName string `json:"server_name"`
	// Pins trust exactly these keys (self-signed certificate); empty uses
	// the system CAs for ServerName.
	Pins []string `json:"pins,omitempty"`
}

// Config returns the client TLS settings.
func (c ClientTLS) Config(now func() time.Time) (*tls.Config, error) {
	if c.ServerName == "" || len(c.ServerName) > 253 {
		return nil, errors.New("TLS gizleme için sunucu adı (SNI) gerekli")
	}
	pins, err := ParsePins(c.Pins)
	if err != nil {
		return nil, err
	}
	if len(pins) > 0 {
		cfg, err := PinOnlyConfig(c.ServerName, pins, now)
		if err != nil {
			return nil, err
		}
		cfg.NextProtos = alpn
		return cfg, nil
	}
	return &tls.Config{ServerName: c.ServerName, MinVersion: tls.VersionTLS12, NextProtos: alpn}, nil
}

// prefixConn replays bytes already read before the rest of the stream.
type prefixConn struct {
	net.Conn
	r io.Reader
}

func (p *prefixConn) Read(b []byte) (int, error) { return p.r.Read(b) }

// Demux reads len(magic) bytes from c (within timeout) after the TLS
// handshake. When they equal magic, the returned conn replays them and ok
// is true. Otherwise a decoy HTTP 404 is written, c is closed and ok is
// false.
func Demux(c net.Conn, magic string, timeout time.Duration) (net.Conn, bool) {
	_ = c.SetReadDeadline(time.Now().Add(timeout))
	got := make([]byte, len(magic))
	if _, err := io.ReadFull(c, got); err != nil {
		_ = c.Close()
		return nil, false
	}
	_ = c.SetReadDeadline(time.Time{})
	if !bytes.Equal(got, []byte(magic)) {
		_ = c.SetWriteDeadline(time.Now().Add(timeout))
		_, _ = io.WriteString(c, decoyResponse)
		_ = c.Close()
		return nil, false
	}
	return &prefixConn{Conn: c, r: io.MultiReader(bytes.NewReader(got), c)}, true
}

// Handshake runs the server side of a TLS handshake within timeout.
func Handshake(c net.Conn, cfg *tls.Config, timeout time.Duration) (*tls.Conn, error) {
	tc := tls.Server(c, cfg)
	_ = c.SetDeadline(time.Now().Add(timeout))
	if err := tc.Handshake(); err != nil {
		_ = c.Close()
		return nil, err
	}
	_ = c.SetDeadline(time.Time{})
	return tc, nil
}

// DialTLS wraps an established TCP stream in the client side of the
// camouflage within timeout.
func DialTLS(c net.Conn, cfg *tls.Config, timeout time.Duration) (net.Conn, error) {
	tc := tls.Client(c, cfg)
	_ = c.SetDeadline(time.Now().Add(timeout))
	if err := tc.Handshake(); err != nil {
		_ = c.Close()
		return nil, err
	}
	_ = c.SetDeadline(time.Time{})
	return tc, nil
}
