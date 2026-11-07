// Package pki is the internal certificate authority of an OpenScale
// network (ADR-0138): a separate ECDSA P-256 key, pinned by the root-signed
// network document through its certificate, that issues short-lived TLS
// server certificates for names inside the network only.
//
// The CA certificate carries critical name constraints (the network's DNS
// domain and its two address ranges) and an extended key usage of server
// authentication, so a browser that trusts it cannot be fooled about any
// name outside the network, nor accept a client or code signing
// certificate from it. Nothing here touches a system trust store.
package pki

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/trust"
)

// PEM block types.
const (
	pemCertificate = "CERTIFICATE"
	pemECKey       = "EC PRIVATE KEY"
	pemCSR         = "CERTIFICATE REQUEST"
)

// Limits.
const (
	// DefaultCAValidity is the CA certificate's default validity.
	DefaultCAValidity = 365 * 24 * time.Hour
	// MaxCSRSize bounds a certificate request (DER).
	MaxCSRSize = 4096
	// maxPEMFile bounds key and certificate files.
	maxPEMFile = 64 << 10
	// backdate covers small clock differences between devices.
	backdate = 5 * time.Minute
)

// Errors.
var (
	ErrBadCSR      = errors.New("pki: invalid certificate request")
	ErrBadKey      = errors.New("pki: key must be ECDSA P-256")
	ErrCAExpired   = errors.New("pki: the internal CA certificate is not valid now")
	ErrKeyMismatch = errors.New("pki: the CA key does not match the pinned certificate")
)

// GenerateKey returns a new ECDSA P-256 key.
func GenerateKey(random io.Reader) (*ecdsa.PrivateKey, error) {
	if random == nil {
		random = rand.Reader
	}
	return ecdsa.GenerateKey(elliptic.P256(), random)
}

// NewCA creates the self-signed CA certificate for a network's domain and
// address ranges. The result passes trust.CheckCACertificate.
func NewCA(key *ecdsa.PrivateKey, networkName, domain string, v4, v6 netip.Prefix, now time.Time, validity time.Duration) ([]byte, error) {
	if key == nil || key.Curve != elliptic.P256() {
		return nil, ErrBadKey
	}
	if validity <= 0 {
		validity = DefaultCAValidity
	}
	if validity > trust.MaxCAValidity-backdate {
		validity = trust.MaxCAValidity - backdate
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	ski, err := keyID(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	cn := "OpenScale iç CA"
	if networkName != "" {
		cn += " (" + networkName + ")"
	}
	now = now.UTC().Truncate(time.Second)
	tmpl := &x509.Certificate{
		SerialNumber:                serial,
		Subject:                     pkix.Name{CommonName: cn, Organization: []string{"OpenScale"}},
		NotBefore:                   now.Add(-backdate),
		NotAfter:                    now.Add(validity),
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:                 []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid:       true,
		IsCA:                        true,
		MaxPathLen:                  0,
		MaxPathLenZero:              true,
		SubjectKeyId:                ski,
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         []string{domain},
		PermittedIPRanges:           []*net.IPNet{prefixNet(v4.Masked()), prefixNet(v6.Masked())},
		SignatureAlgorithm:          x509.ECDSAWithSHA256,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	if err := trust.CheckCACertificate(c, domain, v4, v6); err != nil {
		return nil, err
	}
	return der, nil
}

func prefixNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: net.IP(p.Addr().AsSlice()), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}

func randomSerial() (*big.Int, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	b[0] &= 0x7f
	b[0] |= 0x01 // never zero, always positive
	return new(big.Int).SetBytes(b), nil
}

func keyID(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(der)
	return sum[:20], nil
}

// Fingerprint is the SHA-256 digest of a certificate as colon separated
// hex, as browsers and certutil show it.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	var b strings.Builder
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(h[i : i+2])
	}
	return b.String()
}

// NormalizeFingerprint drops separators and case so typed fingerprints
// compare.
func NormalizeFingerprint(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "SHA256:")
	return strings.NewReplacer(":", "", " ", "", "-", "").Replace(s)
}

// CertPEM encodes certificates as PEM.
func CertPEM(ders ...[]byte) []byte {
	var buf bytes.Buffer
	for _, d := range ders {
		_ = pem.Encode(&buf, &pem.Block{Type: pemCertificate, Bytes: d})
	}
	return buf.Bytes()
}

// KeyPEM encodes a private key as PEM (SEC 1).
func KeyPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemECKey, Bytes: der}), nil
}

// ParseKeyPEM reads a P-256 key written by KeyPEM (or PKCS #8).
func ParseKeyPEM(data []byte) (*ecdsa.PrivateKey, error) {
	if len(data) > maxPEMFile {
		return nil, ErrBadKey
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, ErrBadKey
	}
	var key *ecdsa.PrivateKey
	switch block.Type {
	case pemECKey:
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, ErrBadKey
		}
		key = k
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, ErrBadKey
		}
		ek, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, ErrBadKey
		}
		key = ek
	default:
		return nil, ErrBadKey
	}
	if key.Curve != elliptic.P256() {
		return nil, ErrBadKey
	}
	return key, nil
}

// ParseCertsPEM reads every certificate of a PEM file, in order.
func ParseCertsPEM(data []byte) ([]*x509.Certificate, error) {
	if len(data) > maxPEMFile {
		return nil, errors.New("pki: certificate file is too large")
	}
	var out []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != pemCertificate {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("pki: %w", err)
		}
		out = append(out, c)
		if len(out) > 8 {
			return nil, errors.New("pki: too many certificates")
		}
	}
	if len(out) == 0 {
		return nil, errors.New("pki: no certificate found")
	}
	return out, nil
}

// NewCSR returns a certificate request for key (DER). The issuer uses
// only its public key: the names are decided by the network document.
func NewCSR(key *ecdsa.PrivateKey, commonName string) ([]byte, error) {
	tmpl := &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: commonName},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	return x509.CreateCertificateRequest(rand.Reader, tmpl, key)
}

// ParseCSR parses and checks a certificate request: bounded size, valid
// self-signature, ECDSA P-256 key.
func ParseCSR(der []byte) (*ecdsa.PublicKey, error) {
	if len(der) == 0 || len(der) > MaxCSRSize {
		return nil, ErrBadCSR
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, ErrBadCSR
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, ErrBadCSR
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, ErrBadKey
	}
	return pub, nil
}

// CA is a loaded internal CA: the pinned certificate and its key.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// LoadCA pairs a key with the pinned certificate, refusing a key that is
// not the certificate's.
func LoadCA(certDER []byte, keyPEM []byte) (*CA, error) {
	c, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("pki: %w", err)
	}
	key, err := ParseKeyPEM(keyPEM)
	if err != nil {
		return nil, err
	}
	pub, ok := c.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, ErrKeyMismatch
	}
	return &CA{Cert: c, Key: key}, nil
}

// Issue signs a server certificate for pub with the given names. The
// lifetime ends at the CA's own end at the latest. The new certificate is
// verified against the CA before it is returned, so a name outside the
// CA's constraints is never handed out.
func (ca *CA) Issue(pub *ecdsa.PublicKey, dns []string, ips []netip.Addr, now time.Time, lifetime time.Duration) ([]byte, error) {
	if pub == nil || pub.Curve != elliptic.P256() {
		return nil, ErrBadKey
	}
	if len(dns) == 0 {
		return nil, errors.New("pki: no names to certify")
	}
	now = now.UTC().Truncate(time.Second)
	if now.Before(ca.Cert.NotBefore) || !now.Before(ca.Cert.NotAfter) {
		return nil, ErrCAExpired
	}
	if lifetime <= 0 || lifetime > time.Duration(trust.MaxCertDays)*24*time.Hour {
		return nil, fmt.Errorf("pki: lifetime must be between 1 second and %d days", trust.MaxCertDays)
	}
	notAfter := now.Add(lifetime)
	if notAfter.After(ca.Cert.NotAfter) {
		notAfter = ca.Cert.NotAfter
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	var addrs []net.IP
	for _, a := range ips {
		addrs = append(addrs, net.IP(a.Unmap().AsSlice()))
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: dns[0]},
		NotBefore:             now.Add(-backdate),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dns,
		IPAddresses:           addrs,
		AuthorityKeyId:        ca.Cert.SubjectKeyId,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, pub, ca.Key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	if err := VerifyLeaf(leaf, ca.Cert, now); err != nil {
		return nil, err
	}
	return der, nil
}

// VerifyLeaf checks leaf against the CA as a TLS client would, including
// the name constraints, for every name it carries.
func VerifyLeaf(leaf, caCert *x509.Certificate, now time.Time) error {
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	opts := x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if _, err := leaf.Verify(opts); err != nil {
		return fmt.Errorf("pki: issued certificate does not verify: %w", err)
	}
	for _, n := range leaf.DNSNames {
		host := strings.Replace(n, "*", "x", 1)
		if err := leaf.VerifyHostname(host); err != nil {
			return fmt.Errorf("pki: %w", err)
		}
	}
	return nil
}
