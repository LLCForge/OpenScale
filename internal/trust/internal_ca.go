package trust

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"time"
)

// Internal certificate authority and services inside the tunnel (ADR-0138,
// ADR-0139).
//
// The root key never signs X.509: it signs the network document, and the
// document pins the certificate of a separate internal CA whose key lives
// on one device (the issuer). The pinned certificate must carry name
// constraints that limit it to the network's DNS domain and address
// ranges, so a browser that trusts it can be fooled at most about names
// inside the network. Devices ask the issuer for short-lived server
// certificates over the tunnel; the issuer finds the device by the
// tunnel source address and certifies only that device's own names.

// Services of the tunnel service publishing (ADR-0139) and of the
// internal CA (ADR-0138). Like the panel they are served by their own
// components, not by the Apps reconcile loop, so they are not part of
// Services().
const (
	// ServiceServe lets the source reach the web applications, file
	// directories and identity provider that the destination publishes
	// on its shared serve port (ServePort).
	ServiceServe RuleService = "serve"
	// ServiceCert lets the source ask the destination, the issuer of the
	// internal CA, for a certificate of its own names.
	ServiceCert RuleService = "cert"
)

// Fixed tunnel ports of the services above (4022, 4039-4050 and 47821 are
// taken).
const (
	ServePort uint16 = 4051
	CertPort  uint16 = 4052
)

// Limits of the internal CA.
const (
	// DefaultCertDays is the lifetime of an issued server certificate
	// when the document does not set one.
	DefaultCertDays = 7
	// MaxCertDays bounds the lifetime of issued certificates: they are
	// short lived because there is no revocation list.
	MaxCertDays = 30
	// MaxCAValidity bounds the CA certificate's own validity.
	MaxCAValidity = 825 * 24 * time.Hour
	// MaxCACertSize bounds the pinned certificate (DER).
	MaxCACertSize = 4096
)

// InternalCA pins the internal certificate authority (ADR-0138).
type InternalCA struct {
	// Certificate is the self-signed CA certificate (DER, ECDSA P-256).
	Certificate []byte `json:"certificate"`
	// Issuer names the device that holds the CA key and answers
	// certificate requests.
	Issuer string `json:"issuer"`
	// CertDays is the lifetime of issued certificates (0: DefaultCertDays).
	CertDays int `json:"cert_days,omitempty"`
}

// Errors of the internal CA.
var (
	ErrNoInternalCA   = errors.New("the network has no internal certificate authority")
	ErrInvalidCACert  = errors.New("internal CA certificate is invalid")
	ErrCAConstraints  = errors.New("internal CA certificate must be constrained to the network's DNS domain and address ranges")
	ErrUnknownIssuer  = errors.New("internal CA issuer is not a device of the network")
	ErrInvalidCADays  = fmt.Errorf("cert_days must be between 1 and %d", MaxCertDays)
	errCACertTooLarge = fmt.Errorf("internal CA certificate is larger than %d bytes", MaxCACertSize)
)

// Lifetime returns the lifetime of issued certificates.
func (ca *InternalCA) Lifetime() time.Duration {
	days := ca.CertDays
	if days <= 0 {
		days = DefaultCertDays
	}
	return time.Duration(days) * 24 * time.Hour
}

// ParsedCertificate parses the pinned certificate.
func (ca *InternalCA) ParsedCertificate() (*x509.Certificate, error) {
	if len(ca.Certificate) == 0 || len(ca.Certificate) > MaxCACertSize {
		return nil, ErrInvalidCACert
	}
	c, err := x509.ParseCertificate(ca.Certificate)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCACert, err)
	}
	return c, nil
}

// validateInternalCA checks the internal_ca section. It runs only on a
// document whose root signature was already verified, so the X.509
// parser sees owner-signed bytes only.
func (doc *Document) validateInternalCA() error {
	ca := doc.InternalCA
	if ca == nil {
		return nil
	}
	if len(ca.Certificate) > MaxCACertSize {
		return errCACertTooLarge
	}
	if ca.CertDays < 0 || ca.CertDays > MaxCertDays {
		return ErrInvalidCADays
	}
	if _, ok := doc.DeviceByName(ca.Issuer); !ok {
		return ErrUnknownIssuer
	}
	c, err := ca.ParsedCertificate()
	if err != nil {
		return err
	}
	return CheckCACertificate(c, doc.DNSDomain, doc.IPv4Prefix, doc.IPv6Prefix)
}

// CheckCACertificate reports whether c is acceptable as the internal CA of
// a network with the given domain and address ranges: a self-signed ECDSA
// P-256 CA that may sign only end-entity server certificates, with
// critical name constraints that permit exactly the domain and the two
// ranges.
func CheckCACertificate(c *x509.Certificate, domain string, v4, v6 netip.Prefix) error {
	pub, ok := c.PublicKey.(*ecdsa.PublicKey)
	switch {
	case !ok || pub.Curve != elliptic.P256():
		return fmt.Errorf("%w: key must be ECDSA P-256", ErrInvalidCACert)
	case c.SignatureAlgorithm != x509.ECDSAWithSHA256:
		return fmt.Errorf("%w: signature must be ECDSA with SHA-256", ErrInvalidCACert)
	case !c.BasicConstraintsValid || !c.IsCA || c.MaxPathLen != 0 || !c.MaxPathLenZero:
		return fmt.Errorf("%w: must be a CA that signs only end-entity certificates (pathlen 0)", ErrInvalidCACert)
	case c.KeyUsage&x509.KeyUsageCertSign == 0:
		return fmt.Errorf("%w: key usage must allow certificate signing", ErrInvalidCACert)
	case len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || len(c.UnknownExtKeyUsage) != 0:
		return fmt.Errorf("%w: extended key usage must be server authentication only", ErrInvalidCACert)
	case !c.NotAfter.After(c.NotBefore) || c.NotAfter.Sub(c.NotBefore) > MaxCAValidity:
		return fmt.Errorf("%w: validity must be at most %d days", ErrInvalidCACert, int(MaxCAValidity.Hours()/24))
	case !bytes.Equal(c.RawIssuer, c.RawSubject):
		return fmt.Errorf("%w: must be self-signed", ErrInvalidCACert)
	}
	if err := c.CheckSignatureFrom(c); err != nil {
		return fmt.Errorf("%w: self-signature: %v", ErrInvalidCACert, err)
	}
	if !c.PermittedDNSDomainsCritical || !slices.Equal(c.PermittedDNSDomains, []string{domain}) ||
		len(c.ExcludedDNSDomains) != 0 || len(c.ExcludedIPRanges) != 0 ||
		len(c.PermittedEmailAddresses) != 0 || len(c.ExcludedEmailAddresses) != 0 ||
		len(c.PermittedURIDomains) != 0 || len(c.ExcludedURIDomains) != 0 {
		return ErrCAConstraints
	}
	want := []netip.Prefix{v4.Masked(), v6.Masked()}
	if len(c.PermittedIPRanges) != len(want) {
		return ErrCAConstraints
	}
	for i, r := range c.PermittedIPRanges {
		p, ok := ipNetPrefix(r)
		if !ok || p != want[i] {
			return ErrCAConstraints
		}
	}
	return nil
}

// ipNetPrefix converts a name constraint range to a prefix; a mask that is
// not a prefix (non-contiguous) is refused.
func ipNetPrefix(n *net.IPNet) (netip.Prefix, bool) {
	if n == nil {
		return netip.Prefix{}, false
	}
	a, ok := netip.AddrFromSlice(n.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	ones, bits := n.Mask.Size()
	if bits == 0 {
		return netip.Prefix{}, false
	}
	a = a.Unmap()
	if a.BitLen() != bits {
		return netip.Prefix{}, false
	}
	p := netip.PrefixFrom(a, ones)
	if p.Masked() != p {
		return netip.Prefix{}, false
	}
	return p, true
}

// SetInternalCA pins the internal CA (nil removes it).
func (doc *Document) SetInternalCA(ca *InternalCA) error {
	var next *InternalCA
	if ca != nil {
		cp := *ca
		cp.Certificate = slices.Clone(ca.Certificate)
		next = &cp
	}
	return doc.transact(func() error {
		doc.InternalCA = next
		return nil
	})
}

// renameInternalCA follows a device rename (RenameDevice).
func (doc *Document) renameInternalCA(oldName, newName string) {
	if doc.InternalCA != nil && doc.InternalCA.Issuer == oldName {
		doc.InternalCA.Issuer = newName
	}
}

// dropInternalCAFor removes the internal CA when its issuer is revoked:
// the CA key is on that device, so its certificate must not stay pinned.
func (doc *Document) dropInternalCAFor(name string) {
	if doc.InternalCA != nil && doc.InternalCA.Issuer == name {
		doc.InternalCA = nil
	}
}

// CertNames returns the names a certificate for the named device may
// carry: its MagicDNS name and aliases, each also as a wildcard for the
// service names below it (<service>.<device>.<domain>), and its tunnel
// addresses.
func (doc *Document) CertNames(name string) ([]string, []netip.Addr, bool) {
	d, ok := doc.DeviceByName(name)
	if !ok {
		return nil, nil, false
	}
	var dns []string
	for _, label := range append([]string{d.Name}, d.Aliases...) {
		fqdn := label + "." + doc.DNSDomain
		dns = append(dns, fqdn, "*."+fqdn)
	}
	var ips []netip.Addr
	for _, a := range []netip.Addr{d.IPv4, d.IPv6} {
		if a.IsValid() {
			ips = append(ips, a)
		}
	}
	return dns, ips, true
}

// AllowsServe reports whether device from may use the services that
// device to publishes on its shared serve port (ADR-0139).
func (doc *Document) AllowsServe(from, to string) bool {
	return doc.serviceAllowed(ServiceServe, from, to, nil)
}

// AllowsCertRequest reports whether device from may ask the internal CA's
// issuer for a certificate of its own names (ADR-0138).
func (doc *Document) AllowsCertRequest(from string) bool {
	if doc.InternalCA == nil {
		return false
	}
	return doc.serviceAllowed(ServiceCert, from, doc.InternalCA.Issuer, nil)
}

// MatchesEntries reports whether the named device matches one of the
// rule entries (device names, "*", "tag:x", "group:y"). Components use it
// for local lists that can only narrow what the rules allow.
func (doc *Document) MatchesEntries(entries []string, name string) bool {
	if _, ok := doc.DeviceByName(name); !ok {
		return false
	}
	return doc.matchesAny(entries, doc.subject(name))
}
