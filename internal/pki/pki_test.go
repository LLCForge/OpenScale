package pki

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/trust"
)

var (
	testNow    = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	testDomain = "openscale.internal"
	testV4     = netip.MustParsePrefix("100.80.0.0/16")
	testV6     = netip.MustParsePrefix("fd12:3456:789a::/48")
)

func newTestCA(t *testing.T) *CA {
	t.Helper()
	key, err := GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	der, err := NewCA(key, "Ev", testDomain, testV4, testV6, testNow, 0)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := KeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := LoadCA(der, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func TestNewCAPassesTrustCheck(t *testing.T) {
	ca := newTestCA(t)
	if err := trust.CheckCACertificate(ca.Cert, testDomain, testV4, testV6); err != nil {
		t.Fatal(err)
	}
	if got := ca.Cert.NotAfter.Sub(ca.Cert.NotBefore); got > trust.MaxCAValidity {
		t.Fatalf("validity %v", got)
	}
	other, _ := GenerateKey(nil)
	otherPEM, _ := KeyPEM(other)
	if _, err := LoadCA(ca.Cert.Raw, otherPEM); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("mismatched key: %v", err)
	}
}

func TestIssueConstrained(t *testing.T) {
	ca := newTestCA(t)
	leafKey, _ := GenerateKey(nil)
	dns := []string{"nas." + testDomain, "*.nas." + testDomain}
	ips := []netip.Addr{netip.MustParseAddr("100.80.0.5"), netip.MustParseAddr("fd12:3456:789a::5")}
	der, err := ca.Issue(&leafKey.PublicKey, dns, ips, testNow, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.IsCA || leaf.NotAfter.Sub(testNow) != 7*24*time.Hour || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatalf("leaf fields: ca=%v notAfter=%v eku=%v", leaf.IsCA, leaf.NotAfter, leaf.ExtKeyUsage)
	}
	if err := leaf.VerifyHostname("grafana.nas." + testDomain); err != nil {
		t.Fatal(err)
	}
	// Names outside the constraints are never issued.
	for _, bad := range [][]string{{"example.org"}, {"nas." + testDomain, "evil.example.org"}} {
		if _, err := ca.Issue(&leafKey.PublicKey, bad, nil, testNow, time.Hour); err == nil {
			t.Fatalf("issued outside constraints: %v", bad)
		}
	}
	if _, err := ca.Issue(&leafKey.PublicKey, dns, []netip.Addr{netip.MustParseAddr("192.0.2.1")}, testNow, time.Hour); err == nil {
		t.Fatal("issued an address outside the network")
	}
	if _, err := ca.Issue(&leafKey.PublicKey, dns, nil, testNow, 31*24*time.Hour); err == nil {
		t.Fatal("lifetime above the maximum accepted")
	}
	if _, err := ca.Issue(&leafKey.PublicKey, dns, nil, ca.Cert.NotAfter.Add(time.Hour), time.Hour); !errors.Is(err, ErrCAExpired) {
		t.Fatalf("expired CA: %v", err)
	}
	// Lifetime is cut at the CA's end.
	late := ca.Cert.NotAfter.Add(-time.Hour)
	der, err = ca.Issue(&leafKey.PublicKey, dns, nil, late, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ = x509.ParseCertificate(der)
	if leaf.NotAfter.After(ca.Cert.NotAfter) {
		t.Fatal("leaf outlives the CA")
	}
}

func TestParseCSR(t *testing.T) {
	key, _ := GenerateKey(nil)
	csr, err := NewCSR(key, "x")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParseCSR(csr)
	if err != nil || !pub.Equal(&key.PublicKey) {
		t.Fatalf("csr: %v", err)
	}
	broken := append([]byte(nil), csr...)
	broken[len(broken)-3] ^= 0xff
	if _, err := ParseCSR(broken); err == nil {
		t.Fatal("broken signature accepted")
	}
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	edCSR, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "x"}}, edKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseCSR(edCSR); !errors.Is(err, ErrBadKey) {
		t.Fatalf("ed25519 csr: %v", err)
	}
	if _, err := ParseCSR(make([]byte, MaxCSRSize+1)); err == nil {
		t.Fatal("oversized csr accepted")
	}
}

func TestFingerprintNormalize(t *testing.T) {
	fp := Fingerprint([]byte("x"))
	if NormalizeFingerprint(strings.ToLower(fp)) != NormalizeFingerprint(strings.ReplaceAll(fp, ":", "")) {
		t.Fatal("normalize")
	}
}

func TestIssuerOverHTTP(t *testing.T) {
	ca := newTestCA(t)
	allowed := netip.MustParseAddr("127.0.0.1")
	iss := NewIssuer(IssuerConfig{
		Authorize: func(remote netip.Addr) (Grant, bool) {
			if remote != allowed {
				return Grant{}, false
			}
			return Grant{Device: "laptop", DNS: []string{"laptop." + testDomain, "*.laptop." + testDomain}, IPs: []netip.Addr{netip.MustParseAddr("100.80.0.2")}, Lifetime: 24 * time.Hour}, true
		},
		CA:  func() (*CA, error) { return ca, nil },
		Now: func() time.Time { return testNow },
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- iss.Serve(ctx, ln) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	addr := netip.MustParseAddrPort(ln.Addr().String())
	key, _ := GenerateKey(nil)
	leafDER, err := Request(ctx, addr, netip.Addr{}, key, ca.Cert.Raw, testNow)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(leafDER)
	if leaf.Subject.CommonName != "laptop."+testDomain || len(leaf.IPAddresses) != 1 {
		t.Fatalf("leaf: %v %v", leaf.Subject, leaf.IPAddresses)
	}
	// A different pinned CA makes the client refuse the answer.
	other := newTestCA(t)
	if _, err := Request(ctx, addr, netip.Addr{}, key, other.Cert.Raw, testNow); err == nil {
		t.Fatal("answer chaining to another CA accepted")
	}
	// Rate limit per device.
	var lastErr error
	for range perDeviceMax + 2 {
		_, lastErr = Request(ctx, addr, netip.Addr{}, key, ca.Cert.Raw, testNow)
	}
	if lastErr == nil || !strings.Contains(lastErr.Error(), "429") {
		t.Fatalf("rate limit: %v", lastErr)
	}
	// Wrong method.
	resp, err := http.Get("http://" + addr.String() + CertPath)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET: %d", resp.StatusCode)
	}
}

func TestIssuerRefusesUnknownSource(t *testing.T) {
	ca := newTestCA(t)
	iss := NewIssuer(IssuerConfig{
		Authorize: func(netip.Addr) (Grant, bool) { return Grant{}, false },
		CA:        func() (*CA, error) { return ca, nil },
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = iss.Serve(ctx, ln) }()
	key, _ := GenerateKey(nil)
	_, err = Request(ctx, netip.MustParseAddrPort(ln.Addr().String()), netip.Addr{}, key, ca.Cert.Raw, time.Now())
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("got %v", err)
	}
}

func TestKeyPEMRoundTrip(t *testing.T) {
	key, _ := GenerateKey(nil)
	b, err := KeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseKeyPEM(b)
	if err != nil || !back.Equal(key) {
		t.Fatalf("round trip: %v", err)
	}
	var _ *ecdsa.PrivateKey = back
	if _, err := ParseKeyPEM([]byte("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n")); err == nil {
		t.Fatal("rsa accepted")
	}
}

func TestTrustStoreStepsNeverEmpty(t *testing.T) {
	for _, goos := range []string{"windows", "darwin", "linux", "android", "plan9"} {
		if len(TrustStoreSteps(goos, "ca.crt")) == 0 {
			t.Fatal(goos)
		}
	}
}

func FuzzParseCSR(f *testing.F) {
	key, _ := GenerateKey(nil)
	csr, _ := NewCSR(key, "x")
	f.Add(csr)
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x00})
	f.Fuzz(func(t *testing.T, b []byte) {
		pub, err := ParseCSR(b)
		if err == nil && pub == nil {
			t.Fatal("nil key without error")
		}
	})
}

func FuzzParseCertsPEM(f *testing.F) {
	key, err := GenerateKey(nil)
	if err != nil {
		f.Fatal(err)
	}
	der, err := NewCA(key, "", testDomain, testV4, testV6, testNow, 0)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(CertPEM(der))
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		certs, err := ParseCertsPEM(b)
		if err == nil && len(certs) == 0 {
			t.Fatal("no certificates without error")
		}
		_, _ = ParseKeyPEM(b)
	})
}
