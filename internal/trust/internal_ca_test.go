package trust

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"
)

// testCACert builds a CA certificate; mutate adjusts the template.
func testCACert(t *testing.T, doc *Document, mutate func(*x509.Certificate)) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pn := func(p netip.Prefix) *net.IPNet {
		return &net.IPNet{IP: net.IP(p.Addr().AsSlice()), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
	}
	tmpl := &x509.Certificate{
		SerialNumber:                big.NewInt(7),
		Subject:                     pkix.Name{CommonName: "test CA"},
		NotBefore:                   testNow.Add(-time.Hour),
		NotAfter:                    testNow.Add(365 * 24 * time.Hour),
		KeyUsage:                    x509.KeyUsageCertSign,
		ExtKeyUsage:                 []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid:       true,
		IsCA:                        true,
		MaxPathLenZero:              true,
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         []string{doc.DNSDomain},
		PermittedIPRanges:           []*net.IPNet{pn(doc.IPv4Prefix), pn(doc.IPv6Prefix)},
		SignatureAlgorithm:          x509.ECDSAWithSHA256,
	}
	if mutate != nil {
		mutate(tmpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestInternalCAValidation(t *testing.T) {
	_, doc := policyDoc(t)
	good := testCACert(t, doc, nil)
	if err := doc.SetInternalCA(&InternalCA{Certificate: good, Issuer: "vps"}); err != nil {
		t.Fatalf("valid CA rejected: %v", err)
	}
	if doc.InternalCA.Lifetime() != DefaultCertDays*24*time.Hour {
		t.Fatalf("default lifetime %v", doc.InternalCA.Lifetime())
	}
	bad := map[string]*InternalCA{
		"unknown issuer": {Certificate: good, Issuer: "yok"},
		"days":           {Certificate: good, Issuer: "vps", CertDays: MaxCertDays + 1},
		"garbage":        {Certificate: []byte("not a certificate"), Issuer: "vps"},
		"too large":      {Certificate: bytes.Repeat([]byte{1}, MaxCACertSize+1), Issuer: "vps"},
		"no constraints": {Certificate: testCACert(t, doc, func(c *x509.Certificate) {
			c.PermittedDNSDomains, c.PermittedIPRanges, c.PermittedDNSDomainsCritical = nil, nil, false
		}), Issuer: "vps"},
		"other domain": {Certificate: testCACert(t, doc, func(c *x509.Certificate) { c.PermittedDNSDomains = []string{"example.org"} }), Issuer: "vps"},
		"extra domain": {Certificate: testCACert(t, doc, func(c *x509.Certificate) {
			c.PermittedDNSDomains = append(c.PermittedDNSDomains, "example.org")
		}), Issuer: "vps"},
		"not critical": {Certificate: testCACert(t, doc, func(c *x509.Certificate) { c.PermittedDNSDomainsCritical = false }), Issuer: "vps"},
		"path length":  {Certificate: testCACert(t, doc, func(c *x509.Certificate) { c.MaxPathLenZero, c.MaxPathLen = false, 1 }), Issuer: "vps"},
		"client auth": {Certificate: testCACert(t, doc, func(c *x509.Certificate) {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
		}), Issuer: "vps"},
		"no eku":     {Certificate: testCACert(t, doc, func(c *x509.Certificate) { c.ExtKeyUsage = nil }), Issuer: "vps"},
		"long valid": {Certificate: testCACert(t, doc, func(c *x509.Certificate) { c.NotAfter = c.NotBefore.Add(MaxCAValidity + time.Hour) }), Issuer: "vps"},
		"not ca": {Certificate: testCACert(t, doc, func(c *x509.Certificate) {
			c.IsCA, c.MaxPathLenZero = false, false
			c.KeyUsage = x509.KeyUsageDigitalSignature
		}), Issuer: "vps"},
		"wrong ipv4": {Certificate: testCACert(t, doc, func(c *x509.Certificate) {
			c.PermittedIPRanges[0] = &net.IPNet{IP: net.IPv4(10, 0, 0, 0).To4(), Mask: net.CIDRMask(8, 32)}
		}), Issuer: "vps"},
	}
	for name, ca := range bad {
		if err := doc.SetInternalCA(ca); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if !bytes.Equal(doc.InternalCA.Certificate, good) {
			t.Fatalf("%s: rejected change must not be kept", name)
		}
	}
}

func TestInternalCAEncodingAndEdits(t *testing.T) {
	_, doc := policyDoc(t)
	before, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(before, []byte("internal_ca")) {
		t.Fatal("document without a CA must encode without the field")
	}
	der := testCACert(t, doc, nil)
	if err := doc.SetInternalCA(&InternalCA{Certificate: der, Issuer: "vps", CertDays: 3}); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var back Document
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if err := back.Validate(); err != nil || !bytes.Equal(back.InternalCA.Certificate, der) || back.InternalCA.CertDays != 3 {
		t.Fatalf("round trip: %v", err)
	}
	if err := doc.RenameDevice("vps", "sunucu"); err != nil {
		t.Fatal(err)
	}
	if doc.InternalCA.Issuer != "sunucu" {
		t.Fatalf("rename did not follow: %q", doc.InternalCA.Issuer)
	}
	if _, err := doc.RevokeDevice("sunucu", testNow); err != nil {
		t.Fatalf("revoking the issuer must not fail: %v", err)
	}
	if doc.InternalCA != nil {
		t.Fatal("revoking the issuer must unpin the CA")
	}
	// A domain change that the CA does not cover is refused.
	if err := doc.SetInternalCA(&InternalCA{Certificate: testCACert(t, doc, nil), Issuer: "laptop"}); err != nil {
		t.Fatal(err)
	}
	if err := doc.transact(func() error { doc.DNSDomain = "baska.internal"; return nil }); err == nil {
		t.Fatal("domain change must fail while the CA pins the old domain")
	}
}

func TestServeAndCertPolicy(t *testing.T) {
	_, doc := policyDoc(t)
	if err := doc.SetDeviceTags("vps", []string{"sunucu"}); err != nil {
		t.Fatal(err)
	}
	if err := doc.SetInternalCA(&InternalCA{Certificate: testCACert(t, doc, nil), Issuer: "vps"}); err != nil {
		t.Fatal(err)
	}
	for _, r := range []Rule{
		{From: []string{"laptop", "telefon"}, To: []string{"tag:sunucu"}, Service: ServiceServe},
		{From: []string{"telefon"}, To: []string{"vps"}, Service: ServiceServe, Action: RuleDeny},
		{From: []string{"*"}, To: []string{"vps"}, Service: ServiceCert},
		{From: []string{"masaustu"}, To: []string{"vps"}, Protocol: ProtocolAny},
	} {
		if err := doc.AddRule(r); err != nil {
			t.Fatal(err)
		}
	}
	if !doc.AllowsServe("laptop", "vps") || doc.AllowsServe("telefon", "vps") || doc.AllowsServe("masaustu", "vps") {
		t.Fatal("serve decisions wrong (deny wins, any rule does not grant the service)")
	}
	if !doc.Allows("laptop", "vps", ProtocolTCP, ServePort) {
		t.Fatal("serve rule must open the serve port")
	}
	if !doc.HostsService("vps", ServiceServe) || doc.HostsService("laptop", ServiceServe) {
		t.Fatal("HostsService serve")
	}
	if !doc.AllowsCertRequest("laptop") || doc.AllowsCertRequest("vps") {
		t.Fatal("cert request decisions wrong")
	}
	dns, ips, ok := doc.CertNames("vps")
	want := []string{"vps." + doc.DNSDomain, "*.vps." + doc.DNSDomain}
	if !ok || !slices.Equal(dns, want) || len(ips) != 2 {
		t.Fatalf("CertNames: %v %v", dns, ips)
	}
	if !doc.MatchesEntries([]string{"tag:sunucu"}, "vps") || doc.MatchesEntries([]string{"tag:sunucu"}, "laptop") || doc.MatchesEntries([]string{"*"}, "yok") {
		t.Fatal("MatchesEntries")
	}
	if err := doc.AddRule(Rule{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceServe, Users: []string{"ali"}}); err == nil {
		t.Fatal("serve rule with users accepted")
	}
}

func TestCheckCACertificateErrors(t *testing.T) {
	_, doc := policyDoc(t)
	c, err := x509.ParseCertificate(testCACert(t, doc, nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckCACertificate(c, "baska.internal", doc.IPv4Prefix, doc.IPv6Prefix); !errors.Is(err, ErrCAConstraints) {
		t.Fatalf("got %v", err)
	}
}
