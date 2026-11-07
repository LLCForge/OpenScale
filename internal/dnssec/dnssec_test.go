package dnssec

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

var testNow = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

func mustName(t testing.TB, s string) dnsmessage.Name {
	t.Helper()
	n, err := dnsmessage.NewName(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func aRR(t testing.TB, name string, ip [4]byte) RR {
	t.Helper()
	rr, err := FromResource(dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: mustName(t, name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 300},
		Body:   &dnsmessage.AResource{A: ip},
	})
	if err != nil {
		t.Fatal(err)
	}
	return rr
}

// RFC 4509 2.3 test vector (key tag and SHA-256 DS of an RSA/SHA-1 key).
func TestRFC4509Vector(t *testing.T) {
	pub, err := base64.StdEncoding.DecodeString("AQOeiiR0GOMYkDshWoSKz9XzfwJr1AYtsmx3TGkJaNXVbfi/2pHm822aJ5iI9BMzNXxeYCmZDRD99WYwYqUSdjMmmAphXdvxegXd/M5+X7OrzKBaMbCVdFLUUh6DhweJBjEVv5f2wwjM9XzcnOf+EPbtG9DMBmADjFDc2w/rljwvFw==")
	if err != nil {
		t.Fatal(err)
	}
	k := DNSKEY{Flags: 256, Protocol: 3, Algorithm: AlgRSASHA1, PublicKey: pub}
	if got := k.KeyTag(); got != 60485 {
		t.Fatalf("key tag %d, want 60485", got)
	}
	ds, err := ComputeDS("dskey.example.com.", k, DigestSHA256)
	if err != nil {
		t.Fatal(err)
	}
	want := "D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A"
	if got := strings.ToUpper(hex.EncodeToString(ds.Digest)); got != want {
		t.Fatalf("digest %s, want %s", got, want)
	}
	// RSA/SHA-1 is not supported: the DS never matches (insecure, not secure).
	if (DS{KeyTag: 60485, Algorithm: AlgRSASHA1, DigestType: DigestSHA256, Digest: ds.Digest}).Matches("dskey.example.com.", k) {
		t.Fatal("SHA-1 algorithm DS matched")
	}
}

func TestRootAnchors(t *testing.T) {
	a := RootAnchors()
	if len(a) != 2 || a[0].KeyTag != 20326 || a[1].KeyTag != 38696 {
		t.Fatalf("anchors %+v", a)
	}
	for _, d := range a {
		if !d.Supported() || len(d.Digest) != 32 {
			t.Fatalf("anchor %d unusable", d.KeyTag)
		}
		back, err := ParseDS(d.Rdata())
		if err != nil || !bytes.Equal(back.Digest, d.Digest) {
			t.Fatal("anchor round trip")
		}
	}
}

func TestParseAnchors(t *testing.T) {
	in := "; comment\n. 172800 IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D\n\n. DS 1 13 4 " +
		strings.Repeat("ab", 48) + "\n"
	got, err := ParseAnchors(strings.NewReader(in))
	if err != nil || len(got) != 2 || got[0].KeyTag != 20326 || got[1].DigestType != DigestSHA384 {
		t.Fatalf("%v %+v", err, got)
	}
	for _, bad := range []string{
		"", "example. DS 1 8 2 " + strings.Repeat("00", 32), ". DS 1 8 2 abcd", ". A 1.2.3.4 x y z",
		". DS 1 5 1 " + strings.Repeat("00", 20), // only unsupported
	} {
		if _, err := ParseAnchors(strings.NewReader(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

type testKey struct {
	priv crypto.Signer
	key  DNSKEY
	alg  uint8
}

func newTestKey(t testing.TB, alg uint8, flags uint16) testKey {
	t.Helper()
	var priv crypto.Signer
	var err error
	switch alg {
	case AlgED25519:
		_, priv, err = ed25519.GenerateKey(rand.Reader)
	case AlgECDSAP256SHA256:
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case AlgECDSAP384SHA384:
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case AlgRSASHA256, AlgRSASHA512:
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
	}
	if err != nil {
		t.Fatal(err)
	}
	k, err := NewDNSKEY(priv.Public(), alg, flags)
	if err != nil {
		t.Fatal(err)
	}
	return testKey{priv: priv, key: k, alg: alg}
}

func (k testKey) sign(t testing.TB, signer string, rrset []RR) RRSIG {
	t.Helper()
	s := RRSIG{
		TypeCovered: rrset[0].Type, Algorithm: k.alg, Labels: uint8(LabelCount(rrset[0].Name)), OrigTTL: rrset[0].TTL,
		Inception: uint32(testNow.Add(-time.Hour).Unix()), Expiration: uint32(testNow.Add(24 * time.Hour).Unix()),
		KeyTag: k.key.KeyTag(), SignerName: signer,
	}
	s, err := Sign(s, rrset, k.priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSignVerifyAlgorithms(t *testing.T) {
	for _, alg := range []uint8{AlgED25519, AlgECDSAP256SHA256, AlgECDSAP384SHA384, AlgRSASHA256, AlgRSASHA512} {
		k := newTestKey(t, alg, FlagZone)
		set := []RR{aRR(t, "WWW.Example.", [4]byte{192, 0, 2, 1}), aRR(t, "www.example.", [4]byte{192, 0, 2, 2})}
		sig := k.sign(t, "example.", set)
		// Wire round trip of the RRSIG.
		rd, err := sig.Rdata()
		if err != nil {
			t.Fatal(err)
		}
		sig2, err := ParseRRSIG(rd)
		if err != nil {
			t.Fatal(err)
		}
		// Order and duplicates do not matter.
		set2 := []RR{set[1], set[0], set[1]}
		if err := VerifyRRSIG(sig2, k.key, set2, testNow); err != nil {
			t.Fatalf("alg %d: %v", alg, err)
		}
		bad := slices.Clone(set)
		bad[0].Rdata = []byte{192, 0, 2, 9}
		if err := VerifyRRSIG(sig2, k.key, bad, testNow); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("alg %d: tampered set: %v", alg, err)
		}
		if err := VerifyRRSIG(sig2, k.key, set, testNow.Add(48*time.Hour)); !errors.Is(err, ErrSignatureTime) {
			t.Fatalf("alg %d: expired: %v", alg, err)
		}
		other := newTestKey(t, alg, FlagZone)
		if err := VerifyRRSIG(sig2, other.key, set, testNow); err == nil {
			t.Fatalf("alg %d: other key verified", alg)
		}
		revoked := k.key
		revoked.Flags |= FlagRevoke
		if err := VerifyRRSIG(sig2, revoked, set, testNow); err == nil {
			t.Fatalf("alg %d: revoked key verified", alg)
		}
		// Owner outside the signer's zone.
		if err := VerifyRRSIG(sig2, k.key, set, testNow); err != nil {
			t.Fatal(err)
		}
		sig3 := sig2
		sig3.SignerName = "other."
		if err := VerifyRRSIG(sig3, k.key, set, testNow); err == nil {
			t.Fatalf("alg %d: wrong signer verified", alg)
		}
	}
}

func TestWildcardSignature(t *testing.T) {
	k := newTestKey(t, AlgED25519, FlagZone)
	wild := []RR{aRR(t, "*.example.", [4]byte{192, 0, 2, 7})}
	sig := k.sign(t, "example.", wild)
	if sig.Labels != 1 {
		t.Fatalf("labels %d", sig.Labels)
	}
	expanded := []RR{aRR(t, "deep.host.example.", [4]byte{192, 0, 2, 7})}
	if err := VerifyRRSIG(sig, k.key, expanded, testNow); err != nil {
		t.Fatalf("expanded wildcard: %v", err)
	}
}

func TestUnsupportedAlgorithm(t *testing.T) {
	k := newTestKey(t, AlgED25519, FlagZone)
	set := []RR{aRR(t, "a.example.", [4]byte{192, 0, 2, 1})}
	sig := k.sign(t, "example.", set)
	sig.Algorithm = AlgRSASHA1
	if err := VerifyRRSIG(sig, k.key, set, testNow); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatal(err)
	}
	if SupportedAlgorithm(AlgED448) || SupportedDigest(DigestSHA1) {
		t.Fatal("unexpected support")
	}
}

func TestCanonicalLowercasesNames(t *testing.T) {
	r := dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: mustName(t, "Example."), Type: dnsmessage.TypeMX, Class: dnsmessage.ClassINET},
		Body:   &dnsmessage.MXResource{Pref: 10, MX: mustName(t, "Mail.EXAMPLE.")},
	}
	rr, err := FromResource(r)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte{0, 10}, []byte("\x04mail\x07example\x00")...)
	if rr.Name != "example." || !bytes.Equal(rr.Rdata, want) {
		t.Fatalf("%q %x", rr.Name, rr.Rdata)
	}
	soa := dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: mustName(t, "example."), Type: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET},
		Body:   &dnsmessage.SOAResource{NS: mustName(t, "NS.example."), MBox: mustName(t, "Host.example."), Serial: 1},
	}
	rr, err = FromResource(soa)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(rr.Rdata, []byte("\x02ns\x07example\x00\x04host")) {
		t.Fatalf("soa %x", rr.Rdata)
	}
	// TXT keeps its case.
	txt := dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: mustName(t, "example."), Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET},
		Body:   &dnsmessage.TXTResource{TXT: []string{"AbC"}},
	}
	rr, err = FromResource(txt)
	if err != nil || !bytes.Equal(rr.Rdata, []byte("\x03AbC")) {
		t.Fatalf("%v %x", err, rr.Rdata)
	}
}

func TestBitmapRoundTrip(t *testing.T) {
	types := []uint16{1, 2, 6, 46, 47, 48, 257, 65534}
	b := packBitmap(types)
	got, err := parseBitmap(b)
	if err != nil || !slices.Equal([]uint16(got), types) {
		t.Fatalf("%v %v", err, got)
	}
	for _, bad := range [][]byte{{0}, {0, 0}, {0, 33}, {1, 1, 0xff, 0, 1, 0xff}} {
		if _, err := parseBitmap(bad); err == nil {
			t.Errorf("accepted %x", bad)
		}
	}
}

func TestCompareNames(t *testing.T) {
	// RFC 4034 6.1 example order.
	order := []string{"example.", "a.example.", "yljkjljk.a.example.", "Z.a.example.", "zABC.a.EXAMPLE.", "z.example.", "\x01.z.example.", "*.z.example.", "\x80.z.example."}
	for i := 0; i+1 < len(order); i++ {
		if CompareNames(order[i], order[i+1]) >= 0 {
			t.Errorf("%q !< %q", order[i], order[i+1])
		}
	}
}

func nsec(owner, next string, types ...uint16) NSECRecord {
	return NSECRecord{Owner: owner, NSEC: NSEC{NextName: next, Types: types}}
}

func TestNSECProofs(t *testing.T) {
	d := Denial{Zone: "example.", NSEC: []NSECRecord{
		nsec("example.", "a.example.", 2, 6, 46, 47, 48),
		nsec("a.example.", "c.example.", 1, 46, 47),
		nsec("c.example.", "x.y.example.", 1, 46, 47),
		nsec("sub.example.", "x.y.example.", 2, 46, 47), // delegation (no SOA)
		nsec("x.y.example.", "example.", 1, 46, 47),
	}}
	if p := d.NXDomain("b.example."); p != Proved {
		t.Fatalf("NXDOMAIN b: %v", p)
	}
	if p := d.NXDomain("a.example."); p != NotProved {
		t.Fatal("existing name proved absent")
	}
	if p := d.NoData("a.example.", 28); p != Proved {
		t.Fatalf("NODATA AAAA: %v", p)
	}
	if p := d.NoData("a.example.", 1); p != NotProved {
		t.Fatal("present type proved absent")
	}
	// y.example. is an empty non-terminal.
	if p := d.NoData("y.example.", 1); p != Proved {
		t.Fatalf("ENT: %v", p)
	}
	if p, deleg := d.NoDS("sub.example."); p != Proved || !deleg {
		t.Fatalf("NoDS: %v %v", p, deleg)
	}
	if p, deleg := d.NoDS("a.example."); p != Proved || deleg {
		t.Fatalf("NoDS not a cut: %v %v", p, deleg)
	}
	// The delegation's NSEC cannot deny names below it.
	d2 := Denial{Zone: "example.", NSEC: []NSECRecord{nsec("sub.example.", "x.y.example.", 2, 46, 47), nsec("example.", "a.example.", 2, 6)}}
	if p := d2.NXDomain("www.sub.example."); p != NotProved {
		t.Fatal("parent-side NSEC denied a name below the delegation")
	}
	// The wildcard must be covered too.
	d3 := Denial{Zone: "example.", NSEC: []NSECRecord{nsec("a.example.", "c.example.", 1)}}
	if p := d3.NXDomain("b.example."); p != NotProved {
		t.Fatal("NXDOMAIN without wildcard proof")
	}
	if p := d.WildcardAnswer("b.example.", "example."); p != Proved {
		t.Fatalf("wildcard answer: %v", p)
	}
	// Outside the zone nothing is proved.
	if p := d.NXDomain("b.other."); p != NotProved {
		t.Fatal("out of zone")
	}
}

// nsec3Zone builds a closed NSEC3 chain for names in zone.
func nsec3Zone(t *testing.T, zone string, optOut bool, names map[string][]uint16) []NSEC3Record {
	t.Helper()
	salt := []byte{0xab, 0xcd}
	type h struct {
		hash  []byte
		types []uint16
	}
	var hs []h
	for n, ty := range names {
		x, err := NSEC3Hash(n, salt, 2)
		if err != nil {
			t.Fatal(err)
		}
		hs = append(hs, h{x, ty})
	}
	slices.SortFunc(hs, func(a, b h) int { return bytes.Compare(a.hash, b.hash) })
	var out []NSEC3Record
	for i, x := range hs {
		next := hs[(i+1)%len(hs)].hash
		var flags uint8
		if optOut {
			flags = NSEC3OptOut
		}
		out = append(out, NSEC3Record{Owner: NSEC3Label(x.hash) + "." + zone, NSEC3: NSEC3{
			HashAlgorithm: 1, Flags: flags, Iterations: 2, Salt: salt, NextHashed: next, Types: x.types,
		}})
	}
	return out
}

func TestNSEC3Proofs(t *testing.T) {
	recs := nsec3Zone(t, "example.", false, map[string][]uint16{
		"example.":     {2, 6, 46, 48, 51},
		"a.example.":   {1, 46},
		"sub.example.": {2},
	})
	d := Denial{Zone: "example.", NSEC3: recs}
	if p := d.NXDomain("nope.example."); p != Proved {
		t.Fatalf("NXDOMAIN: %v", p)
	}
	if p := d.NXDomain("a.example."); p != NotProved {
		t.Fatal("existing name")
	}
	if p := d.NoData("a.example.", 28); p != Proved {
		t.Fatalf("NODATA: %v", p)
	}
	if p := d.NoData("a.example.", 1); p != NotProved {
		t.Fatal("present type")
	}
	if p, deleg := d.NoDS("sub.example."); p != Proved || !deleg {
		t.Fatalf("NoDS: %v %v", p, deleg)
	}
	if p := d.WildcardAnswer("x.example.", "example."); p != Proved {
		t.Fatalf("wildcard: %v", p)
	}
	// Below an existing delegation the closest encloser proof fails.
	if p := d.NXDomain("www.sub.example."); p != NotProved {
		t.Fatal("proof below a delegation")
	}
	// Opt-out: an unsigned delegation may exist.
	oo := Denial{Zone: "example.", NSEC3: nsec3Zone(t, "example.", true, map[string][]uint16{
		"example.":   {2, 6, 46, 48, 51},
		"a.example.": {1, 46},
	})}
	if p, deleg := oo.NoDS("unsigned.example."); p != ProvedInsecure || !deleg {
		t.Fatalf("opt-out: %v %v", p, deleg)
	}
	// Too many iterations: insecure.
	many := slices.Clone(recs)
	for i := range many {
		many[i].Iterations = MaxNSEC3Iterations + 1
	}
	if p := (Denial{Zone: "example.", NSEC3: many}).NXDomain("nope.example."); p != ProvedInsecure {
		t.Fatalf("iterations: %v", p)
	}
}

func TestRecordRoundTrips(t *testing.T) {
	n := NSEC{NextName: "b.example.", Types: TypeBitmap{1, 46, 47}}
	rd, err := n.Rdata()
	if err != nil {
		t.Fatal(err)
	}
	n2, err := ParseNSEC(rd)
	if err != nil || n2.NextName != "b.example." || !slices.Equal(n2.Types, n.Types) {
		t.Fatalf("%v %+v", err, n2)
	}
	n3 := NSEC3{HashAlgorithm: 1, Iterations: 5, Salt: []byte{1}, NextHashed: bytes.Repeat([]byte{7}, 20), Types: TypeBitmap{2, 6}}
	m, err := ParseNSEC3(n3.Rdata())
	if err != nil || m.Iterations != 5 || !bytes.Equal(m.NextHashed, n3.NextHashed) {
		t.Fatalf("%v %+v", err, m)
	}
	k := DNSKEY{Flags: 257, Protocol: 3, Algorithm: 15, PublicKey: bytes.Repeat([]byte{1}, 32)}
	k2, err := ParseDNSKEY(k.Rdata())
	if err != nil || k2.KeyTag() != k.KeyTag() {
		t.Fatal(err)
	}
	// Compression pointers in RRSIG signer names are refused.
	if _, err := ParseRRSIG(append(make([]byte, 18), 0xC0, 0x0C, 1)); err == nil {
		t.Fatal("pointer accepted")
	}
}
