package trust

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)

// testArgon2 uses the minimum allowed cost to keep tests fast.
var testArgon2 = Argon2Params{Time: 1, MemoryKiB: minArgonMemory, Threads: 1}

type fixture struct {
	rootPub  ed25519.PublicKey
	rootPriv ed25519.PrivateKey
	doc      *Document
	anchor   Anchor
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	pub, priv, err := GenerateRootKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := NewNetworkID(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ula, err := RandomULAPrefix(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := NewDocument(id, DefaultDNSDomain, DefaultIPv4Prefix, ula, testNow, DefaultValidity)
	if err != nil {
		t.Fatalf("NewDocument: %v", err)
	}
	return &fixture{rootPub: pub, rootPriv: priv, doc: doc, anchor: Anchor{RootKey: pub, NetworkID: id}}
}

func newRequest(t *testing.T, hostname string) (*DeviceSecrets, *EnrollmentRequest) {
	t.Helper()
	secrets, err := GenerateDeviceSecrets(rand.Reader, testNow)
	if err != nil {
		t.Fatal(err)
	}
	env, _, err := secrets.NewEnrollmentRequest(hostname, testNow)
	if err != nil {
		t.Fatal(err)
	}
	line, err := EncodeEnrollment(env)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeEnrollment(line)
	if err != nil {
		t.Fatalf("DecodeEnrollment: %v", err)
	}
	req, err := OpenEnrollmentRequest(decoded, testNow.Add(time.Minute))
	if err != nil {
		t.Fatalf("OpenEnrollmentRequest: %v", err)
	}
	return secrets, req
}

func (f *fixture) sign(t *testing.T, doc *Document) Envelope {
	t.Helper()
	env, err := SignDocument(doc, f.rootPriv)
	if err != nil {
		t.Fatalf("SignDocument: %v", err)
	}
	return env
}

func TestRootKeySealRoundTrip(t *testing.T) {
	_, priv, err := GenerateRootKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pass := []byte("dogru parola 123")
	sealed, err := SealRootKey(priv, pass, testArgon2, rand.Reader)
	if err != nil {
		t.Fatalf("SealRootKey: %v", err)
	}
	data, err := MarshalSealedRootKey(sealed)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := UnmarshalSealedRootKey(data)
	if err != nil {
		t.Fatalf("UnmarshalSealedRootKey: %v", err)
	}
	opened, err := loaded.Open(pass)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !opened.Equal(priv) {
		t.Fatal("opened key differs from sealed key")
	}
	if _, err := loaded.Open([]byte("yanlis parola 123")); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("wrong passphrase error = %v", err)
	}
}

func TestRootKeyRejectsTampering(t *testing.T) {
	_, priv, _ := GenerateRootKey(rand.Reader)
	pass := []byte("dogru parola 123")
	sealed, err := SealRootKey(priv, pass, Argon2Params{Time: 2, MemoryKiB: minArgonMemory, Threads: 1}, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	downgraded := *sealed
	downgraded.KDF.Time = 1
	if _, err := downgraded.Open(pass); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("KDF downgrade must fail authentication, got %v", err)
	}

	swapped := *sealed
	otherPub, _, _ := GenerateRootKey(rand.Reader)
	copy(swapped.PublicKey[:], otherPub)
	if _, err := swapped.Open(pass); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("public key swap must fail, got %v", err)
	}

	huge := *sealed
	huge.KDF.MemoryKiB = maxArgonMemory + 1
	if _, err := huge.Open(pass); err == nil {
		t.Fatal("out-of-range KDF parameters must be rejected before deriving")
	}
}

func TestPassphrasePolicy(t *testing.T) {
	_, priv, _ := GenerateRootKey(rand.Reader)
	if _, err := SealRootKey(priv, []byte("kisa"), testArgon2, rand.Reader); !errors.Is(err, ErrWeakPassphrase) {
		t.Fatalf("short passphrase error = %v", err)
	}
	if err := CheckPassphrase([]byte("çok güçlü şifre")); err != nil {
		t.Fatalf("multibyte passphrase should count runes: %v", err)
	}
}

func TestDocumentSignAndOpen(t *testing.T) {
	f := newFixture(t)
	_, laptop := newRequest(t, "Laptop.local")
	if laptop.Hostname != "laptop" {
		t.Fatalf("hostname sanitized to %q", laptop.Hostname)
	}
	next, err := f.doc.Next(testNow, DefaultValidity)
	if err != nil {
		t.Fatal(err)
	}
	dev, err := next.AddDevice(laptop, "laptop", []Role{RoleExitNode}, testNow, DefaultDeviceLife)
	if err != nil {
		t.Fatalf("AddDevice: %v", err)
	}
	if dev.IPv4 != netip.MustParseAddr("100.80.0.1") || !next.IPv6Prefix.Contains(dev.IPv6) {
		t.Fatalf("unexpected addresses %s %s", dev.IPv4, dev.IPv6)
	}
	env := f.sign(t, next)

	got, err := OpenDocument(env, f.anchor, 0, testNow.Add(time.Hour))
	if err != nil {
		t.Fatalf("OpenDocument: %v", err)
	}
	if got.Version != 2 || len(got.Devices) != 1 || !got.Devices[0].HasRole(RoleExitNode) {
		t.Fatalf("unexpected document: %+v", got)
	}
}

func TestOpenDocumentRejections(t *testing.T) {
	f := newFixture(t)
	env := f.sign(t, f.doc)

	otherPub, _, _ := GenerateRootKey(rand.Reader)
	tampered := env
	tampered.Payload = []byte(strings.Replace(string(env.Payload), `"version":1`, `"version":9`, 1))

	wrongCtx, err := Sign(f.rootPriv, EnrollmentContext, env.Payload)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		env    Envelope
		anchor Anchor
		minVer uint64
		now    time.Time
		want   error
	}{
		{"wrong root", env, Anchor{RootKey: otherPub, NetworkID: f.anchor.NetworkID}, 0, testNow, ErrBadSignature},
		{"tampered payload", tampered, f.anchor, 0, testNow, ErrBadSignature},
		{"wrong context", wrongCtx, f.anchor, 0, testNow, ErrWrongContext},
		{"wrong network", env, Anchor{RootKey: f.rootPub, NetworkID: strings.Repeat("0", 32)}, 0, testNow, ErrWrongNetwork},
		{"rollback", env, f.anchor, 2, testNow, ErrRollback},
		{"expired", env, f.anchor, 0, testNow.Add(DefaultValidity), ErrExpired},
		{"not yet valid", env, f.anchor, 0, testNow.Add(-time.Hour), ErrNotYetValid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := OpenDocument(tt.env, tt.anchor, tt.minVer, tt.now)
			if !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestOpenDocumentRejectsUnknownFields(t *testing.T) {
	f := newFixture(t)
	payload, err := json.Marshal(f.doc)
	if err != nil {
		t.Fatal(err)
	}
	withExtra := strings.Replace(string(payload), `{"network_id"`, `{"admin":true,"network_id"`, 1)
	env, err := Sign(f.rootPriv, DocumentContext, []byte(withExtra))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenDocument(env, f.anchor, 0, testNow); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("error = %v, want unknown field rejection", err)
	}
}

func TestStateRejectsRollbackAndEquivocation(t *testing.T) {
	f := newFixture(t)
	state := &State{Anchor: f.anchor}

	v1 := f.sign(t, f.doc)
	if _, err := state.Accept(v1, testNow); err != nil {
		t.Fatalf("accept v1: %v", err)
	}
	v2doc, _ := f.doc.Next(testNow, DefaultValidity)
	v2 := f.sign(t, v2doc)
	if _, err := state.Accept(v2, testNow); err != nil {
		t.Fatalf("accept v2: %v", err)
	}
	if _, err := state.Accept(v1, testNow); !errors.Is(err, ErrRollback) {
		t.Fatalf("v1 after v2 error = %v, want ErrRollback", err)
	}
	if _, err := state.Accept(v2, testNow); err != nil {
		t.Fatalf("re-accepting identical v2 must succeed: %v", err)
	}

	forked, _ := f.doc.Next(testNow, 30*24*time.Hour)
	if _, err := state.Accept(f.sign(t, forked), testNow); !errors.Is(err, ErrEquivocation) {
		t.Fatalf("different v2 error = %v, want ErrEquivocation", err)
	}
}

func TestRevokedDeviceCannotReturn(t *testing.T) {
	f := newFixture(t)
	_, laptop := newRequest(t, "laptop")
	_, desktop := newRequest(t, "desktop")
	doc, _ := f.doc.Next(testNow, DefaultValidity)
	if _, err := doc.AddDevice(laptop, "laptop", nil, testNow, DefaultDeviceLife); err != nil {
		t.Fatal(err)
	}
	if _, err := doc.AddDevice(desktop, "masaustu", nil, testNow, DefaultDeviceLife); err != nil {
		t.Fatal(err)
	}
	if err := doc.AddRule(Rule{From: []string{"laptop"}, To: []string{"masaustu"}, Protocol: ProtocolTCP, Ports: []string{"3389"}}); err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	if err := doc.AddRule(Rule{From: []string{"*"}, To: []string{"masaustu", "laptop"}, Protocol: ProtocolICMP}); err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	dropped, err := doc.RevokeDevice("laptop", testNow)
	if err != nil {
		t.Fatalf("RevokeDevice: %v", err)
	}
	if dropped != 1 || len(doc.Rules) != 1 || len(doc.Rules[0].To) != 1 {
		t.Fatalf("rules after revoke: dropped=%d rules=%+v", dropped, doc.Rules)
	}
	if _, err := doc.AddDevice(laptop, "laptop2", nil, testNow, DefaultDeviceLife); !errors.Is(err, ErrRevokedKey) {
		t.Fatalf("re-enroll error = %v, want ErrRevokedKey", err)
	}
	if _, err := doc.RevokeDevice("laptop", testNow); !errors.Is(err, ErrUnknownDevice) {
		t.Fatalf("double revoke error = %v", err)
	}
}

func TestAddDeviceRejectsDuplicates(t *testing.T) {
	f := newFixture(t)
	_, a := newRequest(t, "a")
	doc, _ := f.doc.Next(testNow, DefaultValidity)
	if _, err := doc.AddDevice(a, "a", nil, testNow, DefaultDeviceLife); err != nil {
		t.Fatal(err)
	}
	if _, err := doc.AddDevice(a, "b", nil, testNow, DefaultDeviceLife); err == nil {
		t.Fatal("same keys under a second name must be rejected")
	}
	_, b := newRequest(t, "b")
	if _, err := doc.AddDevice(b, "a", nil, testNow, DefaultDeviceLife); !errors.Is(err, ErrNameTaken) {
		t.Fatalf("duplicate name error = %v", err)
	}
	if _, err := doc.AddDevice(b, "Bad_Name", nil, testNow, DefaultDeviceLife); err == nil {
		t.Fatal("invalid name must be rejected")
	}
	if len(doc.Devices) != 1 {
		t.Fatalf("failed adds must not change the document, got %d devices", len(doc.Devices))
	}
}

func TestRuleValidation(t *testing.T) {
	f := newFixture(t)
	_, a := newRequest(t, "a")
	doc, _ := f.doc.Next(testNow, DefaultValidity)
	if _, err := doc.AddDevice(a, "a", nil, testNow, DefaultDeviceLife); err != nil {
		t.Fatal(err)
	}
	bad := []Rule{
		{From: []string{"ghost"}, To: []string{"a"}, Protocol: ProtocolAny},
		{From: []string{"a"}, To: []string{"a"}, Protocol: ProtocolTCP},
		{From: []string{"a"}, To: []string{"a"}, Protocol: ProtocolTCP, Ports: []string{"0"}},
		{From: []string{"a"}, To: []string{"a"}, Protocol: ProtocolTCP, Ports: []string{"10-5"}},
		{From: []string{"a"}, To: []string{"a"}, Protocol: ProtocolICMP, Ports: []string{"22"}},
		{From: []string{"a"}, To: []string{"a"}, Protocol: "gre"},
		{From: []string{"a", "a"}, To: []string{"a"}, Protocol: ProtocolAny},
		{From: []string{"a"}, To: []string{"a"}, Protocol: ProtocolAny, Description: "x\ny"},
	}
	for i, r := range bad {
		if err := doc.AddRule(r); err == nil {
			t.Errorf("rule %d should be rejected: %+v", i, r)
		}
	}
	if len(doc.Rules) != 0 {
		t.Fatalf("rejected rules must not be kept: %+v", doc.Rules)
	}
	if err := doc.AddRule(Rule{From: []string{"a"}, To: []string{"*"}, Protocol: ProtocolUDP, Ports: []string{"5900-5910", "53"}}); err != nil {
		t.Fatalf("valid rule rejected: %v", err)
	}
}

func TestPrefixValidation(t *testing.T) {
	ula := netip.MustParsePrefix("fd12:3456:789a::/48")
	id := strings.Repeat("a", 32)
	bad := []struct {
		v4, v6 string
	}{
		{"8.8.0.0/16", ula.String()},
		{"100.80.0.1/16", ula.String()},
		{"10.0.0.0/31", ula.String()},
		{"100.80.0.0/16", "2001:db8::/48"},
	}
	for _, b := range bad {
		if _, err := NewDocument(id, DefaultDNSDomain, netip.MustParsePrefix(b.v4), netip.MustParsePrefix(b.v6), testNow, DefaultValidity); err == nil {
			t.Errorf("prefixes %s %s should be rejected", b.v4, b.v6)
		}
	}
	if _, err := NewDocument(id, "localhost", DefaultIPv4Prefix, ula, testNow, DefaultValidity); err == nil {
		t.Error("single-label domain should be rejected")
	}
	if _, err := NewDocument(id, DefaultDNSDomain, DefaultIPv4Prefix, ula, testNow, MaxValidity+time.Hour); err == nil {
		t.Error("validity above the maximum should be rejected")
	}
}

func TestAddressAllocationSkipsBroadcast(t *testing.T) {
	f := newFixture(t)
	f.doc.IPv4Prefix = netip.MustParsePrefix("10.9.9.0/30")
	doc, _ := f.doc.Next(testNow, DefaultValidity)
	// 10.9.9.3 is broadcast and 10.9.9.2 is reserved for MagicDNS.
	if r := doc.DNSResolverIPv4().String(); r != "10.9.9.2" {
		t.Fatalf("resolver %s", r)
	}
	for i, want := range []string{"10.9.9.1"} {
		_, req := newRequest(t, "")
		d, err := doc.AddDevice(req, []string{"a"}[i], nil, testNow, DefaultDeviceLife)
		if err != nil {
			t.Fatalf("device %d: %v", i, err)
		}
		if d.IPv4.String() != want {
			t.Fatalf("device %d got %s, want %s", i, d.IPv4, want)
		}
	}
	_, req := newRequest(t, "")
	if _, err := doc.AddDevice(req, "c", nil, testNow, DefaultDeviceLife); !errors.Is(err, ErrAddressSpaceFull) {
		t.Fatalf("error = %v, want ErrAddressSpaceFull", err)
	}
}

func TestEnrollmentRejections(t *testing.T) {
	secrets, err := GenerateDeviceSecrets(rand.Reader, testNow)
	if err != nil {
		t.Fatal(err)
	}
	env, req, err := secrets.NewEnrollmentRequest("pc", testNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenEnrollmentRequest(env, testNow.Add(EnrollmentMaxAge+time.Minute)); !errors.Is(err, ErrEnrollmentExpired) {
		t.Fatalf("stale request error = %v", err)
	}

	// An attacker swaps the WireGuard key but cannot re-sign with the
	// device's signing key.
	var swapped EnrollmentRequest
	if err := json.Unmarshal(env.Payload, &swapped); err != nil {
		t.Fatal(err)
	}
	swapped.WireGuardKey[0] ^= 0xff
	payload, _ := json.Marshal(swapped)
	forged := Envelope{Context: env.Context, Payload: payload, Signature: env.Signature}
	if _, err := OpenEnrollmentRequest(forged, testNow); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("forged request error = %v, want ErrBadSignature", err)
	}
	if swapped.Fingerprint() == req.Fingerprint() {
		t.Fatal("fingerprint must change when a key changes")
	}

	if _, err := DecodeEnrollment("osreq1.%%%"); err == nil {
		t.Fatal("garbage enrollment line must be rejected")
	}
	if _, err := DecodeEnrollment("hello"); err == nil {
		t.Fatal("line without prefix must be rejected")
	}
}

func TestDeviceSecretsRoundTrip(t *testing.T) {
	s, err := GenerateDeviceSecrets(rand.Reader, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if s.WireGuardPrivate[0]&7 != 0 || s.WireGuardPrivate[31]&0x80 != 0 || s.WireGuardPrivate[31]&0x40 == 0 {
		t.Fatal("wireguard key is not clamped")
	}
	data, err := MarshalDeviceSecrets(s)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := UnmarshalDeviceSecrets(data)
	if err != nil {
		t.Fatalf("UnmarshalDeviceSecrets: %v", err)
	}
	a1, b1, _ := s.PublicKeys()
	a2, b2, _ := loaded.PublicKeys()
	if a1 != a2 || b1 != b2 {
		t.Fatal("public keys differ after round trip")
	}
}

func TestKeyTextRejectsNonCanonical(t *testing.T) {
	var k Key
	k[0] = 1
	parsed, err := ParseKey(k.String())
	if err != nil || parsed != k {
		t.Fatalf("round trip failed: %v", err)
	}
	if _, err := ParseKey("short"); err == nil {
		t.Fatal("short key must be rejected")
	}
	nonCanonical := k.String()[:42] + "B="
	if _, err := ParseKey(nonCanonical); err == nil {
		t.Fatal("non-canonical base64 must be rejected")
	}
}

func TestFingerprintNormalization(t *testing.T) {
	_, req := newRequest(t, "x")
	fp := req.Fingerprint()
	if len(fp) != 19 {
		t.Fatalf("fingerprint %q has unexpected length", fp)
	}
	if NormalizeFingerprint(strings.ToLower(fp)) != NormalizeFingerprint(fp) {
		t.Fatal("normalization must ignore case and separators")
	}
}

func FuzzOpenDocument(f *testing.F) {
	pub, priv, _ := GenerateRootKey(rand.Reader)
	id := strings.Repeat("b", 32)
	doc, err := NewDocument(id, DefaultDNSDomain, DefaultIPv4Prefix, netip.MustParsePrefix("fd00:1:2::/48"), testNow, DefaultValidity)
	if err != nil {
		f.Fatal(err)
	}
	env, _ := SignDocument(doc, priv)
	data, _ := MarshalEnvelope(env)
	f.Add(data)
	f.Add([]byte(`{"context":"x","payload":"","signature":""}`))
	// A seed using the ADR-0021 fields, so mutations explore them.
	rich, _ := doc.Next(testNow, DefaultValidity)
	empty := []string{}
	rich.Groups = []Group{{Name: "bos", Members: []string{"tag:mobil"}}}
	rich.ExitUsers = &empty
	rich.Rules = []Rule{{From: []string{"group:bos"}, To: []string{"*"}, Protocol: "47", Ports: []string{}, Action: RuleDeny, Disabled: true}}
	if richEnv, err := SignDocument(rich, priv); err == nil {
		richData, _ := MarshalEnvelope(richEnv)
		f.Add(richData)
	} else {
		f.Fatal(err)
	}
	anchor := Anchor{RootKey: pub, NetworkID: id}
	f.Fuzz(func(t *testing.T, data []byte) {
		env, err := UnmarshalEnvelope(data)
		if err != nil {
			return
		}
		got, err := OpenDocument(env, anchor, 0, testNow)
		if err == nil && got.Validate() != nil {
			t.Fatal("accepted an invalid document")
		}
	})
}

func FuzzDecodeEnrollment(f *testing.F) {
	s, _ := GenerateDeviceSecrets(rand.Reader, testNow)
	env, _, _ := s.NewEnrollmentRequest("pc", testNow)
	line, _ := EncodeEnrollment(env)
	f.Add(line)
	f.Add("osreq1.")
	f.Fuzz(func(t *testing.T, line string) {
		env, err := DecodeEnrollment(line)
		if err != nil {
			return
		}
		_, _ = OpenEnrollmentRequest(env, testNow)
	})
}
