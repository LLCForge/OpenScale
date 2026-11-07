package piv

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/trust"
)

// fakeOpenPGP emulates the OpenPGP card answers this package relies on, in
// the YubiKey flavour (a wrong PIN answers 6982 and the retries come from
// DO C4). It is a test double, not a reference implementation.
type fakeOpenPGP struct {
	version    Version
	noVersion  bool
	pw1, pw3   []byte
	pw1Tries   int
	pw3Tries   int
	verified81 bool
	verified83 bool
	attrs      []byte
	seed       []byte
	fp         []byte
	ts         []byte
	uif        []byte
	pw1Valid   byte
	wrong63Cx  bool // answer 63Cx like other cards instead of 6982
	corruptSig bool
	signs      int
}

func newFakeOpenPGP(v Version) *fakeOpenPGP {
	return &fakeOpenPGP{
		version: v, pw1: []byte("123456"), pw3: []byte("12345678"), pw1Tries: 3, pw3Tries: 3,
		attrs: []byte{0x01, 0x08, 0x00, 0x00, 0x11, 0x00}, // RSA 2048, the factory default
		uif:   []byte{UIFOff, uifButtonAvailable},
	}
}

func (f *fakeOpenPGP) pwStatus() []byte {
	return []byte{f.pw1Valid, 127, 127, 127, byte(f.pw1Tries), 0, byte(f.pw3Tries)}
}

func (f *fakeOpenPGP) pub() ed25519.PublicKey {
	return ed25519.NewKeyFromSeed(f.seed).Public().(ed25519.PublicKey)
}

func (f *fakeOpenPGP) appData() []byte {
	aid := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x03, 0x04, 0x00, 0x06, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00}
	fps := make([]byte, 60)
	copy(fps, f.fp)
	disc := tlv(0xC0, []byte{0x7D, 0, 0, 0, 0x08, 0, 0, 0xFF, 0, 0})
	disc = appendTLV(disc, doAlgoSig, f.attrs)
	disc = appendTLV(disc, doPWStatus, f.pwStatus())
	disc = appendTLV(disc, doFingerprints, fps)
	disc = appendTLV(disc, doUIFSig, f.uif)
	body := tlv(doAID, aid)
	body = appendTLV(body, 0x5F52, []byte{0x00, 0x73, 0x00, 0x00, 0xE0, 0x05, 0x90, 0x00})
	body = appendTLV(body, doDiscretionary, disc)
	return tlv(doAppRelated, body) // YubiKey 5 wraps the value in 6E
}

func (f *fakeOpenPGP) Transmit(apdu []byte) ([]byte, error) {
	if len(apdu) < 4 {
		return []byte{0x67, 0x00}, nil
	}
	ins, p1, p2 := apdu[1], apdu[2], apdu[3]
	var data []byte
	if len(apdu) > 5 {
		data = apdu[5 : 5+int(apdu[4])]
	}
	ok := func(d []byte) ([]byte, error) { return append(append([]byte(nil), d...), 0x90, 0x00), nil }
	sw := func(s uint16) ([]byte, error) { return []byte{byte(s >> 8), byte(s)}, nil }
	tag := uint16(p1)<<8 | uint16(p2)
	switch ins {
	case insSelect:
		if !bytes.Equal(data, openPGPAID) {
			return sw(swFileNotFound)
		}
		f.verified81, f.verified83 = false, false
		return ok(nil)
	case insOpenPGPVersion:
		if f.noVersion {
			return sw(swInsNotSupported)
		}
		return ok([]byte{f.version.Major, f.version.Minor, f.version.Patch})
	case insVerify:
		pin, tries, flag := f.pw1, &f.pw1Tries, &f.verified81
		if p2 == pwAdmin {
			pin, tries, flag = f.pw3, &f.pw3Tries, &f.verified83
		} else if p2 != pwSign {
			return sw(swIncorrectParams)
		}
		if *tries == 0 {
			return sw(swAuthBlocked)
		}
		if !bytes.Equal(data, pin) {
			*tries--
			if f.wrong63Cx {
				return sw(0x63C0 | uint16(*tries))
			}
			return sw(swSecurityStatus)
		}
		*tries, *flag = 3, true
		return ok(nil)
	case insGetData:
		switch tag {
		case doAppRelated:
			return ok(f.appData())
		case doPWStatus:
			return ok(f.pwStatus())
		case doAlgoSig:
			return ok(f.attrs)
		case doUIFSig:
			return ok(f.uif)
		}
		return sw(swDataNotFound)
	case insPutData:
		if !f.verified83 {
			return sw(swSecurityStatus)
		}
		switch tag {
		case doAlgoSig:
			if f.version.AtLeast(MinOpenPGPEd25519Firmware) || f.noVersion {
				if !isEd25519Attrs(data) {
					return sw(swWrongData)
				}
			} else {
				return sw(swWrongData)
			}
			f.attrs, f.seed, f.fp = append([]byte(nil), data...), nil, nil // a new algorithm clears the key
		case doFPSig:
			f.fp = append([]byte(nil), data...)
		case doTimeSig:
			f.ts = append([]byte(nil), data...)
		case doPWStatus:
			f.pw1Valid = data[0]
		case doUIFSig:
			if f.uif[0] == UIFFixed || f.uif[0] == UIFCachedFixed {
				return sw(swSecurityStatus)
			}
			f.uif = append([]byte(nil), data...)
		default:
			return sw(swDataNotFound)
		}
		return ok(nil)
	case insPutDataOdd:
		if !f.verified83 {
			return sw(swSecurityStatus)
		}
		if p1 != 0x3F || p2 != 0xFF || !isEd25519Attrs(f.attrs) {
			return sw(swIncorrectParams)
		}
		body, err := unwrapTLV(data, doExtHeader)
		if err != nil {
			return sw(swWrongData)
		}
		list, err := parseTLVs(body)
		if err != nil || len(list) != 3 || list[0].Tag != doCRTSig || len(list[0].Value) != 0 {
			return sw(swWrongData)
		}
		hdr, _ := findTLV(list, doPrivTemplate)
		key, _ := findTLV(list, doPrivConcat)
		if !bytes.Equal(hdr, []byte{doPrivEdDSA, 32}) || len(key) != 32 {
			return sw(swWrongData)
		}
		f.seed = append([]byte(nil), key...)
		return ok(nil)
	case insGenerateAsym:
		if p1 != 0x81 || !bytes.Equal(data, []byte{doCRTSig, 0x00}) {
			return sw(swIncorrectParams)
		}
		if f.seed == nil {
			return sw(swDataNotFound)
		}
		return ok(tlv(doPubKey, tlv(doPubPoint, f.pub())))
	case insPSO:
		if p1 != 0x9E || p2 != 0x9A || f.seed == nil {
			return sw(swIncorrectParams)
		}
		if !f.verified81 {
			return sw(swSecurityStatus)
		}
		if f.pw1Valid == 0 {
			f.verified81 = false
		}
		f.signs++
		sig := ed25519.Sign(ed25519.NewKeyFromSeed(f.seed), data)
		if f.corruptSig {
			sig[0] ^= 1
		}
		return ok(sig)
	}
	return sw(swInsNotSupported)
}

// multiApplet routes APDUs to the applet selected last, like a YubiKey
// with both PIV and OpenPGP.
type multiApplet struct {
	piv     *fakeToken
	openpgp *fakeOpenPGP
	cur     Transport
	sent    [][]byte
}

func (m *multiApplet) Transmit(apdu []byte) ([]byte, error) {
	m.sent = append(m.sent, append([]byte(nil), apdu...))
	if len(apdu) > 5 && apdu[1] == insSelect {
		data := apdu[5 : 5+int(apdu[4])]
		switch {
		case bytes.Equal(data, pivAID) && m.piv != nil:
			m.cur = m.piv
		case bytes.Equal(data, openPGPAID) && m.openpgp != nil:
			m.cur = m.openpgp
		default:
			m.cur = nil
			return []byte{0x6A, 0x82}, nil
		}
	}
	if m.cur == nil {
		return []byte{0x69, 0x85}, nil
	}
	return m.cur.Transmit(apdu)
}

func TestOpenPGPAPDUVectors(t *testing.T) {
	cases := []struct {
		name string
		cmd  Command
		want string
	}{
		{"select", Command{INS: insSelect, P1: 0x04, Data: openPGPAID}, "00a4040006d27600012401"},
		{"get data 6e", Command{INS: insGetData, P1: 0x00, P2: 0x6E, Le: 256}, "00ca006e00"},
		{"verify pw1 81", Command{INS: insVerify, P2: pwSign, Data: []byte("123456")}, "0020008106313233343536"},
		{"verify pw3", Command{INS: insVerify, P2: pwAdmin, Data: []byte("12345678")}, "00200083083132333435363738"},
		{"read sig pub", Command{INS: insGenerateAsym, P1: 0x81, Data: []byte{0xB6, 0x00}, Le: 256}, "00478100" + "02b600" + "00"},
		{"pso cds", Command{INS: insPSO, P1: 0x9E, P2: 0x9A, Data: []byte("abc"), Le: 256}, "002a9e9a0361626300"},
		{"set ed25519 attrs", Command{INS: insPutData, P2: doAlgoSig, Data: ed25519AlgoAttrs}, "00da00c10a162b06010401da470f01"},
		{"yubico version", Command{INS: insOpenPGPVersion, Le: 256}, "00f1000000"},
	}
	for _, c := range cases {
		parts, err := c.cmd.Encode()
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if len(parts) != 1 || hex.EncodeToString(parts[0]) != c.want {
			t.Errorf("%s: got %x, want %s", c.name, parts, c.want)
		}
	}
	seed := bytes.Repeat([]byte{0x22}, 32)
	imp, err := encodeOpenPGPImportEd25519(seed)
	if err != nil {
		t.Fatal(err)
	}
	parts, _ := Command{INS: insPutDataOdd, P1: 0x3F, P2: 0xFF, Data: imp}.Encode()
	want := "00db3fff2c" + "4d2a" + "b600" + "7f48029220" + "5f4820" + hex.EncodeToString(seed)
	if got := hex.EncodeToString(parts[0]); got != want {
		t.Errorf("import:\n got %s\nwant %s", got, want)
	}
	if _, err := encodeOpenPGPImportEd25519(seed[:31]); err == nil {
		t.Error("short seed accepted")
	}
}

func TestOpenPGPFingerprintLayout(t *testing.T) {
	// The fingerprint is SHA-1 over 0x99 || len || v4 key body; recompute
	// the body independently from the RFC layout.
	pub := bytes.Repeat([]byte{0x01}, 32)
	got := openPGPFingerprint(pub, 0x5F000000)
	body := mustHex(t, "045f000000"+"16"+"09"+"2b06010401da470f01"+"0107"+"40"+hex.EncodeToString(pub))
	if len(body) != 51 {
		t.Fatalf("body length %d", len(body))
	}
	want := sha1.Sum(append([]byte{0x99, 0x00, 51}, body...))
	if got != want {
		t.Errorf("fingerprint %x, want %x", got, want)
	}
	other := openPGPFingerprint(pub, 0x5F000001)
	if got == other {
		t.Error("timestamp does not change the fingerprint")
	}
	var zero [20]byte
	if got == zero {
		t.Error("zero fingerprint")
	}
}

func TestParseApplicationData(t *testing.T) {
	f := newFakeOpenPGP(Version{5, 4, 3})
	f.attrs = ed25519AlgoAttrs
	f.fp = bytes.Repeat([]byte{0xAA}, 20)
	f.uif = []byte{UIFOn, uifButtonAvailable}
	info, err := parseApplicationData(f.appData())
	if err != nil {
		t.Fatal(err)
	}
	if info.Manufacturer != 0x0006 || info.Serial != 0x01020304 || info.SpecVersion != [2]byte{3, 4} {
		t.Errorf("aid fields: %+v", info)
	}
	if !info.SigIsEd25519() || info.PWStatus.PW1Retries != 3 || info.PWStatus.PW3Retries != 3 || info.PWStatus.PW1ValidMultiple {
		t.Errorf("status: %+v", info)
	}
	if !info.HasUIF || info.SigUIF != UIFOn || info.Fingerprints[0][0] != 0xAA || info.Fingerprints[1][0] != 0 {
		t.Errorf("uif/fingerprints: %+v", info)
	}
	// Unwrapped form (no 6E around the value) parses too.
	inner, _ := unwrapTLV(f.appData(), doAppRelated)
	if _, err := parseApplicationData(inner); err != nil {
		t.Errorf("unwrapped: %v", err)
	}
	if !isEd25519Attrs(append(append([]byte(nil), ed25519AlgoAttrs...), 0xFF)) || isEd25519Attrs([]byte{0x16, 0x2B}) {
		t.Error("attribute match")
	}
	for _, bad := range []string{"", "6e00", "6e03" + "4f0100", "4f10" + "d2760001240103040006010203040000"} {
		if _, err := parseApplicationData(mustHex(t, bad)); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
	if _, err := parseOpenPGPPublicKey(mustHex(t, "7f4903860101")); !errors.Is(err, ErrNotEd25519Key) {
		t.Errorf("short point: %v", err)
	}
	pub := bytes.Repeat([]byte{3}, 32)
	if k, err := parseOpenPGPPublicKey(tlv(doPubKey, tlv(doPubPoint, append([]byte{0x40}, pub...)))); err != nil || !bytes.Equal(k, pub) {
		t.Errorf("0x40-prefixed point: %v", err)
	}
}

func TestOpenPGPImportAndSign(t *testing.T) {
	f := newFakeOpenPGP(Version{5, 4, 3})
	c, err := NewOpenPGPClient(f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.SignaturePublicKey(); !errors.Is(err, ErrNoSignatureKey) {
		t.Fatalf("empty card: %v", err)
	}
	_, root, _ := ed25519.GenerateKey(rand.Reader)
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := c.ImportEd25519([]byte("00000000"), root, OpenPGPImportOptions{UIF: UIFKeep}); err == nil {
		t.Fatal("wrong admin PIN accepted")
	} else if w := (*ErrWrongPIN)(nil); !errors.As(err, &w) || !w.Admin || w.Retries != 2 {
		t.Fatalf("wrong admin PIN: %v", err)
	}
	if err := c.ImportEd25519([]byte("1234567"), root, OpenPGPImportOptions{UIF: UIFKeep}); !errors.Is(err, errOpenPGPAdminPIN) {
		t.Fatalf("7-byte admin PIN: %v", err)
	}
	opts := OpenPGPImportOptions{UIF: UIFOn, SinglePINUse: true, Created: created}
	if err := c.ImportEd25519([]byte("12345678"), root, opts); err != nil {
		t.Fatalf("import: %v", err)
	}
	if !isEd25519Attrs(f.attrs) || f.uif[0] != UIFOn || f.pw1Valid != 0 {
		t.Fatalf("card state after import: attrs %x uif %x valid %d", f.attrs, f.uif, f.pw1Valid)
	}
	pub := root.Public().(ed25519.PublicKey)
	fp := openPGPFingerprint(pub, uint32(created.Unix()))
	if !bytes.Equal(f.fp, fp[:]) || binary.BigEndian.Uint32(f.ts) != uint32(created.Unix()) {
		t.Error("fingerprint or creation time not written")
	}
	info, err := c.Info()
	if err != nil || !info.SigIsEd25519() || info.Fingerprints[0] != fp {
		t.Fatalf("info: %+v %v", info, err)
	}

	wrong := 0
	signer, err := NewOpenPGPSigner(c, func() ([]byte, error) {
		if wrong > 0 {
			wrong--
			return []byte("000000"), nil
		}
		return []byte("123456"), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(signer.PublicKey(), pub) {
		t.Fatal("public key mismatch")
	}
	// A network document signed through the OpenPGP key verifies like a
	// PIV-signed one (same ed25519-digest-v1 message, ADR-0123).
	id, _ := trust.NewNetworkID(rand.Reader)
	ula, _ := trust.RandomULAPrefix(rand.Reader)
	doc, err := trust.NewDocument(id, trust.DefaultDNSDomain, trust.DefaultIPv4Prefix, ula, testNow, trust.DefaultValidity)
	if err != nil {
		t.Fatal(err)
	}
	env, err := trust.SignDocumentWith(doc, signer)
	if err != nil {
		t.Fatalf("SignDocumentWith: %v", err)
	}
	st := &trust.State{Anchor: trust.Anchor{RootKey: pub, NetworkID: id}}
	if _, err := st.Accept(env, testNow); err != nil {
		t.Fatalf("OpenPGP-signed document rejected: %v", err)
	}
	// Single PIN use: signing without a fresh VERIFY is refused by the card.
	if _, err := c.Sign([]byte("again")); err == nil {
		t.Fatal("second signature without PIN accepted")
	}

	wrong = 1
	_, err = signer.SignMessage([]byte("x"))
	var wp *ErrWrongPIN
	if !errors.As(err, &wp) || wp.Retries != 2 || wp.Admin {
		t.Fatalf("wrong PIN: %v", err)
	}
	if _, err := signer.SignMessage([]byte("x")); err != nil {
		t.Fatalf("right PIN after a wrong one: %v", err)
	}
	wrong = 3
	for range 2 {
		signer.SignMessage([]byte("x"))
	}
	if _, err := signer.SignMessage([]byte("x")); !errors.Is(err, ErrPINBlocked) {
		t.Fatalf("blocked PIN: %v", err)
	}
	if err := c.VerifyPIN([]byte("12345")); !errors.Is(err, errOpenPGPPIN) {
		t.Fatalf("5-byte PIN: %v", err)
	}
	if err := c.VerifyPIN(bytes.Repeat([]byte("1"), 128)); !errors.Is(err, errOpenPGPPIN) {
		t.Fatalf("128-byte PIN: %v", err)
	}
}

func TestOpenPGPWrongPIN63Cx(t *testing.T) {
	f := newFakeOpenPGP(Version{5, 4, 3})
	f.wrong63Cx = true
	c, _ := NewOpenPGPClient(f)
	err := c.VerifyPIN([]byte("999999"))
	var wp *ErrWrongPIN
	if !errors.As(err, &wp) || wp.Retries != 2 {
		t.Fatalf("63C2: %v", err)
	}
	c.VerifyPIN([]byte("999999"))
	if err := c.VerifyPIN([]byte("999999")); !errors.Is(err, ErrPINBlocked) {
		t.Fatalf("63C0: %v", err)
	}
	if err := c.VerifyAdminPIN([]byte("12345678")); err != nil {
		t.Fatal(err)
	}
}

func TestOpenPGPCorruptSignatureCaught(t *testing.T) {
	f := newFakeOpenPGP(Version{5, 4, 3})
	c, _ := NewOpenPGPClient(f)
	_, root, _ := ed25519.GenerateKey(rand.Reader)
	if err := c.ImportEd25519([]byte("12345678"), root, OpenPGPImportOptions{UIF: UIFKeep}); err != nil {
		t.Fatal(err)
	}
	s, err := NewOpenPGPSigner(c, func() ([]byte, error) { return []byte("123456"), nil })
	if err != nil {
		t.Fatal(err)
	}
	f.corruptSig = true
	if _, err := s.SignMessage([]byte("m")); err == nil {
		t.Fatal("corrupt signature returned")
	}
}

func TestOpenPGPOldFirmwareAndFixedUIF(t *testing.T) {
	f := newFakeOpenPGP(Version{5, 2, 2})
	c, _ := NewOpenPGPClient(f)
	_, root, _ := ed25519.GenerateKey(rand.Reader)
	if err := c.ImportEd25519([]byte("12345678"), root, OpenPGPImportOptions{UIF: UIFKeep}); !errors.Is(err, ErrOpenPGPFirmwareTooOld) {
		t.Fatalf("5.2.2: %v", err)
	}
	f = newFakeOpenPGP(Version{})
	f.noVersion = true
	f.uif = []byte{UIFFixed, uifButtonAvailable}
	c, _ = NewOpenPGPClient(f)
	if err := c.ImportEd25519([]byte("12345678"), root, OpenPGPImportOptions{UIF: UIFOff}); err == nil {
		t.Fatal("fixed touch flag was turned off")
	}
	// The key was imported before the flag write failed; the public key
	// still reads back.
	if pub, err := c.SignaturePublicKey(); err != nil || !bytes.Equal(pub, root.Public().(ed25519.PublicKey)) {
		t.Fatalf("pub after failed UIF: %v", err)
	}
}

func TestAutoSelectToken(t *testing.T) {
	_, root, _ := ed25519.GenerateKey(rand.Reader)
	pub := root.Public().(ed25519.PublicKey)
	pinFn := func() ([]byte, error) { return []byte("123456"), nil }

	// 5.4: PIV has no Ed25519, the OpenPGP key is used.
	old := &multiApplet{
		piv:     &fakeToken{t: t, version: Version{5, 4, 3}, pin: []byte("123456"), tries: 3, mgmt: defaultMgmt},
		openpgp: newFakeOpenPGP(Version{5, 4, 3}),
	}
	if k, v, err := ChooseImportBackend(old); err != nil || k != KindOpenPGP || v != (Version{5, 4, 3}) {
		t.Fatalf("import backend 5.4: %v %v %v", k, v, err)
	}
	if _, err := NewToken(old, TokenOptions{PIN: pinFn}); !errors.Is(err, ErrNoEd25519Key) {
		t.Fatalf("empty 5.4 token: %v", err)
	}
	oc, _ := NewOpenPGPClient(old)
	if err := oc.ImportEd25519([]byte("12345678"), root, OpenPGPImportOptions{UIF: UIFKeep}); err != nil {
		t.Fatal(err)
	}
	tok, err := NewToken(old, TokenOptions{PIN: pinFn})
	if err != nil || tok.Kind() != KindOpenPGP || !bytes.Equal(tok.PublicKey(), pub) || tok.Version() != (Version{5, 4, 3}) {
		t.Fatalf("auto 5.4: %v", err)
	}
	msg := []byte("digest message")
	if sig, err := tok.Sign(msg); err != nil || !ed25519.Verify(pub, msg, sig) {
		t.Fatalf("sign 5.4: %v", err)
	}
	if _, err := NewToken(old, TokenOptions{Kind: KindPIV, PIN: pinFn}); !errors.Is(err, ErrNoEd25519Key) {
		t.Fatalf("forced PIV on 5.4: %v", err)
	}
	var _ trust.DigestSigner = tok

	// 5.7 with the key in PIV 9C: PIV wins.
	newer := &multiApplet{
		piv:     &fakeToken{t: t, version: Version{5, 7, 2}, pin: []byte("123456"), tries: 3, mgmt: defaultMgmt, priv: root, pinPolicy: PINPolicyAlways},
		openpgp: newFakeOpenPGP(Version{5, 7, 2}),
	}
	if k, _, err := ChooseImportBackend(newer); err != nil || k != KindPIV {
		t.Fatalf("import backend 5.7: %v %v", k, err)
	}
	tok, err = NewToken(newer, TokenOptions{PIN: pinFn})
	if err != nil || tok.Kind() != KindPIV || !bytes.Equal(tok.PublicKey(), pub) {
		t.Fatalf("auto 5.7: %v", err)
	}
	if sig, err := tok.Sign(msg); err != nil || !ed25519.Verify(pub, msg, sig) {
		t.Fatalf("sign 5.7: %v", err)
	}

	// 5.7 with an empty PIV slot but an OpenPGP key: OpenPGP is used.
	mixed := &multiApplet{
		piv:     &fakeToken{t: t, version: Version{5, 7, 2}, pin: []byte("123456"), tries: 3, mgmt: defaultMgmt},
		openpgp: newFakeOpenPGP(Version{5, 7, 2}),
	}
	oc, _ = NewOpenPGPClient(mixed)
	if err := oc.ImportEd25519([]byte("12345678"), root, OpenPGPImportOptions{UIF: UIFKeep}); err != nil {
		t.Fatal(err)
	}
	if tok, err := NewToken(mixed, TokenOptions{PIN: pinFn}); err != nil || tok.Kind() != KindOpenPGP {
		t.Fatalf("auto 5.7 with OpenPGP key: %v", err)
	}

	// Too old for both.
	ancient := &multiApplet{
		piv:     &fakeToken{t: t, version: Version{4, 3, 7}, mgmt: defaultMgmt},
		openpgp: newFakeOpenPGP(Version{4, 3, 7}),
	}
	if _, _, err := ChooseImportBackend(ancient); !errors.Is(err, ErrOpenPGPFirmwareTooOld) {
		t.Fatalf("4.3: %v", err)
	}
}

func TestProbeTransportNeedsNoPIN(t *testing.T) {
	_, root, _ := ed25519.GenerateKey(rand.Reader)
	pub := root.Public().(ed25519.PublicKey)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	m := &multiApplet{
		piv:     &fakeToken{t: t, version: Version{5, 4, 3}, mgmt: defaultMgmt},
		openpgp: newFakeOpenPGP(Version{5, 4, 3}),
	}
	r := ProbeTransport(m, PresenceOptions{Keys: []ed25519.PublicKey{other, pub}})
	if !r.Present || r.PublicKey != nil || r.Admin() {
		t.Fatalf("empty token: %+v", r)
	}
	oc, _ := NewOpenPGPClient(m)
	oc.ImportEd25519([]byte("12345678"), root, OpenPGPImportOptions{UIF: UIFKeep})
	m.sent = nil
	r = ProbeTransport(m, PresenceOptions{Keys: []ed25519.PublicKey{other, pub}})
	if r.Kind != KindOpenPGP || r.Match != 1 || !r.Admin() || r.Version != (Version{5, 4, 3}) {
		t.Fatalf("probe: %+v", r)
	}
	for _, a := range m.sent {
		if a[1] == insVerify || a[1] == insPSO || a[1] == insPutData || a[1] == insPutDataOdd || a[1] == insImportKey {
			t.Fatalf("probe sent %x", a)
		}
	}
	if r := ProbeTransport(m, PresenceOptions{Keys: []ed25519.PublicKey{other}}); r.Admin() || r.PublicKey == nil {
		t.Fatalf("foreign key matched: %+v", r)
	}
}

func TestProberCachesUntilReadersChange(t *testing.T) {
	readers := []string{"Yubico YubiKey OTP+FIDO+CCID 0"}
	now := time.Unix(1000, 0)
	probes := 0
	p := &Prober{
		now:  func() time.Time { return now },
		list: func() ([]string, error) { return readers, nil },
		probe: func(_ context.Context, rs []string, _ PresenceOptions) (PresenceResult, error) {
			probes++
			return PresenceResult{Present: len(rs) > 0, Match: 0}, nil
		},
	}
	ctx := context.Background()
	for range 5 {
		if r, err := p.Check(ctx); err != nil || !r.Admin() {
			t.Fatal(r, err)
		}
		now = now.Add(2 * time.Second)
	}
	if probes != 1 {
		t.Fatalf("probes = %d, want 1", probes)
	}
	readers = nil
	p.Check(ctx)
	if probes != 2 {
		t.Fatal("reader removal not probed")
	}
	now = now.Add(31 * time.Second)
	p.Check(ctx)
	if probes != 3 {
		t.Fatal("max age not honoured")
	}
	p.Invalidate()
	p.Check(ctx)
	if probes != 4 {
		t.Fatal("invalidate ignored")
	}
}

func TestPickAndMatchReaders(t *testing.T) {
	rs := []string{"Alcor Micro USB Smart Card Reader 0", "Yubico YubiKey OTP+FIDO+CCID 0", "Yubico YubiKey OTP+FIDO+CCID 01"}
	if r, err := pickReader(rs, ""); err != nil || r != rs[1] {
		t.Errorf("default: %q %v", r, err)
	}
	if r, err := pickReader(rs, "yubico yubikey otp+fido+ccid 01"); err != nil || r != rs[2] {
		t.Errorf("exact: %q %v", r, err)
	}
	if _, err := pickReader(rs, "nitrokey"); err == nil {
		t.Error("no match accepted")
	}
	if got := matchingReaders(rs, ""); len(got) != 2 {
		t.Errorf("matching: %v", got)
	}
	if got := matchingReaders(nil, ""); got != nil {
		t.Errorf("none: %v", got)
	}
}

func FuzzParseApplicationData(f *testing.F) {
	fk := newFakeOpenPGP(Version{5, 4, 3})
	f.Add(fk.appData())
	inner, _ := unwrapTLV(fk.appData(), doAppRelated)
	f.Add(inner)
	f.Add(append(mustHexS("7f49228620"), make([]byte, 32)...))
	f.Add(mustHexS("6e00"))
	f.Fuzz(func(t *testing.T, data []byte) {
		info, err := parseApplicationData(data)
		if err == nil {
			if len(info.AID) != 16 {
				t.Fatal("accepted a bad AID")
			}
			if info.PWStatus.PW1MaxLen > 127 || info.PWStatus.PW3MaxLen > 127 {
				t.Fatal("PIN length out of range")
			}
		}
		if pub, err := parseOpenPGPPublicKey(data); err == nil && len(pub) != ed25519.PublicKeySize {
			t.Fatal("bad public key length")
		}
		_, _ = parsePWStatus(data)
	})
}
