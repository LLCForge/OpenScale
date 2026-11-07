package piv

import (
	"bytes"
	"crypto/aes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/trust"
)

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAPDUEncodingVectors(t *testing.T) {
	cases := []struct {
		name string
		cmd  Command
		want string
	}{
		{"select piv", Command{INS: insSelect, P1: 0x04, Data: pivAID}, "00a404000ba000000308000010000100"},
		{"get version", Command{INS: insGetVersion}, "00fd0000"},
		{"get metadata 9c", Command{INS: insGetMetadata, P2: SlotSignature}, "00f7009c"},
		{"get response", Command{INS: insGetResp, Le: 256}, "00c0000000"},
		{"le 16", Command{INS: insGetResp, Le: 16}, "00c0000010"},
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
	pin, err := encodePIN([]byte("123456"))
	if err != nil {
		t.Fatal(err)
	}
	parts, _ := Command{INS: insVerify, P2: 0x80, Data: pin}.Encode()
	if got := hex.EncodeToString(parts[0]); got != "0020008008313233343536ffff" {
		t.Errorf("verify pin: %s", got)
	}
	sign, err := encodeSign([]byte("abc"))
	if err != nil {
		t.Fatal(err)
	}
	parts, _ = Command{INS: insAuthenticate, P1: AlgEd25519, P2: SlotSignature, Data: sign}.Encode()
	if got := hex.EncodeToString(parts[0]); got != "0087e09c097c0782008103616263" {
		t.Errorf("sign: %s", got)
	}
	seed := bytes.Repeat([]byte{0x11}, 32)
	imp, err := encodeImportEd25519(seed, PINPolicyAlways, TouchPolicyAlways)
	if err != nil {
		t.Fatal(err)
	}
	parts, _ = Command{INS: insImportKey, P1: AlgEd25519, P2: SlotSignature, Data: imp}.Encode()
	want := "00fee09c28" + "0720" + hex.EncodeToString(seed) + "aa0103" + "ab0102"
	if got := hex.EncodeToString(parts[0]); got != want {
		t.Errorf("import: %s", got)
	}
	if _, err := encodePIN([]byte("12345")); err == nil {
		t.Error("5-digit PIN accepted")
	}
	if _, err := encodePIN([]byte("123456789")); err == nil {
		t.Error("9-digit PIN accepted")
	}
}

func TestAPDUCommandChaining(t *testing.T) {
	data := bytes.Repeat([]byte{0xAB}, 600)
	parts, err := Command{INS: 0xDB, P1: 0x3F, P2: 0xFF, Data: data}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) != 3 {
		t.Fatalf("parts = %d", len(parts))
	}
	for i, p := range parts {
		chained := p[0]&claChain != 0
		if chained != (i < 2) {
			t.Errorf("part %d chaining bit = %v", i, chained)
		}
	}
	if parts[0][4] != 255 || parts[1][4] != 255 || parts[2][4] != 90 {
		t.Errorf("lengths %d %d %d", parts[0][4], parts[1][4], parts[2][4])
	}
	if _, err := (Command{CLA: 0x10}).Encode(); err == nil {
		t.Error("caller chaining bit accepted")
	}
}

func TestTLVLengthForms(t *testing.T) {
	for _, n := range []int{0, 1, 0x7F, 0x80, 0xFF, 0x100, 0x1234} {
		v := bytes.Repeat([]byte{7}, n)
		enc := tlv(0x7F49, v)
		list, err := parseTLVs(enc)
		if err != nil || len(list) != 1 || list[0].Tag != 0x7F49 || !bytes.Equal(list[0].Value, v) {
			t.Fatalf("length %d: %v", n, err)
		}
	}
	if got := hex.EncodeToString(tlv(0x81, bytes.Repeat([]byte{0}, 0x80))[:3]); got != "818180" {
		t.Errorf("long form: %s", got)
	}
	for _, bad := range []string{"7c", "7c05", "7c8301000000", "5f", "7c8101", "9f8001"} {
		if _, err := parseTLVs(mustHex(t, bad)); err == nil {
			t.Errorf("%s parsed", bad)
		}
	}
}

func TestParseMetadata(t *testing.T) {
	pub := bytes.Repeat([]byte{0x42}, 32)
	data := mustHex(t, "0101e0"+"02020302"+"030102"+"0422"+"8620"+hex.EncodeToString(pub))
	m, err := parseMetadata(data)
	if err != nil {
		t.Fatal(err)
	}
	if m.Algorithm != AlgEd25519 || m.PINPolicy != PINPolicyAlways || m.TouchPolicy != TouchPolicyAlways || !m.Imported || !bytes.Equal(m.PublicKey, pub) {
		t.Fatalf("got %+v", m)
	}
	if _, err := parseMetadata(mustHex(t, "0302")); err == nil {
		t.Error("truncated metadata parsed")
	}
}

func TestStatusWords(t *testing.T) {
	if err := pinError(&StatusError{SW: 0x63C2}); err == nil {
		t.Fatal("nil")
	} else if w := (*ErrWrongPIN)(nil); !errors.As(err, &w) || w.Retries != 2 {
		t.Errorf("63C2: %v", err)
	}
	if !errors.Is(pinError(&StatusError{SW: 0x6983}), ErrPINBlocked) {
		t.Error("6983 is not blocked")
	}
	if v := (Version{5, 7, 1}); !v.AtLeast(MinEd25519Firmware) || (Version{5, 4, 3}).AtLeast(MinEd25519Firmware) || !(Version{6, 0, 0}).AtLeast(MinEd25519Firmware) {
		t.Error("version comparison")
	}
}

// fakeToken emulates the PIV applet answers this package relies on. It is
// a test double for encoding and decoding, not a reference implementation.
type fakeToken struct {
	t         *testing.T
	version   Version
	pin       []byte
	tries     int
	verified  bool
	mgmt      []byte
	witness   []byte
	authed    bool
	priv      ed25519.PrivateKey
	pending   []byte // 61xx continuation data
	chunk     int    // answer at most this many bytes per APDU (0 = all)
	chainBuf  []byte
	pinPolicy byte
}

func (f *fakeToken) Transmit(apdu []byte) ([]byte, error) {
	if len(apdu) < 4 {
		return []byte{0x67, 0x00}, nil
	}
	cla, ins, p1, p2 := apdu[0], apdu[1], apdu[2], apdu[3]
	var data []byte
	if len(apdu) > 5 {
		data = apdu[5 : 5+int(apdu[4])]
	}
	if cla&claChain != 0 {
		f.chainBuf = append(f.chainBuf, data...)
		return []byte{0x90, 0x00}, nil
	}
	if f.chainBuf != nil {
		data = append(f.chainBuf, data...)
		f.chainBuf = nil
	}
	ok := func(d []byte) ([]byte, error) {
		if f.chunk > 0 && len(d) > f.chunk {
			f.pending = d[f.chunk:]
			rest := len(f.pending)
			if rest > 255 {
				rest = 0
			}
			return append(append([]byte(nil), d[:f.chunk]...), 0x61, byte(rest)), nil
		}
		return append(append([]byte(nil), d...), 0x90, 0x00), nil
	}
	sw := func(s uint16) ([]byte, error) { return []byte{byte(s >> 8), byte(s)}, nil }
	switch ins {
	case insGetResp:
		d := f.pending
		f.pending = nil
		return ok(d)
	case insSelect:
		if !bytes.Equal(data, pivAID) {
			return sw(swFileNotFound)
		}
		return ok(nil)
	case insGetVersion:
		return ok([]byte{f.version.Major, f.version.Minor, f.version.Patch})
	case insVerify:
		if f.tries == 0 {
			return sw(swAuthBlocked)
		}
		want, _ := encodePIN(f.pin)
		if !bytes.Equal(data, want) {
			f.tries--
			return sw(0x63C0 | uint16(f.tries))
		}
		f.tries, f.verified = 3, true
		return ok(nil)
	case insGetMetadata:
		if f.priv == nil || p2 != SlotSignature {
			return sw(swFileNotFound)
		}
		pub := f.priv.Public().(ed25519.PublicKey)
		return ok(append(append(tlv(tagMetaAlgorithm, []byte{AlgEd25519}), tlv(tagMetaPolicy, []byte{f.pinPolicy, TouchPolicyNever})...),
			append(tlv(tagMetaOrigin, []byte{2}), tlv(tagMetaPublicKey, tlv(tagECPoint, pub))...)...))
	case insAuthenticate:
		if p2 == SlotManagement && p1 == AlgAES192 {
			block, _ := aes.NewCipher(f.mgmt)
			if f.witness == nil {
				f.witness = make([]byte, 16)
				rand.Read(f.witness)
				enc := make([]byte, 16)
				block.Encrypt(enc, f.witness)
				return ok(tlv(tagDynAuth, tlv(tagWitness, enc)))
			}
			inner, err := unwrapTLV(data, tagDynAuth)
			if err != nil {
				return sw(swWrongData)
			}
			list, _ := parseTLVs(inner)
			w, _ := findTLV(list, tagWitness)
			ch, _ := findTLV(list, tagChallenge)
			wantW := f.witness
			f.witness = nil
			if !bytes.Equal(w, wantW) || len(ch) != 16 {
				return sw(swSecurityStatus)
			}
			f.authed = true
			enc := make([]byte, 16)
			block.Encrypt(enc, ch)
			return ok(tlv(tagDynAuth, tlv(tagResponse, enc)))
		}
		if p1 != AlgEd25519 || p2 != SlotSignature || f.priv == nil {
			return sw(swIncorrectParams)
		}
		if f.pinPolicy == PINPolicyAlways && !f.verified {
			return sw(swSecurityStatus)
		}
		f.verified = false
		inner, err := unwrapTLV(data, tagDynAuth)
		if err != nil {
			return sw(swWrongData)
		}
		list, _ := parseTLVs(inner)
		msg, _ := findTLV(list, tagChallenge)
		return ok(tlv(tagDynAuth, tlv(tagResponse, ed25519.Sign(f.priv, msg))))
	case insImportKey:
		if !f.authed {
			return sw(swSecurityStatus)
		}
		if !f.version.AtLeast(MinEd25519Firmware) || p1 != AlgEd25519 {
			return sw(swIncorrectParams)
		}
		list, err := parseTLVs(data)
		if err != nil {
			return sw(swWrongData)
		}
		seed, _ := findTLV(list, tagEd25519Private)
		if pp, ok := findTLV(list, tagPINPolicy); ok {
			f.pinPolicy = pp[0]
		}
		f.priv = ed25519.NewKeyFromSeed(seed)
		return ok(nil)
	}
	return sw(swInsNotSupported)
}

var defaultMgmt = mustHexS("010203040506070801020304050607080102030405060708")

func mustHexS(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestFakeTokenImportAndSign(t *testing.T) {
	tok := &fakeToken{t: t, version: Version{5, 7, 2}, pin: []byte("654321"), tries: 3, mgmt: defaultMgmt, chunk: 20}
	c, err := NewClient(tok)
	if err != nil {
		t.Fatal(err)
	}
	_, root, _ := ed25519.GenerateKey(rand.Reader)
	if err := c.ImportEd25519(SlotSignature, root, PINPolicyAlways, TouchPolicyNever); err == nil {
		t.Fatal("import without management key accepted")
	}
	if err := c.AuthenticateManagementKey(ManagementKey{Algorithm: AlgAES192, Key: bytes.Repeat([]byte{9}, 24)}, nil); !errors.Is(err, ErrManagementAuth) {
		t.Fatalf("wrong management key: %v", err)
	}
	if err := c.AuthenticateManagementKey(ManagementKey{Algorithm: AlgAES192, Key: defaultMgmt}, nil); err != nil {
		t.Fatalf("management key: %v", err)
	}
	if err := c.ImportEd25519(SlotSignature, root, PINPolicyAlways, TouchPolicyNever); err != nil {
		t.Fatalf("import: %v", err)
	}

	wrong := 0
	signer, err := NewSigner(c, SlotSignature, func() ([]byte, error) {
		if wrong > 0 {
			wrong--
			return []byte("000000"), nil
		}
		return []byte("654321"), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(signer.PublicKey(), root.Public().(ed25519.PublicKey)) {
		t.Fatal("public key mismatch")
	}
	// A whole network document signed through the token verifies like any
	// other root signature (ADR-0123).
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
	st := &trust.State{Anchor: trust.Anchor{RootKey: root.Public().(ed25519.PublicKey), NetworkID: id}}
	if _, err := st.Accept(env, testNow); err != nil {
		t.Fatalf("token-signed document rejected: %v", err)
	}

	wrong = 1
	_, err = signer.SignMessage([]byte("x"))
	var wp *ErrWrongPIN
	if !errors.As(err, &wp) || wp.Retries != 2 {
		t.Fatalf("wrong PIN: %v", err)
	}
	wrong = 3
	for range 2 {
		signer.SignMessage([]byte("x"))
	}
	if _, err := signer.SignMessage([]byte("x")); !errors.Is(err, ErrPINBlocked) {
		t.Fatalf("blocked PIN: %v", err)
	}
}

func TestOldFirmwareRefused(t *testing.T) {
	tok := &fakeToken{t: t, version: Version{5, 4, 3}, pin: []byte("123456"), tries: 3, mgmt: defaultMgmt}
	c, err := NewClient(tok)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.CheckEd25519Support(); !errors.Is(err, ErrFirmwareTooOld) {
		t.Fatalf("got %v", err)
	}
	if _, err := NewSigner(c, SlotSignature, nil); !errors.Is(err, ErrFirmwareTooOld) {
		t.Fatalf("signer on old firmware: %v", err)
	}
}

func FuzzParseTLVs(f *testing.F) {
	f.Add(mustHexS("7c0a800811223344556677887f"))
	f.Add(append(mustHexS("0101e004228620"), make([]byte, 32)...))
	f.Add(mustHexS("5fc1818100"))
	f.Fuzz(func(t *testing.T, data []byte) {
		list, err := parseTLVs(data)
		if err != nil {
			return
		}
		// Re-encoding what was parsed yields a parseable sequence of the
		// same elements (encoding is canonical, input may not be).
		var enc []byte
		for _, e := range list {
			enc = appendTLV(enc, e.Tag, e.Value)
		}
		again, err := parseTLVs(enc)
		if err != nil || len(again) != len(list) {
			t.Fatalf("re-encoded TLVs do not parse: %v", err)
		}
		for i := range list {
			if again[i].Tag != list[i].Tag || !bytes.Equal(again[i].Value, list[i].Value) {
				t.Fatal("re-encoded TLVs differ")
			}
		}
		_, _ = parseMetadata(data)
		_, _ = dynAuthValue(data, tagResponse)
	})
}

func FuzzParseResponse(f *testing.F) {
	f.Add([]byte{0x90, 0x00})
	f.Add([]byte{0x01, 0x61, 0x10})
	f.Fuzz(func(t *testing.T, raw []byte) {
		r, err := ParseResponse(raw)
		if err != nil {
			if len(raw) >= 2 {
				t.Fatal("rejected a response with a status word")
			}
			return
		}
		if len(r.Data) != len(raw)-2 {
			t.Fatal("data length")
		}
	})
}

var testNow = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
