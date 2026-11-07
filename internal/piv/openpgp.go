package piv

import (
	"crypto/ed25519"
	"crypto/sha1" // OpenPGP v4 fingerprint (RFC 4880 12.2): an identifier, not a security check
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// OpenPGP card application (OpenPGP Smart Card Application 3.4) as the
// YubiKey implements it (ADR-0171). YubiKey firmware 5.2.3 and newer sign
// with Ed25519 in the OpenPGP application, which covers the 5.x keys that
// cannot use Ed25519 in PIV (5.7+). The signature is pure EdDSA over the
// bytes sent, exactly like the PIV slot, so trust.DigestMessage works for
// both.

// openPGPAID is the application identifier prefix (RID D2 76 00 01 24,
// PIX 01); SELECT by this partial AID picks the OpenPGP application.
var openPGPAID = []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}

// Instructions used only by the OpenPGP application.
const (
	insGetData        = 0xCA
	insPutData        = 0xDA
	insPutDataOdd     = 0xDB
	insPSO            = 0x2A
	insGenerateAsym   = 0x47
	insOpenPGPVersion = 0xF1 // Yubico extension: firmware version
)

// Password references for VERIFY.
const (
	pwSign  = 0x81 // PW1, for PSO:COMPUTE DIGITAL SIGNATURE
	pwOther = 0x82 // PW1, for decipher and other operations
	pwAdmin = 0x83 // PW3, the admin PIN
)

// Data objects.
const (
	doAppRelated    = 0x6E
	doDiscretionary = 0x73
	doAID           = 0x4F
	doAlgoSig       = 0xC1
	doPWStatus      = 0xC4
	doFingerprints  = 0xC5
	doFPSig         = 0xC7
	doTimeSig       = 0xCE
	doUIFSig        = 0xD6 // Yubico/3.4: user interaction flag of the signature key
	doCRTSig        = 0xB6
	doPubKey        = 0x7F49
	doPubPoint      = 0x86
	doExtHeader     = 0x4D
	doPrivTemplate  = 0x7F48
	doPrivConcat    = 0x5F48
	doPrivEdDSA     = 0x92

	swDataNotFound = 0x6A88
)

// algoEdDSA is the OpenPGP algorithm ID 22 (EdDSA); the Ed25519 curve OID
// is 1.3.6.1.4.1.11591.15.1.
const algoEdDSA = 0x16

var ed25519OID = []byte{0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01}

// ed25519AlgoAttrs is the algorithm attributes DO value for Ed25519.
var ed25519AlgoAttrs = append([]byte{algoEdDSA}, ed25519OID...)

// MinOpenPGPEd25519Firmware is the first YubiKey firmware that signs with
// Ed25519 in the OpenPGP application.
var MinOpenPGPEd25519Firmware = Version{5, 2, 3}

// OpenPGP errors.
var (
	ErrOpenPGPFirmwareTooOld = errors.New("token firmware does not support Ed25519 in OpenPGP (5.2.3 or newer is required)")
	ErrNoSignatureKey        = errors.New("the token holds no signature key")
	ErrNotEd25519Key         = errors.New("the signature key is not Ed25519")
	errOpenPGPPIN            = errors.New("OpenPGP PIN must be 6-127 bytes")
	errOpenPGPAdminPIN       = errors.New("OpenPGP admin PIN must be 8-127 bytes")
)

// UIF (user interaction flag, "touch policy") values of DO D6.
const (
	UIFOff             = 0x00
	UIFOn              = 0x01
	UIFFixed           = 0x02 // cannot be turned off without a reset
	UIFCached          = 0x03
	UIFCachedFixed     = 0x04
	UIFKeep            = 0xFF // ImportEd25519: do not change the flag
	uifButtonAvailable = 0x20
)

// PWStatus is the PW status bytes DO (C4).
type PWStatus struct {
	// PW1ValidMultiple is false when one VERIFY 81 allows one signature
	// only (the safe default, comparable to PIV PIN policy "always").
	PW1ValidMultiple bool
	PW1MaxLen        int
	RCMaxLen         int
	PW3MaxLen        int
	PW1Retries       int
	RCRetries        int
	PW3Retries       int
}

func parsePWStatus(v []byte) (PWStatus, error) {
	if len(v) < 7 {
		return PWStatus{}, errors.New("malformed PW status bytes")
	}
	return PWStatus{
		PW1ValidMultiple: v[0] != 0,
		PW1MaxLen:        int(v[1] & 0x7F),
		RCMaxLen:         int(v[2]),
		PW3MaxLen:        int(v[3] & 0x7F),
		PW1Retries:       int(v[4]),
		RCRetries:        int(v[5]),
		PW3Retries:       int(v[6]),
	}, nil
}

// OpenPGPInfo is the parsed application related data (DO 6E).
type OpenPGPInfo struct {
	AID          []byte
	SpecVersion  [2]byte // from the AID
	Manufacturer uint16  // 0x0006 is Yubico
	Serial       uint32
	SigAlgorithm []byte // DO C1
	PWStatus     PWStatus
	// Fingerprints are the signature, decryption and authentication key
	// fingerprints (DO C5); all-zero means "no key".
	Fingerprints [3][20]byte
	// SigUIF is the signature key's touch flag; HasUIF is false when the
	// card does not report one.
	SigUIF byte
	HasUIF bool
}

// SigIsEd25519 reports whether the signature key attributes name Ed25519.
func (i OpenPGPInfo) SigIsEd25519() bool { return isEd25519Attrs(i.SigAlgorithm) }

func isEd25519Attrs(a []byte) bool {
	// An optional trailing 0xFF announces "import with public key".
	if len(a) == len(ed25519AlgoAttrs)+1 && a[len(a)-1] == 0xFF {
		a = a[:len(a)-1]
	}
	return subtle.ConstantTimeCompare(a, ed25519AlgoAttrs) == 1
}

// parseApplicationData parses DO 6E; the card may or may not wrap the
// value in the 6E tag itself.
func parseApplicationData(data []byte) (OpenPGPInfo, error) {
	list, err := parseTLVs(data)
	if err != nil {
		return OpenPGPInfo{}, err
	}
	if len(list) == 1 && list[0].Tag == doAppRelated {
		if list, err = parseTLVs(list[0].Value); err != nil {
			return OpenPGPInfo{}, err
		}
	}
	var info OpenPGPInfo
	aid, ok := findTLV(list, doAID)
	if !ok || len(aid) != 16 {
		return OpenPGPInfo{}, errors.New("application data without a valid AID")
	}
	info.AID = append([]byte(nil), aid...)
	info.SpecVersion = [2]byte{aid[6], aid[7]}
	info.Manufacturer = binary.BigEndian.Uint16(aid[8:10])
	info.Serial = binary.BigEndian.Uint32(aid[10:14])
	disc, ok := findTLV(list, doDiscretionary)
	if !ok {
		return OpenPGPInfo{}, errors.New("application data without discretionary data objects")
	}
	dlist, err := parseTLVs(disc)
	if err != nil {
		return OpenPGPInfo{}, err
	}
	if a, ok := findTLV(dlist, doAlgoSig); ok {
		info.SigAlgorithm = append([]byte(nil), a...)
	}
	pw, ok := findTLV(dlist, doPWStatus)
	if !ok {
		return OpenPGPInfo{}, errors.New("application data without PW status bytes")
	}
	if info.PWStatus, err = parsePWStatus(pw); err != nil {
		return OpenPGPInfo{}, err
	}
	if fp, ok := findTLV(dlist, doFingerprints); ok {
		if len(fp) < 60 {
			return OpenPGPInfo{}, errors.New("malformed fingerprints")
		}
		for i := range 3 {
			copy(info.Fingerprints[i][:], fp[i*20:(i+1)*20])
		}
	}
	if u, ok := findTLV(dlist, doUIFSig); ok && len(u) >= 1 {
		info.SigUIF, info.HasUIF = u[0], true
	}
	return info, nil
}

// parseOpenPGPPublicKey extracts an Ed25519 point from a 7F49 template.
func parseOpenPGPPublicKey(data []byte) (ed25519.PublicKey, error) {
	inner, err := unwrapTLV(data, doPubKey)
	if err != nil {
		return nil, err
	}
	list, err := parseTLVs(inner)
	if err != nil {
		return nil, err
	}
	pt, ok := findTLV(list, doPubPoint)
	if !ok {
		return nil, errors.New("public key template without a point")
	}
	// Some cards prefix the native point with 0x40 as OpenPGP does.
	if len(pt) == ed25519.PublicKeySize+1 && pt[0] == 0x40 {
		pt = pt[1:]
	}
	if len(pt) != ed25519.PublicKeySize {
		return nil, ErrNotEd25519Key
	}
	return ed25519.PublicKey(append([]byte(nil), pt...)), nil
}

// OpenPGPClient runs OpenPGP card commands over a transport. Like Client it
// is not safe for concurrent use.
type OpenPGPClient struct {
	t Transport
}

// NewOpenPGPClient selects the OpenPGP application on t.
func NewOpenPGPClient(t Transport) (*OpenPGPClient, error) {
	if _, err := transmit(t, Command{INS: insSelect, P1: 0x04, Data: openPGPAID}); err != nil {
		return nil, fmt.Errorf("select OpenPGP application: %w", err)
	}
	return &OpenPGPClient{t: t}, nil
}

// Version returns the YubiKey firmware version. ok is false when the card
// does not implement the Yubico extension (a non-Yubico card).
func (c *OpenPGPClient) Version() (v Version, ok bool, err error) {
	data, err := transmit(c.t, Command{INS: insOpenPGPVersion, Le: 256})
	if err != nil {
		var se *StatusError
		if errors.As(err, &se) {
			return Version{}, false, nil
		}
		return Version{}, false, err
	}
	if len(data) != 3 {
		return Version{}, false, errors.New("unexpected version answer")
	}
	return Version{data[0], data[1], data[2]}, true, nil
}

// CheckEd25519Support fails for a YubiKey older than 5.2.3. A card without
// the version extension is allowed; the algorithm attribute write is then
// the check.
func (c *OpenPGPClient) CheckEd25519Support() (Version, error) {
	v, ok, err := c.Version()
	if err != nil {
		return Version{}, err
	}
	if ok && !v.AtLeast(MinOpenPGPEd25519Firmware) {
		return v, fmt.Errorf("%w (found %s)", ErrOpenPGPFirmwareTooOld, v)
	}
	return v, nil
}

func (c *OpenPGPClient) getData(tag uint16) ([]byte, error) {
	return transmit(c.t, Command{INS: insGetData, P1: byte(tag >> 8), P2: byte(tag), Le: 256})
}

func (c *OpenPGPClient) putData(tag uint16, value []byte) error {
	_, err := transmit(c.t, Command{INS: insPutData, P1: byte(tag >> 8), P2: byte(tag), Data: value})
	return err
}

// Info reads the application related data.
func (c *OpenPGPClient) Info() (OpenPGPInfo, error) {
	data, err := c.getData(doAppRelated)
	if err != nil {
		return OpenPGPInfo{}, err
	}
	info, err := parseApplicationData(data)
	if err != nil {
		return OpenPGPInfo{}, err
	}
	if !info.HasUIF {
		// Older firmware keeps the flag outside DO 6E.
		if u, err := c.getData(doUIFSig); err == nil && len(u) >= 1 {
			info.SigUIF, info.HasUIF = u[0], true
		}
	}
	return info, nil
}

// PWStatus reads DO C4.
func (c *OpenPGPClient) PWStatus() (PWStatus, error) {
	data, err := c.getData(doPWStatus)
	if err != nil {
		return PWStatus{}, err
	}
	// Some cards answer with the C4 tag around the value.
	if v, err := unwrapTLV(data, doPWStatus); err == nil {
		data = v
	}
	return parsePWStatus(data)
}

// SignatureUIF reads the signature key's touch flag (DO D6).
func (c *OpenPGPClient) SignatureUIF() (byte, error) {
	data, err := c.getData(doUIFSig)
	if err != nil {
		return 0, err
	}
	if len(data) < 1 {
		return 0, errors.New("malformed UIF")
	}
	return data[0], nil
}

// VerifyPIN verifies PW1 for signing. A wrong PIN returns *ErrWrongPIN
// with the tries left (read from DO C4 when the card answers 6982, as the
// YubiKey does).
func (c *OpenPGPClient) VerifyPIN(pin []byte) error { return c.verify(pwSign, pin) }

// VerifyAdminPIN verifies PW3.
func (c *OpenPGPClient) VerifyAdminPIN(pin []byte) error { return c.verify(pwAdmin, pin) }

func (c *OpenPGPClient) verify(ref byte, pin []byte) error {
	minLen, errLen := 6, errOpenPGPPIN
	if ref == pwAdmin {
		minLen, errLen = 8, errOpenPGPAdminPIN
	}
	if len(pin) < minLen || len(pin) > 127 {
		return errLen
	}
	data := append([]byte(nil), pin...)
	defer clear(data)
	_, err := transmit(c.t, Command{INS: insVerify, P2: ref, Data: data})
	if err == nil {
		return nil
	}
	var se *StatusError
	if !errors.As(err, &se) {
		return err
	}
	admin := ref == pwAdmin
	switch {
	case se.SW == swAuthBlocked:
		return blockedErr(admin)
	case se.SW&0xFFF0 == 0x63C0:
		if se.SW&0x0F == 0 {
			return blockedErr(admin)
		}
		return &ErrWrongPIN{Retries: int(se.SW & 0x0F), Admin: admin}
	case se.SW == swSecurityStatus || se.SW == swWrongData:
		st, serr := c.PWStatus()
		if serr != nil {
			return &ErrWrongPIN{Retries: -1, Admin: admin}
		}
		left := st.PW1Retries
		if admin {
			left = st.PW3Retries
		}
		if left == 0 {
			return blockedErr(admin)
		}
		return &ErrWrongPIN{Retries: left, Admin: admin}
	}
	return err
}

// ErrAdminPINBlocked is returned when PW3 is blocked; only a full OpenPGP
// reset clears it.
var ErrAdminPINBlocked = errors.New("admin PIN is blocked; the OpenPGP application must be reset")

func blockedErr(admin bool) error {
	if admin {
		return ErrAdminPINBlocked
	}
	return ErrPINBlocked
}

// SignaturePublicKey reads the signature key's public key without a PIN
// (GENERATE ASYMMETRIC KEY PAIR, P1 81 "read").
func (c *OpenPGPClient) SignaturePublicKey() (ed25519.PublicKey, error) {
	data, err := transmit(c.t, Command{INS: insGenerateAsym, P1: 0x81, Data: []byte{doCRTSig, 0x00}, Le: 256})
	if err != nil {
		var se *StatusError
		if errors.As(err, &se) && (se.SW == swDataNotFound || se.SW == swFileNotFound) {
			return nil, ErrNoSignatureKey
		}
		return nil, err
	}
	if len(data) == 0 {
		return nil, ErrNoSignatureKey
	}
	return parseOpenPGPPublicKey(data)
}

// encodeOpenPGPImportEd25519 builds the extended header list (DO 4D) for
// an Ed25519 signature key.
func encodeOpenPGPImportEd25519(seed []byte) ([]byte, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("invalid ed25519 seed")
	}
	// 7F48 lists tag and length of each key part, without values.
	body := []byte{doCRTSig, 0x00}
	body = appendTLV(body, doPrivTemplate, []byte{doPrivEdDSA, byte(len(seed))})
	body = appendTLV(body, doPrivConcat, seed)
	out := tlv(doExtHeader, body)
	clear(body)
	return out, nil
}

// openPGPFingerprint returns the OpenPGP v4 fingerprint of an Ed25519 key
// (legacy EdDSA, RFC 4880bis) created at ts, which is what GnuPG would
// show for the same key. It labels the card's key; trust does not rely on
// it, the public key itself is compared.
func openPGPFingerprint(pub ed25519.PublicKey, ts uint32) [20]byte {
	body := []byte{0x04}
	body = binary.BigEndian.AppendUint32(body, ts)
	body = append(body, algoEdDSA, byte(len(ed25519OID)))
	body = append(body, ed25519OID...)
	body = append(body, 0x01, 0x07, 0x40) // MPI of 263 bits: 0x40 || point
	body = append(body, pub...)
	h := sha1.New()
	h.Write([]byte{0x99, byte(len(body) >> 8), byte(len(body))})
	h.Write(body)
	var fp [20]byte
	copy(fp[:], h.Sum(nil))
	return fp
}

// OpenPGPImportOptions tunes ImportEd25519.
type OpenPGPImportOptions struct {
	// UIF sets the signature touch flag; UIFKeep leaves it.
	UIF byte
	// SinglePINUse makes one VERIFY allow one signature (recommended).
	SinglePINUse bool
	// Created is the key creation time stored with the fingerprint; zero
	// means now.
	Created time.Time
}

// ImportEd25519 imports priv as the OpenPGP signature key. The key is never
// generated on the card, so the passphrase-sealed root.key stays a working
// backup (ADR-0011, ADR-0123). It verifies PW3, switches the signature
// algorithm to Ed25519 when needed (which clears an existing signature key),
// writes the key, its fingerprint and creation time, applies the options
// and reads the public key back to compare.
func (c *OpenPGPClient) ImportEd25519(adminPIN []byte, priv ed25519.PrivateKey, o OpenPGPImportOptions) error {
	if len(priv) != ed25519.PrivateKeySize {
		return errors.New("invalid ed25519 private key")
	}
	// Checked before anything is written: a bad flag found after the key
	// was imported would leave a key with an unintended touch policy.
	if o.UIF != UIFKeep && o.UIF > UIFCachedFixed {
		return errors.New("invalid touch flag")
	}
	if _, err := c.CheckEd25519Support(); err != nil {
		return err
	}
	if err := c.VerifyAdminPIN(adminPIN); err != nil {
		return err
	}
	attrs, err := c.getData(doAlgoSig)
	if err != nil {
		return fmt.Errorf("read algorithm attributes: %w", err)
	}
	if v, err := unwrapTLV(attrs, doAlgoSig); err == nil {
		attrs = v
	}
	if !isEd25519Attrs(attrs) {
		if err := c.putData(doAlgoSig, ed25519AlgoAttrs); err != nil {
			return fmt.Errorf("set Ed25519 algorithm attributes: %w", err)
		}
	}
	seed := priv.Seed()
	defer clear(seed)
	data, err := encodeOpenPGPImportEd25519(seed)
	if err != nil {
		return err
	}
	defer clear(data)
	if _, err := transmit(c.t, Command{INS: insPutDataOdd, P1: 0x3F, P2: 0xFF, Data: data}); err != nil {
		return fmt.Errorf("import key: %w", err)
	}
	want := priv.Public().(ed25519.PublicKey)
	created := o.Created
	if created.IsZero() {
		created = time.Now()
	}
	ts := uint32(created.Unix())
	fp := openPGPFingerprint(want, ts)
	if err := c.putData(doFPSig, fp[:]); err != nil {
		return fmt.Errorf("write fingerprint: %w", err)
	}
	if err := c.putData(doTimeSig, binary.BigEndian.AppendUint32(nil, ts)); err != nil {
		return fmt.Errorf("write creation time: %w", err)
	}
	if o.SinglePINUse {
		if err := c.putData(doPWStatus, []byte{0x00}); err != nil {
			return fmt.Errorf("set PIN policy: %w", err)
		}
	}
	if o.UIF != UIFKeep {
		if err := c.putData(doUIFSig, []byte{o.UIF, uifButtonAvailable}); err != nil {
			return fmt.Errorf("set touch flag: %w", err)
		}
	}
	got, err := c.SignaturePublicKey()
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrKeyMismatch
	}
	return nil
}

// Sign computes a pure Ed25519 signature over msg (PSO:COMPUTE DIGITAL
// SIGNATURE). PW1 (81) must have been verified.
func (c *OpenPGPClient) Sign(msg []byte) ([]byte, error) {
	if len(msg) == 0 || len(msg) > maxSignMessage {
		return nil, errors.New("message to sign must be 1-1024 bytes")
	}
	sig, err := transmit(c.t, Command{INS: insPSO, P1: 0x9E, P2: 0x9A, Data: msg, Le: 256})
	if err != nil {
		return nil, err
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, errors.New("unexpected signature length")
	}
	return sig, nil
}

// OpenPGPSigner is a trust.DigestSigner backed by the OpenPGP signature key.
// It verifies PW1 before every signature and checks every signature
// against the public key read when it was created.
type OpenPGPSigner struct {
	c       *OpenPGPClient
	pub     ed25519.PublicKey
	pin     func() ([]byte, error)
	version Version
}

// NewOpenPGPSigner returns a signer for the card's Ed25519 signature key.
func NewOpenPGPSigner(c *OpenPGPClient, pin func() ([]byte, error)) (*OpenPGPSigner, error) {
	v, err := c.CheckEd25519Support()
	if err != nil {
		return nil, err
	}
	pub, err := c.SignaturePublicKey()
	if err != nil {
		return nil, err
	}
	return &OpenPGPSigner{c: c, pub: pub, pin: pin, version: v}, nil
}

// PublicKey returns the signature key.
func (s *OpenPGPSigner) PublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), s.pub...)
}

// SignMessage verifies PW1, signs msg and checks the signature.
func (s *OpenPGPSigner) SignMessage(msg []byte) ([]byte, error) {
	if s.pin != nil {
		pin, err := s.pin()
		if err != nil {
			clear(pin)
			return nil, err
		}
		err = s.c.VerifyPIN(pin)
		clear(pin)
		if err != nil {
			return nil, err
		}
	}
	sig, err := s.c.Sign(msg)
	if err != nil {
		var se *StatusError
		if errors.As(err, &se) && se.SW == swSecurityStatus {
			return nil, fmt.Errorf("signature PIN not verified: %w", err)
		}
		return nil, err
	}
	if !ed25519.Verify(s.pub, msg, sig) {
		return nil, errors.New("token returned a signature that does not verify")
	}
	return sig, nil
}
