package piv

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
)

// PIV application identifier (NIST SP 800-73-4).
var pivAID = []byte{0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00}

// Instructions.
const (
	insSelect       = 0xA4
	insVerify       = 0x20
	insAuthenticate = 0x87
	insGetVersion   = 0xFD // Yubico extension
	insGetMetadata  = 0xF7 // Yubico extension, firmware 5.3+
	insImportKey    = 0xFE // Yubico extension
)

// Slots.
const (
	SlotAuthentication = 0x9A
	SlotManagement     = 0x9B
	SlotSignature      = 0x9C // PIN for every signature by default
	SlotKeyManagement  = 0x9D
	SlotCardAuth       = 0x9E
)

// Algorithm identifiers.
const (
	AlgTDES    = 0x03
	AlgAES128  = 0x08
	AlgAES192  = 0x0A
	AlgAES256  = 0x0C
	AlgEd25519 = 0xE0 // firmware 5.7+
)

// PIN and touch policies for imported keys.
const (
	PINPolicyDefault   = 0x00
	PINPolicyNever     = 0x01
	PINPolicyOnce      = 0x02
	PINPolicyAlways    = 0x03
	TouchPolicyDefault = 0x00
	TouchPolicyNever   = 0x01
	TouchPolicyAlways  = 0x02
	TouchPolicyCached  = 0x03
)

// Dynamic authentication template tags.
const (
	tagDynAuth   = 0x7C
	tagWitness   = 0x80
	tagChallenge = 0x81
	tagResponse  = 0x82

	tagEd25519Private = 0x07
	tagPINPolicy      = 0xAA
	tagTouchPolicy    = 0xAB

	tagMetaAlgorithm = 0x01
	tagMetaPolicy    = 0x02
	tagMetaOrigin    = 0x03
	tagMetaPublicKey = 0x04
	tagECPoint       = 0x86
)

// MinEd25519Firmware is the first YubiKey firmware with Ed25519 in PIV.
var MinEd25519Firmware = Version{5, 7, 0}

// Errors.
var (
	ErrUnsupported     = errors.New("PC/SC smart card access is not available on this system")
	ErrFirmwareTooOld  = errors.New("token firmware does not support Ed25519 in PIV (5.7 or newer is required)")
	ErrPINBlocked      = errors.New("PIN is blocked; unblock it with the PUK")
	ErrManagementAuth  = errors.New("management key authentication failed")
	ErrKeyMismatch     = errors.New("the key in the slot is not the expected key")
	ErrNotEd25519Slot  = errors.New("the slot does not hold an Ed25519 key")
	errInvalidPINInput = errors.New("PIN must be 6-8 bytes")
)

// Version is a firmware version.
type Version struct{ Major, Minor, Patch byte }

func (v Version) String() string { return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch) }

// AtLeast reports whether v >= o.
func (v Version) AtLeast(o Version) bool {
	if v.Major != o.Major {
		return v.Major > o.Major
	}
	if v.Minor != o.Minor {
		return v.Minor > o.Minor
	}
	return v.Patch >= o.Patch
}

// Client runs PIV commands over a transport. It is not safe for
// concurrent use; the PC/SC transport holds a card transaction.
type Client struct {
	t Transport
}

// NewClient selects the PIV applet on t.
func NewClient(t Transport) (*Client, error) {
	c := &Client{t: t}
	if _, err := transmit(t, Command{INS: insSelect, P1: 0x04, Data: pivAID}); err != nil {
		return nil, fmt.Errorf("select PIV applet: %w", err)
	}
	return c, nil
}

// Version returns the firmware version (Yubico GET VERSION).
func (c *Client) Version() (Version, error) {
	data, err := transmit(c.t, Command{INS: insGetVersion})
	if err != nil {
		return Version{}, err
	}
	if len(data) != 3 {
		return Version{}, errors.New("unexpected version answer")
	}
	return Version{data[0], data[1], data[2]}, nil
}

// CheckEd25519Support fails unless the token can hold Ed25519 keys.
func (c *Client) CheckEd25519Support() (Version, error) {
	v, err := c.Version()
	if err != nil {
		return Version{}, err
	}
	if !v.AtLeast(MinEd25519Firmware) {
		return v, fmt.Errorf("%w (found %s)", ErrFirmwareTooOld, v)
	}
	return v, nil
}

// encodePIN pads a PIN with 0xFF to 8 bytes.
func encodePIN(pin []byte) ([]byte, error) {
	if len(pin) < 6 || len(pin) > 8 {
		return nil, errInvalidPINInput
	}
	out := make([]byte, 8)
	copy(out, pin)
	for i := len(pin); i < 8; i++ {
		out[i] = 0xFF
	}
	return out, nil
}

// VerifyPIN verifies the card PIN. A wrong PIN returns *ErrWrongPIN with
// the remaining tries.
func (c *Client) VerifyPIN(pin []byte) error {
	data, err := encodePIN(pin)
	if err != nil {
		return err
	}
	defer clear(data)
	_, err = transmit(c.t, Command{INS: insVerify, P1: 0x00, P2: 0x80, Data: data})
	return pinError(err)
}

func pinError(err error) error {
	var se *StatusError
	if !errors.As(err, &se) {
		return err
	}
	switch {
	case se.SW == swAuthBlocked:
		return ErrPINBlocked
	case se.SW&0xFFF0 == 0x63C0:
		return &ErrWrongPIN{Retries: int(se.SW & 0x0F)}
	}
	return err
}

// Metadata describes a slot's key (Yubico GET METADATA).
type Metadata struct {
	Algorithm   byte
	PINPolicy   byte
	TouchPolicy byte
	Imported    bool
	PublicKey   []byte // Ed25519: 32 bytes
}

// Metadata returns the metadata of slot.
func (c *Client) Metadata(slot byte) (Metadata, error) {
	data, err := transmit(c.t, Command{INS: insGetMetadata, P2: slot})
	if err != nil {
		return Metadata{}, err
	}
	return parseMetadata(data)
}

func parseMetadata(data []byte) (Metadata, error) {
	list, err := parseTLVs(data)
	if err != nil {
		return Metadata{}, err
	}
	var m Metadata
	alg, ok := findTLV(list, tagMetaAlgorithm)
	if !ok || len(alg) != 1 {
		return Metadata{}, errors.New("metadata without algorithm")
	}
	m.Algorithm = alg[0]
	if p, ok := findTLV(list, tagMetaPolicy); ok && len(p) == 2 {
		m.PINPolicy, m.TouchPolicy = p[0], p[1]
	}
	if o, ok := findTLV(list, tagMetaOrigin); ok && len(o) == 1 {
		m.Imported = o[0] == 0x02
	}
	if pk, ok := findTLV(list, tagMetaPublicKey); ok {
		inner, err := parseTLVs(pk)
		if err != nil {
			return Metadata{}, err
		}
		if pt, ok := findTLV(inner, tagECPoint); ok {
			m.PublicKey = pt
		}
	}
	return m, nil
}

// Ed25519PublicKey returns the Ed25519 public key held in slot.
func (c *Client) Ed25519PublicKey(slot byte) (ed25519.PublicKey, error) {
	m, err := c.Metadata(slot)
	if err != nil {
		return nil, err
	}
	if m.Algorithm != AlgEd25519 || len(m.PublicKey) != ed25519.PublicKeySize {
		return nil, ErrNotEd25519Slot
	}
	return ed25519.PublicKey(append([]byte(nil), m.PublicKey...)), nil
}

// ManagementKey is the PIV management key and its algorithm.
type ManagementKey struct {
	Algorithm byte
	Key       []byte
}

func (k ManagementKey) block() (cipher.Block, error) {
	switch k.Algorithm {
	case AlgTDES:
		if len(k.Key) != 24 {
			return nil, errors.New("3DES management key must be 24 bytes")
		}
		return des.NewTripleDESCipher(k.Key)
	case AlgAES128, AlgAES192, AlgAES256:
		want := map[byte]int{AlgAES128: 16, AlgAES192: 24, AlgAES256: 32}[k.Algorithm]
		if len(k.Key) != want {
			return nil, fmt.Errorf("AES management key must be %d bytes", want)
		}
		return aes.NewCipher(k.Key)
	}
	return nil, errors.New("unsupported management key algorithm")
}

// AuthenticateManagementKey performs mutual authentication with the
// management key (witness, then challenge), required before importing a
// key. The card's answer to our challenge is checked in constant time.
func (c *Client) AuthenticateManagementKey(k ManagementKey, random io.Reader) error {
	block, err := k.block()
	if err != nil {
		return err
	}
	if random == nil {
		random = rand.Reader
	}
	bs := block.BlockSize()
	resp, err := transmit(c.t, Command{INS: insAuthenticate, P1: k.Algorithm, P2: SlotManagement,
		Data: tlv(tagDynAuth, tlv(tagWitness, nil))})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrManagementAuth, err)
	}
	witness, err := dynAuthValue(resp, tagWitness)
	if err != nil || len(witness) != bs {
		return fmt.Errorf("%w: unexpected witness", ErrManagementAuth)
	}
	plainWitness := make([]byte, bs)
	block.Decrypt(plainWitness, witness)
	challenge := make([]byte, bs)
	if _, err := io.ReadFull(random, challenge); err != nil {
		return fmt.Errorf("read challenge: %w", err)
	}
	body := append(tlv(tagWitness, plainWitness), tlv(tagChallenge, challenge)...)
	resp, err = transmit(c.t, Command{INS: insAuthenticate, P1: k.Algorithm, P2: SlotManagement,
		Data: tlv(tagDynAuth, body)})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrManagementAuth, err)
	}
	got, err := dynAuthValue(resp, tagResponse)
	if err != nil || len(got) != bs {
		return fmt.Errorf("%w: unexpected response", ErrManagementAuth)
	}
	want := make([]byte, bs)
	block.Encrypt(want, challenge)
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return fmt.Errorf("%w: card did not prove the management key", ErrManagementAuth)
	}
	return nil
}

func dynAuthValue(resp []byte, tag uint16) ([]byte, error) {
	inner, err := unwrapTLV(resp, tagDynAuth)
	if err != nil {
		return nil, err
	}
	list, err := parseTLVs(inner)
	if err != nil {
		return nil, err
	}
	v, ok := findTLV(list, tag)
	if !ok {
		return nil, errTLV
	}
	return v, nil
}

// encodeImportEd25519 builds the IMPORT KEY data for an Ed25519 seed.
func encodeImportEd25519(seed []byte, pinPolicy, touchPolicy byte) ([]byte, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("invalid ed25519 seed")
	}
	// One allocation large enough for every element: an append that
	// grows the slice would leave a copy of the seed behind in the old
	// array, which nothing clears.
	data := appendTLV(make([]byte, 0, 2+len(seed)+2*3), tagEd25519Private, seed)
	if pinPolicy != PINPolicyDefault {
		data = appendTLV(data, tagPINPolicy, []byte{pinPolicy})
	}
	if touchPolicy != TouchPolicyDefault {
		data = appendTLV(data, tagTouchPolicy, []byte{touchPolicy})
	}
	return data, nil
}

// ImportEd25519 imports priv into slot. The management key must have been
// authenticated. The key is imported, never generated on the token, so the
// passphrase-sealed copies stay a working backup (ADR-0011, ADR-0123). The
// slot's public key is read back and compared.
func (c *Client) ImportEd25519(slot byte, priv ed25519.PrivateKey, pinPolicy, touchPolicy byte) error {
	if len(priv) != ed25519.PrivateKeySize {
		return errors.New("invalid ed25519 private key")
	}
	if _, err := c.CheckEd25519Support(); err != nil {
		return err
	}
	seed := priv.Seed()
	defer clear(seed)
	data, err := encodeImportEd25519(seed, pinPolicy, touchPolicy)
	if err != nil {
		return err
	}
	defer clear(data)
	if _, err := transmit(c.t, Command{INS: insImportKey, P1: AlgEd25519, P2: slot, Data: data}); err != nil {
		return fmt.Errorf("import key: %w", err)
	}
	pub, err := c.Ed25519PublicKey(slot)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(pub, priv.Public().(ed25519.PublicKey)) != 1 {
		return ErrKeyMismatch
	}
	return nil
}

// maxSignMessage bounds what is sent for signing; OpenScale only ever signs
// short digest messages (trust.DigestMessage).
const maxSignMessage = 1024

// encodeSign builds the GENERAL AUTHENTICATE data for a signature.
func encodeSign(msg []byte) ([]byte, error) {
	if len(msg) == 0 || len(msg) > maxSignMessage {
		return nil, errors.New("message to sign must be 1-1024 bytes")
	}
	return tlv(tagDynAuth, append(tlv(tagResponse, nil), tlv(tagChallenge, msg)...)), nil
}

// SignEd25519 signs msg with the Ed25519 key in slot (pure Ed25519; the
// PIN must have been verified when the slot's policy requires it).
func (c *Client) SignEd25519(slot byte, msg []byte) ([]byte, error) {
	data, err := encodeSign(msg)
	if err != nil {
		return nil, err
	}
	resp, err := transmit(c.t, Command{INS: insAuthenticate, P1: AlgEd25519, P2: slot, Data: data})
	if err != nil {
		return nil, pinError(err)
	}
	sig, err := dynAuthValue(resp, tagResponse)
	if err != nil {
		return nil, err
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, errors.New("unexpected signature length")
	}
	return append([]byte(nil), sig...), nil
}

// Signer is a trust.DigestSigner backed by a PIV slot. It verifies the PIN
// before every signature and checks every signature against the slot's
// public key, which was read once when the signer was created.
type Signer struct {
	c    *Client
	slot byte
	pub  ed25519.PublicKey
	pin  func() ([]byte, error)
}

// NewSigner returns a signer for slot. pin is asked for the PIN before each
// signature (the signature slot's default policy).
func NewSigner(c *Client, slot byte, pin func() ([]byte, error)) (*Signer, error) {
	if _, err := c.CheckEd25519Support(); err != nil {
		return nil, err
	}
	pub, err := c.Ed25519PublicKey(slot)
	if err != nil {
		return nil, err
	}
	return &Signer{c: c, slot: slot, pub: pub, pin: pin}, nil
}

// PublicKey returns the slot's public key.
func (s *Signer) PublicKey() ed25519.PublicKey { return append(ed25519.PublicKey(nil), s.pub...) }

// SignMessage verifies the PIN, signs msg and checks the signature.
func (s *Signer) SignMessage(msg []byte) ([]byte, error) {
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
	sig, err := s.c.SignEd25519(s.slot, msg)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(s.pub, msg, sig) {
		return nil, errors.New("token returned a signature that does not verify")
	}
	return sig, nil
}
