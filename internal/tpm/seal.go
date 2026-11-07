package tpm

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// Sealing the device key to this computer's TPM (#602, ADR-0208,
// following the design of ADR-0124).
//
// A random 32-byte data key encrypts the protected file with
// XChaCha20-Poly1305; the data key itself is sealed by the platform:
//
//   - Linux (and any Transport): raw TPM 2.0 commands. A transient ECC
//     P-256 storage primary key is created under the owner hierarchy
//     (nothing is persisted, no NV memory is used), the data key becomes a
//     sealed keyed-hash object (TPM2_Create), and opening loads it and
//     calls TPM2_Unseal. The private blob only loads under the same
//     TPM's owner hierarchy seed, so a disk copy is useless elsewhere.
//   - Windows: CNG "Microsoft Platform Crypto Provider" (ncrypt.dll,
//     ncrypt_windows.go) creates a non-exportable RSA-2048 key inside the
//     TPM and wraps the data key with RSA-OAEP-SHA256.
//   - macOS: the Secure Enclave needs cgo and the Security framework; the
//     CGO_ENABLED=0 build reports ErrUnsupported.
//
// Every seal is verified by unsealing it at once and comparing, before
// the caller replaces the old protection: code that never ran on real
// hardware must not be able to lose the device key silently. Losing the
// TPM (clearing it, replacing the board) loses the sealed key; the device
// is then enrolled again and the network's root key is not affected.
//
// None of this has been run against a real TPM yet (writing to the TPM of
// the development machine is forbidden); tests use a simulated TPM.
//
//	envelope = "OSSEAL1\0" | kind (1) | u16 len | sealed data key |
//	           nonce (24) | ciphertext

// Sealer seals a short secret to the platform.
type Sealer interface {
	// Kind names the mechanism ("tpm2", "ncrypt").
	Kind() string
	Seal(secret []byte) ([]byte, error)
	Unseal(blob []byte) ([]byte, error)
}

const (
	envelopeMagic = "OSSEAL1\x00"
	dataKeySize   = 32
	maxSealedBlob = 4096
	// MaxEnvelopePlain bounds the protected file.
	MaxEnvelopePlain = 1 << 20
)

// Sealer kinds as stored in the envelope.
const (
	kindTPM2   byte = 1
	kindNCrypt byte = 2
)

// Errors.
var (
	ErrSealCheck       = errors.New("mühürlenen anahtar hemen açılamadı; eski koruma korunuyor")
	ErrEnvelope        = errors.New("mühürlü dosya biçimi geçersiz")
	ErrWrongSealerKind = errors.New("mühürlü dosya başka bir mekanizmayla mühürlenmiş")
)

func kindByte(s Sealer) (byte, error) {
	switch s.Kind() {
	case "tpm2":
		return kindTPM2, nil
	case "ncrypt":
		return kindNCrypt, nil
	}
	return 0, fmt.Errorf("bilinmeyen mühürleme türü %q", s.Kind())
}

// SealEnvelope encrypts plain under a fresh data key sealed by s. The
// result is returned only after s unsealed it successfully.
func SealEnvelope(s Sealer, plain []byte, random io.Reader) ([]byte, error) {
	if random == nil {
		random = rand.Reader
	}
	if len(plain) > MaxEnvelopePlain {
		return nil, errors.New("mühürlenecek veri çok büyük")
	}
	kb, err := kindByte(s)
	if err != nil {
		return nil, err
	}
	dk := make([]byte, dataKeySize)
	defer clear(dk)
	if _, err := io.ReadFull(random, dk); err != nil {
		return nil, err
	}
	sealed, err := s.Seal(dk)
	if err != nil {
		return nil, err
	}
	if len(sealed) == 0 || len(sealed) > maxSealedBlob {
		return nil, ErrEnvelope
	}
	check, err := s.Unseal(sealed)
	if err != nil || subtle.ConstantTimeCompare(check, dk) != 1 {
		clear(check)
		return nil, ErrSealCheck
	}
	clear(check)
	aead, err := chacha20poly1305.NewX(dk)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(random, nonce); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	b.WriteString(envelopeMagic)
	b.WriteByte(kb)
	_ = binary.Write(&b, binary.BigEndian, uint16(len(sealed)))
	b.Write(sealed)
	b.Write(nonce)
	hdr := bytes.Clone(b.Bytes())
	b.Write(aead.Seal(nil, nonce, plain, hdr))
	return b.Bytes(), nil
}

// OpenEnvelope reverses SealEnvelope on the same computer.
func OpenEnvelope(s Sealer, env []byte) ([]byte, error) {
	kb, sealed, nonce, ct, hdr, err := ParseEnvelope(env)
	if err != nil {
		return nil, err
	}
	want, err := kindByte(s)
	if err != nil {
		return nil, err
	}
	if kb != want {
		return nil, ErrWrongSealerKind
	}
	dk, err := s.Unseal(sealed)
	if err != nil {
		return nil, err
	}
	defer clear(dk)
	if len(dk) != dataKeySize {
		return nil, ErrEnvelope
	}
	aead, err := chacha20poly1305.NewX(dk)
	if err != nil {
		return nil, err
	}
	p, err := aead.Open(nil, nonce, ct, hdr)
	if err != nil {
		return nil, ErrEnvelope
	}
	return p, nil
}

// IsEnvelope reports whether b starts like a sealed envelope.
func IsEnvelope(b []byte) bool { return bytes.HasPrefix(b, []byte(envelopeMagic)) }

// ParseEnvelope splits an envelope without opening it (exported for
// fuzzing and diagnostics).
func ParseEnvelope(env []byte) (kind byte, sealed, nonce, ct, hdr []byte, err error) {
	h := len(envelopeMagic)
	if len(env) < h+3 || !IsEnvelope(env) {
		return 0, nil, nil, nil, nil, ErrEnvelope
	}
	kind = env[h]
	n := int(binary.BigEndian.Uint16(env[h+1:]))
	off := h + 3
	if n == 0 || n > maxSealedBlob || len(env) < off+n+chacha20poly1305.NonceSizeX+16 {
		return 0, nil, nil, nil, nil, ErrEnvelope
	}
	sealed = env[off : off+n]
	nonce = env[off+n : off+n+chacha20poly1305.NonceSizeX]
	hdr = env[:off+n+chacha20poly1305.NonceSizeX]
	ct = env[off+n+chacha20poly1305.NonceSizeX:]
	return kind, sealed, nonce, ct, hdr, nil
}

// --- raw TPM 2.0 sealing ---

// TPM 2.0 constants used for sealing (TCG TPM 2.0 Library, Part 2).
const (
	tagSessions     = 0x8002
	rsPW            = 0x40000009
	rhOwner         = 0x40000001
	ccCreatePrimary = 0x00000131
	ccCreate        = 0x00000153
	ccLoad          = 0x00000157
	ccUnseal        = 0x0000015E
	ccFlushContext  = 0x00000165
	ccNVReadPublic  = 0x00000169
	ccNVRead        = 0x0000014E

	algECC       = 0x0023
	algSHA256    = 0x000B
	algAES       = 0x0006
	algCFB       = 0x0043
	algNull      = 0x0010
	algKeyedHash = 0x0008
	eccNISTP256  = 0x0003

	attrFixedTPM            = 0x00000002
	attrFixedParent         = 0x00000010
	attrSensitiveDataOrigin = 0x00000020
	attrUserWithAuth        = 0x00000040
	attrNoDA                = 0x00000400
	attrRestricted          = 0x00010000
	attrDecrypt             = 0x00020000
)

// sealCommands is the allowlist for sealing: no EvictControl (nothing
// persistent), no NV writes, no hierarchy changes.
var sealCommands = map[uint32]bool{
	ccCreatePrimary: true, ccCreate: true, ccLoad: true, ccUnseal: true, ccFlushContext: true,
}

type sealOnly struct{ t Transport }

func (s sealOnly) Submit(cmd []byte) ([]byte, error) {
	if len(cmd) < headerSize {
		return nil, errors.New("command too short")
	}
	if cc := binary.BigEndian.Uint32(cmd[6:10]); !sealCommands[cc] {
		return nil, fmt.Errorf("%w: 0x%08X", ErrNotAllowed, cc)
	}
	return s.t.Submit(cmd)
}

func (s sealOnly) Close() error { return s.t.Close() }

// TPM2Sealer seals with raw TPM 2.0 commands over a Transport.
type TPM2Sealer struct {
	t Transport
}

// NewTPM2Sealer wraps t; only the sealing commands can pass.
func NewTPM2Sealer(t Transport) *TPM2Sealer { return &TPM2Sealer{t: sealOnly{t: t}} }

// Kind implements Sealer.
func (s *TPM2Sealer) Kind() string { return "tpm2" }

type cmdBuilder struct{ b []byte }

func newCmd(tag uint16, cc uint32) *cmdBuilder {
	c := &cmdBuilder{b: make([]byte, 10, 256)}
	binary.BigEndian.PutUint16(c.b[0:], tag)
	binary.BigEndian.PutUint32(c.b[6:], cc)
	return c
}

func (c *cmdBuilder) u8(v byte)    { c.b = append(c.b, v) }
func (c *cmdBuilder) u16(v uint16) { c.b = binary.BigEndian.AppendUint16(c.b, v) }
func (c *cmdBuilder) u32(v uint32) { c.b = binary.BigEndian.AppendUint32(c.b, v) }
func (c *cmdBuilder) tpm2b(v []byte) {
	c.u16(uint16(len(v)))
	c.b = append(c.b, v...)
}

// pwAuth appends an empty password session authorization area.
func (c *cmdBuilder) pwAuth() {
	c.u32(9)
	c.u32(rsPW)
	c.u16(0) // nonce
	c.u8(0)  // session attributes
	c.u16(0) // empty password
}

func (c *cmdBuilder) bytes() []byte {
	binary.BigEndian.PutUint32(c.b[2:], uint32(len(c.b)))
	return c.b
}

// primaryTemplate is a TPMT_PUBLIC for an ECC P-256 storage key (the
// common SRK template with empty unique fields).
func primaryTemplate() []byte {
	c := &cmdBuilder{}
	c.u16(algECC)
	c.u16(algSHA256)
	c.u32(attrFixedTPM | attrFixedParent | attrSensitiveDataOrigin | attrUserWithAuth | attrNoDA | attrRestricted | attrDecrypt)
	c.tpm2b(nil) // authPolicy
	c.u16(algAES)
	c.u16(128)
	c.u16(algCFB)
	c.u16(algNull) // scheme
	c.u16(eccNISTP256)
	c.u16(algNull) // kdf
	c.tpm2b(nil)   // unique.x
	c.tpm2b(nil)   // unique.y
	return c.b
}

// sealedTemplate is a TPMT_PUBLIC for a sealed data object.
func sealedTemplate() []byte {
	c := &cmdBuilder{}
	c.u16(algKeyedHash)
	c.u16(algSHA256)
	c.u32(attrFixedTPM | attrFixedParent | attrUserWithAuth | attrNoDA)
	c.tpm2b(nil)   // authPolicy
	c.u16(algNull) // scheme
	c.tpm2b(nil)   // unique
	return c.b
}

func encodeCreatePrimary() []byte {
	c := newCmd(tagSessions, ccCreatePrimary)
	c.u32(rhOwner)
	c.pwAuth()
	c.tpm2b([]byte{0, 0, 0, 0}) // TPM2B_SENSITIVE_CREATE: empty auth, empty data
	c.tpm2b(primaryTemplate())
	c.tpm2b(nil) // outsideInfo
	c.u32(0)     // creationPCR: none
	return c.bytes()
}

func encodeCreate(parent uint32, secret []byte) []byte {
	c := newCmd(tagSessions, ccCreate)
	c.u32(parent)
	c.pwAuth()
	sens := &cmdBuilder{}
	sens.tpm2b(nil)
	sens.tpm2b(secret)
	c.tpm2b(sens.b)
	clear(sens.b)
	c.tpm2b(sealedTemplate())
	c.tpm2b(nil)
	c.u32(0)
	return c.bytes()
}

func encodeLoad(parent uint32, priv, pub []byte) []byte {
	c := newCmd(tagSessions, ccLoad)
	c.u32(parent)
	c.pwAuth()
	c.tpm2b(priv)
	c.tpm2b(pub)
	return c.bytes()
}

func encodeUnseal(obj uint32) []byte {
	c := newCmd(tagSessions, ccUnseal)
	c.u32(obj)
	c.pwAuth()
	return c.bytes()
}

func encodeFlush(h uint32) []byte {
	c := newCmd(tagNoSessions, ccFlushContext)
	c.u32(h)
	return c.bytes()
}

// checkResponse validates the header and returns the body.
func checkResponse(resp []byte) ([]byte, error) {
	if len(resp) > MaxResponse {
		return nil, errors.New("TPM response too long")
	}
	if len(resp) < headerSize {
		return nil, errors.New("TPM response too short")
	}
	if int(binary.BigEndian.Uint32(resp[2:6])) != len(resp) {
		return nil, errors.New("TPM response size mismatch")
	}
	if rc := binary.BigEndian.Uint32(resp[6:10]); rc != 0 {
		return nil, &ResponseError{Code: rc}
	}
	if tag := binary.BigEndian.Uint16(resp[0:2]); tag != tagNoSessions && tag != tagSessions {
		return nil, fmt.Errorf("unexpected TPM response tag 0x%04X", tag)
	}
	return resp[headerSize:], nil
}

type reader struct {
	b   []byte
	err error
}

func (r *reader) u32() uint32 {
	if r.err != nil || len(r.b) < 4 {
		r.err = errors.New("TPM response truncated")
		return 0
	}
	v := binary.BigEndian.Uint32(r.b)
	r.b = r.b[4:]
	return v
}

func (r *reader) u16() uint16 {
	if r.err != nil || len(r.b) < 2 {
		r.err = errors.New("TPM response truncated")
		return 0
	}
	v := binary.BigEndian.Uint16(r.b)
	r.b = r.b[2:]
	return v
}

func (r *reader) tpm2b() []byte {
	n := int(r.u16())
	if r.err != nil || len(r.b) < n {
		r.err = errors.New("TPM response truncated")
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (s *TPM2Sealer) primary() (uint32, error) {
	resp, err := s.t.Submit(encodeCreatePrimary())
	if err != nil {
		return 0, err
	}
	body, err := checkResponse(resp)
	if err != nil {
		return 0, err
	}
	r := &reader{b: body}
	h := r.u32()
	return h, r.err
}

func (s *TPM2Sealer) flush(h uint32) { _, _ = s.t.Submit(encodeFlush(h)) }

// Seal implements Sealer.
func (s *TPM2Sealer) Seal(secret []byte) ([]byte, error) {
	if len(secret) == 0 || len(secret) > 128 {
		return nil, errors.New("sealed secret must be 1-128 bytes")
	}
	parent, err := s.primary()
	if err != nil {
		return nil, err
	}
	defer s.flush(parent)
	cmd := encodeCreate(parent, secret)
	resp, err := s.t.Submit(cmd)
	clear(cmd)
	if err != nil {
		return nil, err
	}
	body, err := checkResponse(resp)
	if err != nil {
		return nil, err
	}
	r := &reader{b: body}
	r.u32() // parameterSize
	priv := r.tpm2b()
	pub := r.tpm2b()
	if r.err != nil || len(priv) == 0 || len(pub) == 0 {
		return nil, errors.New("TPM2_Create response malformed")
	}
	c := &cmdBuilder{}
	c.tpm2b(priv)
	c.tpm2b(pub)
	return c.b, nil
}

// splitBlob returns the private and public parts of a sealed blob.
func splitBlob(blob []byte) ([]byte, []byte, error) {
	r := &reader{b: blob}
	priv := r.tpm2b()
	pub := r.tpm2b()
	if r.err != nil || len(r.b) != 0 || len(priv) == 0 || len(pub) == 0 {
		return nil, nil, ErrEnvelope
	}
	return priv, pub, nil
}

// Unseal implements Sealer.
func (s *TPM2Sealer) Unseal(blob []byte) ([]byte, error) {
	priv, pub, err := splitBlob(blob)
	if err != nil {
		return nil, err
	}
	parent, err := s.primary()
	if err != nil {
		return nil, err
	}
	defer s.flush(parent)
	resp, err := s.t.Submit(encodeLoad(parent, priv, pub))
	if err != nil {
		return nil, err
	}
	body, err := checkResponse(resp)
	if err != nil {
		return nil, err
	}
	r := &reader{b: body}
	obj := r.u32()
	if r.err != nil {
		return nil, r.err
	}
	defer s.flush(obj)
	resp, err = s.t.Submit(encodeUnseal(obj))
	if err != nil {
		return nil, err
	}
	body, err = checkResponse(resp)
	if err != nil {
		return nil, err
	}
	r = &reader{b: body}
	r.u32() // parameterSize
	out := r.tpm2b()
	if r.err != nil || len(out) == 0 {
		return nil, errors.New("TPM2_Unseal response malformed")
	}
	secret := bytes.Clone(out)
	clear(resp)
	return secret, nil
}

// Close releases the transport.
func (s *TPM2Sealer) Close() error { return s.t.Close() }
