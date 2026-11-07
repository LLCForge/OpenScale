package panel

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"slices"
	"time"
)

// WebAuthn (FIDO2) second factor for panel sign-in (#673, ADR-0199).
//
// Only what the panel needs is implemented, with the standard library:
// registration reads the credential from the attestation object (the
// panel asks for attestation "none", so the attestation statement is not
// checked; the credential is trusted because an owner who just proved
// the passphrase registered it) and sign-in verifies the assertion
// signature, the challenge, the origin, the relying party hash, the user
// presence flag and the signature counter. ES256 (P-256) and EdDSA
// (Ed25519) keys are accepted, which covers YubiKey 5.

// COSE algorithm identifiers.
const (
	coseES256 = -7
	coseEdDSA = -8
)

// Authenticator data flags.
const (
	flagUP = 0x01
	flagUV = 0x04
	flagAT = 0x40
	flagED = 0x80
)

var (
	errWebAuthn = errors.New("webauthn: doğrulama başarısız")
	b64url      = base64.RawURLEncoding
)

// WebAuthnCredential is one registered security key.
type WebAuthnCredential struct {
	ID        string    `json:"id"`         // base64url credential ID
	PublicKey string    `json:"public_key"` // base64url COSE key
	Alg       int       `json:"alg"`
	SignCount uint32    `json:"sign_count"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	LastUsed  time.Time `json:"last_used,omitzero"`
}

type clientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin"`
}

// checkClientData parses clientDataJSON and checks type, challenge and
// origin.
func checkClientData(raw []byte, wantType string, challenge []byte, origins []string) error {
	if len(raw) == 0 || len(raw) > 4096 {
		return errWebAuthn
	}
	var cd clientData
	if err := json.Unmarshal(raw, &cd); err != nil {
		return errWebAuthn
	}
	got, err := b64url.DecodeString(cd.Challenge)
	if err != nil || cd.Type != wantType || cd.CrossOrigin || len(challenge) == 0 ||
		subtle.ConstantTimeCompare(got, challenge) != 1 || !slices.Contains(origins, cd.Origin) {
		return errWebAuthn
	}
	return nil
}

type authData struct {
	rpIDHash  []byte
	flags     byte
	signCount uint32
	credID    []byte
	coseKey   []byte
}

func parseAuthData(b []byte, wantCred bool) (authData, error) {
	if len(b) < 37 {
		return authData{}, errWebAuthn
	}
	ad := authData{rpIDHash: b[:32], flags: b[32], signCount: binary.BigEndian.Uint32(b[33:37])}
	rest := b[37:]
	if ad.flags&flagAT != 0 {
		if len(rest) < 18 {
			return authData{}, errWebAuthn
		}
		l := int(binary.BigEndian.Uint16(rest[16:18]))
		rest = rest[18:]
		if l == 0 || l > 1023 || len(rest) < l {
			return authData{}, errWebAuthn
		}
		ad.credID = append([]byte(nil), rest[:l]...)
		rest = rest[l:]
		_, after, err := cborDecode(rest)
		if err != nil {
			return authData{}, errWebAuthn
		}
		ad.coseKey = append([]byte(nil), rest[:len(rest)-len(after)]...)
		rest = after
	}
	if ad.flags&flagED != 0 {
		if _, after, err := cborDecode(rest); err != nil {
			return authData{}, errWebAuthn
		} else {
			rest = after
		}
	}
	if len(rest) != 0 || (wantCred && ad.credID == nil) {
		return authData{}, errWebAuthn
	}
	return ad, nil
}

// coseKey is a parsed public key.
type coseKey struct {
	alg int
	ec  *ecdsa.PublicKey
	ed  ed25519.PublicKey
}

func cborInt(m map[any]any, k int64) (int64, bool) {
	v, ok := m[k].(int64)
	return v, ok
}

func cborBytes(m map[any]any, k int64) ([]byte, bool) {
	v, ok := m[k].([]byte)
	return v, ok
}

func parseCOSEKey(raw []byte) (coseKey, error) {
	v, rest, err := cborDecode(raw)
	if err != nil || len(rest) != 0 {
		return coseKey{}, errWebAuthn
	}
	m, ok := v.(map[any]any)
	if !ok {
		return coseKey{}, errWebAuthn
	}
	kty, _ := cborInt(m, 1)
	alg, _ := cborInt(m, 3)
	crv, _ := cborInt(m, -1)
	x, _ := cborBytes(m, -2)
	switch {
	case kty == 2 && alg == coseES256 && crv == 1:
		y, _ := cborBytes(m, -3)
		if len(x) != 32 || len(y) != 32 {
			return coseKey{}, errWebAuthn
		}
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
		if err != nil {
			return coseKey{}, errWebAuthn
		}
		return coseKey{alg: coseES256, ec: pub}, nil
	case kty == 1 && alg == coseEdDSA && crv == 6:
		if len(x) != ed25519.PublicKeySize {
			return coseKey{}, errWebAuthn
		}
		return coseKey{alg: coseEdDSA, ed: ed25519.PublicKey(append([]byte(nil), x...))}, nil
	}
	return coseKey{}, errors.New("webauthn: desteklenmeyen anahtar türü (ES256 veya EdDSA gerekir)")
}

func (k coseKey) verify(msg, sig []byte) bool {
	switch k.alg {
	case coseES256:
		h := sha256.Sum256(msg)
		return ecdsa.VerifyASN1(k.ec, h[:], sig)
	case coseEdDSA:
		return ed25519.Verify(k.ed, msg, sig)
	}
	return false
}

// RegistrationResponse is what navigator.credentials.create returned,
// base64url encoded by the panel.
type RegistrationResponse struct {
	ClientDataJSON    string `json:"client_data_json"`
	AttestationObject string `json:"attestation_object"`
	Name              string `json:"name"`
}

// verifyRegistration checks a registration against the challenge and
// returns the new credential.
func verifyRegistration(resp RegistrationResponse, challenge []byte, rpID string, origins []string, now time.Time) (WebAuthnCredential, error) {
	cdj, err := b64url.DecodeString(resp.ClientDataJSON)
	if err != nil {
		return WebAuthnCredential{}, errWebAuthn
	}
	if err := checkClientData(cdj, "webauthn.create", challenge, origins); err != nil {
		return WebAuthnCredential{}, err
	}
	att, err := b64url.DecodeString(resp.AttestationObject)
	if err != nil || len(att) > 16<<10 {
		return WebAuthnCredential{}, errWebAuthn
	}
	v, rest, err := cborDecode(att)
	if err != nil || len(rest) != 0 {
		return WebAuthnCredential{}, errWebAuthn
	}
	m, ok := v.(map[any]any)
	if !ok {
		return WebAuthnCredential{}, errWebAuthn
	}
	raw, ok := m["authData"].([]byte)
	if !ok {
		return WebAuthnCredential{}, errWebAuthn
	}
	ad, err := parseAuthData(raw, true)
	if err != nil {
		return WebAuthnCredential{}, err
	}
	rp := sha256.Sum256([]byte(rpID))
	if !bytes.Equal(ad.rpIDHash, rp[:]) || ad.flags&flagUP == 0 {
		return WebAuthnCredential{}, errWebAuthn
	}
	key, err := parseCOSEKey(ad.coseKey)
	if err != nil {
		return WebAuthnCredential{}, err
	}
	name := resp.Name
	if name == "" || len(name) > 64 {
		name = "Güvenlik anahtarı"
	}
	return WebAuthnCredential{ID: b64url.EncodeToString(ad.credID), PublicKey: b64url.EncodeToString(ad.coseKey), Alg: key.alg,
		SignCount: ad.signCount, Name: name, CreatedAt: now.UTC()}, nil
}

// AssertionResponse is what navigator.credentials.get returned.
type AssertionResponse struct {
	CredentialID      string `json:"credential_id"`
	ClientDataJSON    string `json:"client_data_json"`
	AuthenticatorData string `json:"authenticator_data"`
	Signature         string `json:"signature"`
}

// verifyAssertion checks an assertion with one of creds. It returns the
// index of the credential and its new signature counter.
func verifyAssertion(resp AssertionResponse, creds []WebAuthnCredential, challenge []byte, rpID string, origins []string) (int, uint32, error) {
	idx := slices.IndexFunc(creds, func(c WebAuthnCredential) bool { return c.ID == resp.CredentialID })
	if idx < 0 {
		return -1, 0, errWebAuthn
	}
	cdj, err1 := b64url.DecodeString(resp.ClientDataJSON)
	adRaw, err2 := b64url.DecodeString(resp.AuthenticatorData)
	sig, err3 := b64url.DecodeString(resp.Signature)
	if err1 != nil || err2 != nil || err3 != nil || len(sig) > 512 {
		return -1, 0, errWebAuthn
	}
	if err := checkClientData(cdj, "webauthn.get", challenge, origins); err != nil {
		return -1, 0, err
	}
	ad, err := parseAuthData(adRaw, false)
	if err != nil {
		return -1, 0, err
	}
	rp := sha256.Sum256([]byte(rpID))
	if !bytes.Equal(ad.rpIDHash, rp[:]) || ad.flags&flagUP == 0 {
		return -1, 0, errWebAuthn
	}
	coseRaw, err := b64url.DecodeString(creds[idx].PublicKey)
	if err != nil {
		return -1, 0, errWebAuthn
	}
	key, err := parseCOSEKey(coseRaw)
	if err != nil {
		return -1, 0, err
	}
	h := sha256.Sum256(cdj)
	msg := append(append([]byte(nil), adRaw...), h[:]...)
	if !key.verify(msg, sig) {
		return -1, 0, errWebAuthn
	}
	// A counter that does not grow means a cloned key; zero means the key
	// keeps no counter.
	if (ad.signCount != 0 || creds[idx].SignCount != 0) && ad.signCount <= creds[idx].SignCount {
		return -1, 0, errors.New("webauthn: imza sayacı geriledi; anahtar kopyalanmış olabilir")
	}
	return idx, ad.signCount, nil
}
