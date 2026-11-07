package trust

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

// Short authentication string (#20, ADR-0062). A device identity is shown
// as 20 decimal digits in five groups ("1234-5678-9012-3456-7890") that a
// person can read aloud and compare between two screens faster than a
// base32 fingerprint. 20 digits are 66 bits, the strength of the six
// 11-bit words the proposal described: matching a victim's code takes about
// 2^66 key generations, far beyond what fits in an enrollment request's
// 24-hour lifetime. The code is derived from the public keys only, so the
// device and the owner compute it independently.

const (
	sasContext     = "openscale/sas/v1"
	sasGroups      = 5
	sasGroupDigits = 4
	// SASDigits is the number of digits in a short authentication string.
	SASDigits = sasGroups * sasGroupDigits
)

var sasModulus = new(big.Int).Exp(big.NewInt(10), big.NewInt(SASDigits), nil)

// sas derives the code from length-prefixed parts. 128 bits are reduced
// modulo 10^20; the bias is below 2^-61.
func sas(parts ...[]byte) string {
	h := sha256.New()
	h.Write([]byte(sasContext))
	var lenBuf [4]byte
	for _, p := range parts {
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(p))) //nolint:gosec // parts are small keys and ids
		h.Write(lenBuf[:])
		h.Write(p)
	}
	sum := h.Sum(nil)
	n := new(big.Int).SetBytes(sum[:16])
	n.Mod(n, sasModulus)
	digits := fmt.Sprintf("%0*s", SASDigits, n.String())
	groups := make([]string, 0, sasGroups)
	for i := 0; i < SASDigits; i += sasGroupDigits {
		groups = append(groups, digits[i:i+sasGroupDigits])
	}
	return strings.Join(groups, "-")
}

// DeviceSAS returns the short authentication string of a device identity.
func DeviceSAS(deviceID string, signing, wireguard Key) string {
	id, _ := hex.DecodeString(deviceID)
	return sas([]byte("device"), id, signing[:], wireguard[:])
}

// SAS returns the request's short authentication string.
func (r *EnrollmentRequest) SAS() string {
	return DeviceSAS(r.DeviceID, r.SigningKey, r.WireGuardKey)
}

// SAS returns the short authentication string of this device's keys, the
// same code the owner sees for its enrollment request.
func (s *DeviceSecrets) SAS() (string, error) {
	signing, wg, err := s.PublicKeys()
	if err != nil {
		return "", err
	}
	return DeviceSAS(s.DeviceID, signing, wg), nil
}

// RootSAS returns the short authentication string of a root public key, so
// a device can confirm the network it pinned against the owner's screen.
func RootSAS(pub ed25519.PublicKey) string {
	return sas([]byte("root"), pub)
}

// NormalizeSAS keeps only the digits of a typed code.
func NormalizeSAS(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// SASMatches compares a typed code with the expected one in constant time.
func SASMatches(typed, want string) bool {
	a, b := NormalizeSAS(typed), NormalizeSAS(want)
	return len(a) == SASDigits && len(b) == SASDigits && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
