package panel

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/url"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// TOTP backup second factor (#674, ADR-0199): RFC 6238, HMAC-SHA1, six
// digits, 30 second steps, one step of tolerance either way and no reuse
// of a step that already signed in.
//
// The seed is never stored in the clear. It is sealed with
// XChaCha20-Poly1305 under a key derived with Argon2id from the password
// that comes before it at sign-in: the root key passphrase for this
// computer's panel and the separate remote password for the remote
// panel (ADR-0107). Each is its own sealed copy, so the seed can be
// opened only by someone who has just typed the right password; the
// derived key lives only in the half-finished session and is wiped when
// the code is checked or the session expires.

const (
	totpDigits    = 6
	totpPeriod    = 30
	totpSkewSteps = 1
	totpSeedBytes = 20
	totpIssuer    = "OpenScale"
)

// Argon2id parameters of the seed key (moderate: it runs after the
// password check, which already has its own cost).
const (
	sealTime    = 2
	sealMemory  = 32 * 1024
	sealThreads = 2
	sealSalt    = 16
)

var errTOTPSeal = errors.New("totp: tohum açılamadı")

// SealedSeed is one encrypted copy of the TOTP seed.
type SealedSeed struct {
	Salt  []byte `json:"salt"`
	Nonce []byte `json:"nonce"`
	Box   []byte `json:"box"`
}

// deriveSealKey turns a password into the seed key.
func deriveSealKey(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, sealTime, sealMemory, sealThreads, chacha20poly1305.KeySize)
}

func sealSeed(seed, key []byte, salt []byte, random io.Reader) (*SealedSeed, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(random, nonce); err != nil {
		return nil, err
	}
	return &SealedSeed{Salt: salt, Nonce: nonce, Box: aead.Seal(nil, nonce, seed, []byte("openscale-panel-totp-v1"))}, nil
}

// sealSeedWithPassword derives a fresh key from password and seals seed.
func sealSeedWithPassword(seed, password []byte, random io.Reader) (*SealedSeed, error) {
	salt := make([]byte, sealSalt)
	if _, err := io.ReadFull(random, salt); err != nil {
		return nil, err
	}
	key := deriveSealKey(password, salt)
	defer wipe(key)
	return sealSeed(seed, key, salt, random)
}

func (s *SealedSeed) open(key []byte) ([]byte, error) {
	if s == nil || len(key) != chacha20poly1305.KeySize {
		return nil, errTOTPSeal
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil || len(s.Nonce) != aead.NonceSize() {
		return nil, errTOTPSeal
	}
	seed, err := aead.Open(nil, s.Nonce, s.Box, []byte("openscale-panel-totp-v1"))
	if err != nil {
		return nil, errTOTPSeal
	}
	return seed, nil
}

// totpCode computes the code for one time step.
func totpCode(seed []byte, step uint64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], step)
	mac := hmac.New(sha1.New, seed)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1_000_000)
}

// totpCheck returns the matching step, or false. lastStep is the last
// step that signed in; it and earlier steps are refused (no replay).
func totpCheck(seed []byte, code string, now time.Time, lastStep uint64) (uint64, bool) {
	if len(code) != totpDigits {
		return 0, false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	cur := uint64(now.Unix()) / totpPeriod
	found, match := uint64(0), 0
	for d := -totpSkewSteps; d <= totpSkewSteps; d++ {
		step := uint64(int64(cur) + int64(d))
		// Every candidate is computed and compared in constant time.
		eq := subtle.ConstantTimeCompare([]byte(totpCode(seed, step)), []byte(code))
		if eq == 1 && step > lastStep {
			found, match = step, 1
		}
	}
	return found, match == 1
}

// totpURI is the otpauth:// address an authenticator app imports.
func totpURI(seed []byte, account string) string {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(seed)
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", totpIssuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", "6")
	v.Set("period", "30")
	return "otpauth://totp/" + url.PathEscape(totpIssuer+":"+account) + "?" + v.Encode()
}
