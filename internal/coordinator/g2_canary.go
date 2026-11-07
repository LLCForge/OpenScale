package coordinator

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/openscale/openscale/internal/trust"
)

// Warrant canary (#632, ADR-0180): a dated statement the owner signs with
// the root key on their own computer. The coordinator stores and serves it
// like any other signed object; it cannot renew or alter it. Devices warn
// when it is missing, expired or about to expire.

// Canary is the signed payload.
type Canary struct {
	Schema    int       `json:"schema"`
	NetworkID string    `json:"network_id"`
	Seq       uint64    `json:"seq"`
	IssuedAt  time.Time `json:"issued_at"`
	NotAfter  time.Time `json:"not_after"`
	// Signer is the root public key (repeated so a reader can compare
	// fingerprints before trusting it).
	Signer    trust.Key `json:"signer"`
	Statement string    `json:"statement"`
}

const (
	canarySchema = 1
	// MaxCanaryLife bounds NotAfter - IssuedAt.
	MaxCanaryLife = 90 * 24 * time.Hour
	// MinCanaryLife is the shortest allowed validity.
	MinCanaryLife = 24 * time.Hour
	// CanaryWarnBefore is when devices start warning before expiry.
	CanaryWarnBefore = 7 * 24 * time.Hour
	// MaxCanaryStatement bounds the statement in bytes.
	MaxCanaryStatement = 2000
)

// CanaryState is the verdict of a canary check.
type CanaryState string

const (
	CanaryValid    CanaryState = "valid"
	CanaryExpiring CanaryState = "expiring"
	CanaryExpired  CanaryState = "expired"
	CanaryMissing  CanaryState = "missing"
	CanaryInvalid  CanaryState = "invalid"
)

// Label is the Turkish display text of a state.
func (s CanaryState) Label() string {
	switch s {
	case CanaryValid:
		return "Kanarya beyanı geçerli."
	case CanaryExpiring:
		return "Kanarya beyanının süresi bir hafta içinde doluyor; sahip yenilemeli."
	case CanaryExpired:
		return "Kanarya beyanı süresinde yenilenmedi. Sahibin baskı altında olabileceğini veya erişemediğini düşünün."
	case CanaryMissing:
		return "Koordinatörde kanarya beyanı yok."
	}
	return "Kanarya beyanı doğrulanamadı; sahte veya bozuk olabilir."
}

// Validate checks the fields.
func (c Canary) Validate() error {
	life := c.NotAfter.Sub(c.IssuedAt)
	switch {
	case c.Schema != canarySchema:
		return fmt.Errorf("unsupported canary schema %d", c.Schema)
	case c.NetworkID == "" || len(c.NetworkID) > 64:
		return errors.New("canary: bad network id")
	case c.Seq == 0:
		return errors.New("canary: sequence must start at 1")
	case c.IssuedAt.IsZero() || c.NotAfter.IsZero():
		return errors.New("canary: missing dates")
	case life < MinCanaryLife || life > MaxCanaryLife:
		return fmt.Errorf("canary: validity must be %s-%s", MinCanaryLife, MaxCanaryLife)
	case c.Signer.IsZero():
		return errors.New("canary: missing signer")
	}
	return validStatement(c.Statement)
}

func validStatement(s string) error {
	if s == "" || len(s) > MaxCanaryStatement || !utf8.ValidString(s) {
		return fmt.Errorf("canary statement must be 1-%d bytes of UTF-8", MaxCanaryStatement)
	}
	if strings.IndexFunc(s, func(r rune) bool { return unicode.IsControl(r) && r != '\n' }) >= 0 {
		return errors.New("canary statement contains control characters")
	}
	return nil
}

// SignCanary signs c with the root private key. It must run on the owner's
// computer; signing is never delegated to the coordinator.
func SignCanary(root ed25519.PrivateKey, c Canary) ([]byte, error) {
	if len(root) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid root key")
	}
	copy(c.Signer[:], root.Public().(ed25519.PublicKey))
	c.Schema = canarySchema
	c.IssuedAt, c.NotAfter = c.IssuedAt.UTC(), c.NotAfter.UTC()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	o, err := signObject(root, CanaryContext, payload)
	if err != nil {
		return nil, err
	}
	return EncodeSignedObject(o)
}

// OpenCanary verifies an encoded canary against the pinned root and network
// and returns it with its state at now. An invalid signature, another
// network or another signer is an error (CanaryInvalid).
func OpenCanary(data []byte, root ed25519.PublicKey, networkID string, now time.Time) (Canary, CanaryState, error) {
	if len(data) == 0 {
		return Canary{}, CanaryMissing, nil
	}
	o, err := DecodeSignedObject(data)
	if err != nil {
		return Canary{}, CanaryInvalid, err
	}
	var c Canary
	if err := strictJSON(o.Payload, &c); err != nil {
		return Canary{}, CanaryInvalid, fmt.Errorf("canary: %w", err)
	}
	if err := c.Validate(); err != nil {
		return Canary{}, CanaryInvalid, err
	}
	if c.NetworkID != networkID {
		return Canary{}, CanaryInvalid, errors.New("canary belongs to another network")
	}
	if len(root) != ed25519.PublicKeySize || trust.Key(root) != c.Signer {
		return Canary{}, CanaryInvalid, errors.New("canary is not signed by the root key")
	}
	if err := verifyObject(c.Signer, CanaryContext, o); err != nil {
		return Canary{}, CanaryInvalid, fmt.Errorf("canary: %w", err)
	}
	return c, canaryState(c, now), nil
}

func canaryState(c Canary, now time.Time) CanaryState {
	switch {
	case now.IsZero():
		return CanaryValid
	case !now.Before(c.NotAfter):
		return CanaryExpired
	case c.NotAfter.Sub(now) <= CanaryWarnBefore:
		return CanaryExpiring
	}
	return CanaryValid
}

// canaryPolicy accepts root-signed canaries of this network. Uploads must
// not be expired yet (renewing with an expired one makes no sense); a
// stored, expired canary is kept when loading (zero now).
func canaryPolicy(data []byte, doc *trust.Document, root ed25519.PublicKey, now time.Time) (uint64, error) {
	if doc == nil {
		return 0, errors.New("no document")
	}
	c, st, err := OpenCanary(data, root, doc.NetworkID, now)
	if err != nil {
		return 0, err
	}
	if st == CanaryMissing {
		return 0, errors.New("empty canary")
	}
	if !now.IsZero() {
		if st == CanaryExpired {
			return 0, errors.New("canary already expired")
		}
		if c.IssuedAt.After(now.Add(futureSkew)) {
			return 0, errors.New("canary issued in the future")
		}
	}
	return c.Seq, nil
}
