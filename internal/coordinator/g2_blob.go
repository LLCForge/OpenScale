package coordinator

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openscale/openscale/internal/trust"
)

// SealedBlob is the signed payload of a sealed admin blob (ADR-0180): an
// opaque ciphertext the owner's tools sealed for themselves, e.g. the
// pre-signed emergency documents of #682 or k-of-n shares (ADR-0121). The
// coordinator never sees the plaintext; it only checks that the root or a
// current admin device signed the newest sequence number.
type SealedBlob struct {
	Schema    int       `json:"schema"`
	NetworkID string    `json:"network_id"`
	Kind      string    `json:"kind"`
	Seq       uint64    `json:"seq"`
	IssuedAt  time.Time `json:"issued_at"`
	// Signer is the Ed25519 public key that signed: the root key or the
	// signing key of a device with the admin role.
	Signer trust.Key `json:"signer"`
	Sealed []byte    `json:"sealed"`
}

const sealedBlobSchema = 1

// Validate checks the fields of a sealed blob.
func (b SealedBlob) Validate() error {
	switch {
	case b.Schema != sealedBlobSchema:
		return fmt.Errorf("unsupported sealed blob schema %d", b.Schema)
	case b.NetworkID == "" || len(b.NetworkID) > 64:
		return errors.New("sealed blob: bad network id")
	case !ValidBlobKind(b.Kind):
		return errors.New("sealed blob: bad kind")
	case b.Seq == 0:
		return errors.New("sealed blob: sequence must start at 1")
	case b.IssuedAt.IsZero():
		return errors.New("sealed blob: missing issue time")
	case b.Signer.IsZero():
		return errors.New("sealed blob: missing signer")
	case len(b.Sealed) == 0 || len(b.Sealed) > MaxSealedBlob:
		return fmt.Errorf("sealed blob: ciphertext must be 1-%d bytes", MaxSealedBlob)
	}
	return nil
}

// SignSealedBlob signs b with priv (the root key or an admin device's
// signing key). It runs on the owner's computer; the coordinator never
// holds a key that could sign one.
func SignSealedBlob(priv ed25519.PrivateKey, b SealedBlob) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid signing key")
	}
	copy(b.Signer[:], priv.Public().(ed25519.PublicKey))
	b.Schema = sealedBlobSchema
	if err := b.Validate(); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	o, err := signObject(priv, SealedBlobContext, payload)
	if err != nil {
		return nil, err
	}
	return EncodeSignedObject(o)
}

// OpenSealedBlob verifies an encoded sealed blob against doc and root: the
// signer must be root or a device holding the admin role in doc, unexpired
// at now (zero now skips the expiry and clock checks). Readers call it with
// their own pinned root and document.
func OpenSealedBlob(data []byte, doc *trust.Document, root ed25519.PublicKey, now time.Time) (SealedBlob, error) {
	o, err := DecodeSignedObject(data)
	if err != nil {
		return SealedBlob{}, err
	}
	var b SealedBlob
	if err := strictJSON(o.Payload, &b); err != nil {
		return SealedBlob{}, fmt.Errorf("sealed blob: %w", err)
	}
	if err := b.Validate(); err != nil {
		return SealedBlob{}, err
	}
	if doc == nil || b.NetworkID != doc.NetworkID {
		return SealedBlob{}, errors.New("sealed blob belongs to another network")
	}
	if !now.IsZero() && b.IssuedAt.After(now.Add(futureSkew)) {
		return SealedBlob{}, errors.New("sealed blob issued in the future")
	}
	if !blobSignerAllowed(b.Signer, doc, root, now) {
		return SealedBlob{}, errors.New("sealed blob signer is neither the root nor an admin device")
	}
	if err := verifyObject(b.Signer, SealedBlobContext, o); err != nil {
		return SealedBlob{}, fmt.Errorf("sealed blob: %w", err)
	}
	return b, nil
}

func blobSignerAllowed(k trust.Key, doc *trust.Document, root ed25519.PublicKey, now time.Time) bool {
	if len(root) == ed25519.PublicKeySize && trust.Key(root) == k {
		return true
	}
	for _, d := range doc.Devices {
		if d.SigningKey == k && d.HasRole(trust.RoleAdmin) && (now.IsZero() || now.Before(d.ExpiresAt)) {
			return true
		}
	}
	return false
}

// sealedBlobPolicy accepts blobs of one kind.
func sealedBlobPolicy(kind string) objectPolicy {
	return func(data []byte, doc *trust.Document, root ed25519.PublicKey, now time.Time) (uint64, error) {
		b, err := OpenSealedBlob(data, doc, root, now)
		if err != nil {
			return 0, err
		}
		if b.Kind != kind {
			return 0, errors.New("sealed blob kind does not match its slot")
		}
		return b.Seq, nil
	}
}
