package admin

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/openscale/openscale/internal/trust"
)

// Portable administrator (ADR-0172). The administrator key and its grant
// are sealed with a passphrase (Argon2id + XChaCha20-Poly1305) into an
// opaque blob that the coordinator may store, so the administrator can
// sign from another computer after typing the passphrase. The coordinator
// only ever sees the blob and its id; decryption happens on the client.
// Because the coordinator can attack the blob offline, the default KDF
// cost is higher than the root key's and the passphrase policy applies.

// PortableAdminFormat is the sealed secret format of the portable blob.
const PortableAdminFormat = "openscale-admin-portable-v1"

// PortableArgon2 is the default KDF cost of a portable blob: 256 MiB.
var PortableArgon2 = trust.Argon2Params{Time: 4, MemoryKiB: 256 * 1024, Threads: 4}

// MaxPortableBlob bounds a portable blob; the coordinator's store (G2,
// ADR-0180: at most 48 KiB) refuses larger uploads.
const MaxPortableBlob = 48 << 10

// AdminBlobStore keeps opaque portable blobs. The coordinator side is
// implemented elsewhere (G2); this package only needs these calls. ids are
// 64 lowercase hex characters; the store must not interpret the blob.
type AdminBlobStore interface {
	PutAdminBlob(ctx context.Context, id string, blob []byte) error
	GetAdminBlob(ctx context.Context, id string) ([]byte, error)
	DeleteAdminBlob(ctx context.Context, id string) error
}

type portablePlain struct {
	Seed  []byte          `json:"seed"`
	Grant json.RawMessage `json:"grant"`
}

// AdminBlobID derives a blob's id from the network and the administrator's
// name, so another computer finds it without a list; it reveals neither.
func AdminBlobID(networkID, name string) string {
	h := sha256.New()
	h.Write([]byte("openscale/admin-blob-id/v1\x00"))
	h.Write([]byte(networkID))
	h.Write([]byte{0})
	h.Write([]byte(name))
	return hex.EncodeToString(h.Sum(nil))
}

// SealPortableAdmin seals priv and its grant into a portable blob.
func SealPortableAdmin(priv ed25519.PrivateKey, grant trust.SignedGrant, passphrase []byte, params trust.Argon2Params, random io.Reader) (string, []byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", nil, errors.New("invalid administrator key")
	}
	if string(priv.Public().(ed25519.PublicKey)) != string(grant.Grant.Key[:]) {
		return "", nil, trust.ErrAdminMismatch
	}
	seed := priv.Seed()
	defer wipe(seed)
	plain, err := json.Marshal(portablePlain{Seed: seed, Grant: grant.Encoded})
	if err != nil {
		return "", nil, err
	}
	defer wipe(plain)
	id := AdminBlobID(grant.Grant.NetworkID, grant.Grant.Name)
	sealed, err := trust.SealSecret(PortableAdminFormat, id, plain, passphrase, params, random)
	if err != nil {
		return "", nil, err
	}
	data, err := trust.MarshalSealedSecret(sealed)
	if err != nil {
		return "", nil, err
	}
	if len(data) > MaxPortableBlob {
		return "", nil, errors.New("portable blob is too large")
	}
	return id, data, nil
}

// OpenPortableAdmin decrypts a portable blob and verifies the grant
// against the root key. The caller wipes the key with trust.WipeKey.
func OpenPortableAdmin(blob, passphrase []byte, root ed25519.PublicKey, networkID string) (ed25519.PrivateKey, trust.SignedGrant, error) {
	if len(blob) > MaxPortableBlob {
		return nil, trust.SignedGrant{}, errors.New("portable blob is too large")
	}
	sealed, err := trust.UnmarshalSealedSecret(blob, PortableAdminFormat)
	if err != nil {
		return nil, trust.SignedGrant{}, err
	}
	plain, err := sealed.Open(PortableAdminFormat, passphrase)
	if err != nil {
		return nil, trust.SignedGrant{}, err
	}
	defer trust.WipeKey(plain)
	var p portablePlain
	if err := json.Unmarshal(plain, &p); err != nil || len(p.Seed) != ed25519.SeedSize {
		return nil, trust.SignedGrant{}, trust.ErrWrongPassphrase
	}
	defer wipe(p.Seed)
	g, err := trust.OpenAdminGrant(p.Grant, root, networkID)
	if err != nil {
		return nil, trust.SignedGrant{}, err
	}
	if sealed.Label != AdminBlobID(g.NetworkID, g.Name) {
		return nil, trust.SignedGrant{}, errors.New("portable blob does not match its grant")
	}
	priv := ed25519.NewKeyFromSeed(p.Seed)
	if string(priv.Public().(ed25519.PublicKey)) != string(g.Key[:]) {
		wipe(priv)
		return nil, trust.SignedGrant{}, trust.ErrAdminMismatch
	}
	return priv, trust.SignedGrant{Grant: *g, Encoded: append([]byte(nil), p.Grant...)}, nil
}

// UploadPortableAdmin seals and stores the blob.
func UploadPortableAdmin(ctx context.Context, store AdminBlobStore, priv ed25519.PrivateKey, grant trust.SignedGrant, passphrase []byte, params trust.Argon2Params, random io.Reader) (string, error) {
	if store == nil {
		return "", errors.New("no blob store")
	}
	id, blob, err := SealPortableAdmin(priv, grant, passphrase, params, random)
	if err != nil {
		return "", err
	}
	if err := store.PutAdminBlob(ctx, id, blob); err != nil {
		return "", fmt.Errorf("store portable blob: %w", err)
	}
	return id, nil
}

// DownloadPortableAdmin fetches and opens the blob of name.
func DownloadPortableAdmin(ctx context.Context, store AdminBlobStore, name string, passphrase []byte, root ed25519.PublicKey, networkID string) (ed25519.PrivateKey, trust.SignedGrant, error) {
	if store == nil {
		return nil, trust.SignedGrant{}, errors.New("no blob store")
	}
	blob, err := store.GetAdminBlob(ctx, AdminBlobID(networkID, name))
	if err != nil {
		return nil, trust.SignedGrant{}, fmt.Errorf("fetch portable blob: %w", err)
	}
	return OpenPortableAdmin(blob, passphrase, root, networkID)
}
