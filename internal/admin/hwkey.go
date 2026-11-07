package admin

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/openscale/openscale/internal/piv"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

// Root key on a PIV token (#3, ADR-0123). The token holds a copy of the
// same root key that root.key holds sealed with the passphrase: the key is
// imported, never generated on the token, so the passphrase-sealed file and
// its backups (ADR-0011) always remain a working way to sign. Day to day
// the owner signs with the token (PIN, optionally touch) and the passphrase
// is not typed.

// ErrTokenKeyMismatch means the token holds another key than this network's
// root.
var ErrTokenKeyMismatch = errors.New("the hardware token holds a different key than this network's root")

// ImportRootKeyToToken opens the root key with the passphrase and imports
// it into slot. The caller must have authenticated the management key on c.
// The token's public key is read back and compared with the root.
func (n *Network) ImportRootKeyToToken(passphrase []byte, c *piv.Client, slot, pinPolicy, touchPolicy byte) error {
	n.mu.Lock()
	sealed := n.sealed
	n.mu.Unlock()
	rootPriv, err := sealed.Open(passphrase)
	if err != nil {
		return err
	}
	defer wipe(rootPriv)
	if err := c.ImportEd25519(slot, rootPriv, pinPolicy, touchPolicy); err != nil {
		if errors.Is(err, piv.ErrKeyMismatch) {
			return ErrTokenKeyMismatch
		}
		return err
	}
	return nil
}

// CommitWith signs a prepared plan with a hardware-held root key and saves
// it, like Commit does with the passphrase.
func (n *Network) CommitWith(plan *Plan, signer trust.DigestSigner) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if signer == nil {
		return errors.New("no signer")
	}
	if subtle.ConstantTimeCompare(signer.PublicKey(), n.sealed.PublicKey[:]) != 1 {
		return ErrTokenKeyMismatch
	}
	if plan == nil || plan.Next == nil || plan.base != n.doc.Version || plan.Next.Version <= plan.base {
		return ErrConcurrentChange
	}
	onDisk, err := readDocument(filepath.Join(n.dir, documentFile), n.sealed.RootPublicKey())
	if err != nil {
		return err
	}
	if onDisk.Version != n.doc.Version {
		n.doc = onDisk
		return ErrConcurrentChange
	}
	signed, membersPlain, err := n.sealForSigning(plan.Next) // members-only (#629, members_only.go)
	if err != nil {
		return err
	}
	env, err := trust.SignDocumentWith(signed, signer)
	if err != nil {
		return err
	}
	carrySensitive(filepath.Join(n.dir, documentFile), &env, signed) // ADR-0174, g1_admin.go
	data, err := trust.MarshalEnvelope(env)
	if err != nil {
		return err
	}
	// Same order as save: history first (never overwritten), then the
	// current document.
	if err := recordSigned(n.dir, env, signed); err != nil { // #342, ledger.go
		return err
	}
	if err := writeMembersPart(n.dir, plan.Next.Version, membersPlain); err != nil {
		return err
	}
	historyPath := filepath.Join(n.dir, historyDir, historyName(plan.Next.Version))
	if err := securefile.WriteNew(historyPath, data); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return ErrHistoryVersionUsed
		}
		return fmt.Errorf("write history: %w", err)
	}
	if err := securefile.Replace(filepath.Join(n.dir, documentFile), data); err != nil {
		return fmt.Errorf("write network document: %w", err)
	}
	n.doc = plan.Next
	return nil
}
