package admin

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

// Document export and import (#234). The export is the signed network
// document exactly as every device receives it: it holds no private key
// and is not a backup of the root key. An imported file is only verified
// and shown; nothing is signed or written, so importing can never roll the
// network back or resurrect a revoked device. Restoring the root key stays
// with "network restore" and its separately encrypted backup.

// ErrForeignDocument means a signed document verified against this
// network's root key names another network ID (it cannot normally happen,
// but the check costs nothing).
var ErrForeignDocument = errors.New("the document belongs to another network")

// SignedDocument returns the current signed document (network.json) after
// checking its signature again, so a file changed on disk is never handed
// out as genuine.
func (n *Network) SignedDocument() ([]byte, error) {
	n.mu.Lock()
	dir := n.dir
	root := n.sealed.RootPublicKey()
	n.mu.Unlock()
	data, err := securefile.ReadPrivate(filepath.Join(dir, documentFile), trust.MaxEnvelopeSize)
	if err != nil {
		return nil, fmt.Errorf("read network document: %w", err)
	}
	env, err := trust.UnmarshalEnvelope(data)
	if err != nil {
		return nil, err
	}
	if _, err := trust.VerifyDocumentSignature(env, root); err != nil {
		return nil, err
	}
	return data, nil
}

// InspectDocument verifies a signed document file against this network's
// root key and returns it. It changes nothing. Expired or older versions
// verify too: the caller compares versions and shows the difference.
func (n *Network) InspectDocument(data []byte) (*trust.Document, error) {
	if len(data) == 0 {
		return nil, errors.New("empty document")
	}
	if len(data) > trust.MaxEnvelopeSize {
		return nil, trust.ErrTooLarge
	}
	n.mu.Lock()
	root := n.sealed.RootPublicKey()
	networkID := n.doc.NetworkID
	n.mu.Unlock()
	env, err := trust.UnmarshalEnvelope(data)
	if err != nil {
		return nil, err
	}
	doc, err := trust.VerifyDocumentSignature(env, root)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare([]byte(doc.NetworkID), []byte(networkID)) != 1 {
		return nil, ErrForeignDocument
	}
	return doc, nil
}
