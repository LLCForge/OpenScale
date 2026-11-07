package admin

import (
	"crypto/subtle"
	"time"

	"github.com/openscale/openscale/internal/trust"
)

// PendingRotation is a key rotation request verified against the current
// document, waiting for the owner (ADR-0020).
type PendingRotation struct {
	Request     *trust.KeyRotationRequest
	Device      trust.Device
	Fingerprint string
	Signed      trust.SignedKeyRotation
}

// InspectKeyRotation decodes a rotation request line and verifies it
// against the current document. Nothing is signed.
func (n *Network) InspectKeyRotation(line string, now time.Time) (*PendingRotation, error) {
	sr, err := trust.DecodeKeyRotation(line)
	if err != nil {
		return nil, err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	req, err := trust.OpenKeyRotation(n.doc, sr, now)
	if err != nil {
		return nil, err
	}
	var dev trust.Device
	for _, d := range n.doc.Devices {
		if d.ID == req.DeviceID {
			dev = d
		}
	}
	return &PendingRotation{Request: req, Device: dev, Fingerprint: req.Fingerprint(), Signed: sr}, nil
}

// ApplyKeyRotation installs the device's new keys after the owner typed the
// fingerprint shown on the device. The request is verified again against
// the document being signed. A request signed with a stolen old key looks
// valid, which is why the fingerprint is mandatory here.
func (n *Network) ApplyKeyRotation(passphrase []byte, line, typedFingerprint string, now time.Time) (*Plan, error) {
	sr, err := trust.DecodeKeyRotation(line)
	if err != nil {
		return nil, err
	}
	return n.Apply(passphrase, now, func(doc *trust.Document) error {
		req, err := trust.OpenKeyRotation(doc, sr, now)
		if err != nil {
			return err
		}
		got := []byte(trust.NormalizeFingerprint(typedFingerprint))
		want := []byte(trust.NormalizeFingerprint(req.Fingerprint()))
		if len(got) == 0 || subtle.ConstantTimeCompare(got, want) != 1 {
			return ErrFingerprintMismatch
		}
		_, err = doc.ApplyKeyRotation(sr, now)
		return err
	})
}
