package openscale

import (
	"encoding/json"
	"time"

	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/trust"
)

// Lost device mode (#184, P27). The owner revokes a lost phone in the
// panel as for any device; the revocation is part of the root-signed
// document. When the phone next sees that document (the engine stops with
// "not a member"), or when the app starts, it asks RevocationStatus and,
// if this device's keys are revoked, deletes its Keystore key, its sealed
// device key and the network state. There is deliberately no "wipe"
// command over the control channel: the coordinator is not trusted, and a
// document it cannot forge is the only trigger. A device that is merely
// missing from the document (not added yet, membership expired) is not
// wiped.

type revocationStatus struct {
	// Revoked is true only when the verified document lists this device's
	// keys (or its id, with no device of that id left) as revoked.
	Revoked   bool      `json:"revoked"`
	RevokedAt time.Time `json:"revoked_at,omitzero"`
	// Member reports whether the document lists this device now.
	Member          bool   `json:"member"`
	DocumentVersion uint64 `json:"document_version"`
}

// RevocationStatus checks this device against the stored, root-verified
// network document and returns a JSON revocationStatus.
func RevocationStatus(stateDir string, secrets []byte) (string, error) {
	if err := checkStateDir(stateDir); err != nil {
		return "", err
	}
	store, err := member.Open(stateDir)
	if err != nil {
		return "", err
	}
	s, err := parseSecrets(secrets)
	if err != nil {
		return "", err
	}
	defer wipeSecrets(s)
	st, err := revocationOf(store.Document(), s)
	if err != nil {
		return "", err
	}
	out, err := json.Marshal(st)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func revocationOf(doc *trust.Document, s *trust.DeviceSecrets) (revocationStatus, error) {
	signing, wg, err := s.PublicKeys()
	if err != nil {
		return revocationStatus{}, err
	}
	st := revocationStatus{DocumentVersion: doc.Version}
	idListed := false
	for _, d := range doc.Devices {
		if d.WireGuardKey == wg && d.SigningKey == signing {
			st.Member = true
		}
		if d.ID == s.DeviceID {
			idListed = true
		}
	}
	for _, r := range doc.Revoked {
		if r.SigningKey == signing || r.WireGuardKey == wg || (r.DeviceID == s.DeviceID && !idListed) {
			st.Revoked, st.RevokedAt = true, r.RevokedAt
			break
		}
	}
	// A document cannot both list and revoke the same keys (validation
	// refuses it); stay on the safe side of a wipe anyway.
	if st.Member {
		st.Revoked = false
	}
	return st, nil
}
