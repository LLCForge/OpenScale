package member

import (
	"github.com/openscale/openscale/internal/trust"
)

// Members-only documents (blind coordinator, #629, ADR-0178). The store
// keeps and persists the verified public part exactly as signed, so the
// rollback state and the disk copy never hold the members part in the
// clear. A device that registered its keys with SetMembersKey gets the
// complete document from Document and Snapshot; a coordinator, which has no
// such key, only ever sees the public part.

// membersView caches the opened document of the current public part.
type membersView struct {
	deviceID string
	wgPriv   []byte
	src      *trust.Document
	full     *trust.Document
	err      error
}

// SetMembersKey registers this device's id and WireGuard private key for
// opening members-only documents. The slice is used as is, not copied, so
// the caller's wiping of its secrets also covers the store.
func (s *Store) SetMembersKey(deviceID string, wgPriv []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.members = membersView{deviceID: deviceID, wgPriv: wgPriv}
}

// MembersPartError reports why the current members-only document could not
// be opened (nil when it was opened or the document is not sealed).
func (s *Store) MembersPartError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.viewLocked()
	return s.members.err
}

// viewLocked returns the document the device works with. When a sealed
// document cannot be opened the public part is returned: it has no rules,
// so the device allows no traffic (fail closed) and MembersPartError says
// why.
func (s *Store) viewLocked() *trust.Document {
	doc := s.doc
	if !trust.IsMembersOnly(doc) || s.members.deviceID == "" {
		return doc
	}
	if s.members.src == doc {
		return s.members.full
	}
	full, err := trust.OpenMembersOnly(doc, s.members.deviceID, s.members.wgPriv)
	if err != nil {
		full = doc
	}
	s.members.src, s.members.full, s.members.err = doc, full, err
	return full
}
