package admin

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

// Members-only documents, owner side (blind coordinator, #629, ADR-0178).
//
// The owner's tools keep working with the complete document in memory.
// When the setting is on, every signature seals it first
// (trust.SealMembersOnly): network.json and the history hold the signed
// public part, which is what the coordinator receives, and the members
// part's plaintext of the current version is kept next to network.json in
// members_part.json (owner-only file). readDocument merges it back after
// checking it against the signed digest.

const (
	membersOnlySettingFile = "members_only.json"
	membersPartFile        = "members_part.json"
	maxMembersPartFile     = 3 * (trust.MaxDocumentSize + 4096)
)

// ErrMembersPartMissing is returned when network.json is sealed but the
// owner's copy of the members part is missing or belongs to another
// version.
var ErrMembersPartMissing = errors.New("the members-only part of network.json is missing; restore members_part.json from the same version")

type membersOnlySetting struct {
	Enabled bool `json:"enabled"`
}

type membersPartCopy struct {
	Version uint64 `json:"version"`
	Plain   []byte `json:"plain"`
}

// MembersOnlyEnabled reports whether new versions are sealed for members.
func (n *Network) MembersOnlyEnabled() bool {
	return membersOnlyEnabled(n.dir)
}

func membersOnlyEnabled(dir string) bool {
	data, err := securefile.ReadPrivate(filepath.Join(dir, membersOnlySettingFile), 1024)
	if err != nil {
		return false
	}
	var s membersOnlySetting
	return json.Unmarshal(data, &s) == nil && s.Enabled
}

// SetMembersOnly turns sealing on or off for the next signed version. It
// signs nothing. Turning it on is refused unless the current document
// already requires a client that understands members-only documents.
func (n *Network) SetMembersOnly(on bool) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if on && !trust.ClientVersionAtLeast(n.doc.MinClientVersion, trust.MembersOnlyMinClientVersion) {
		return fmt.Errorf("%w: first set the minimum client version to %s or later", trust.ErrMembersOnly, trust.MembersOnlyMinClientVersion)
	}
	data, err := json.Marshal(membersOnlySetting{Enabled: on})
	if err != nil {
		return err
	}
	return securefile.Replace(filepath.Join(n.dir, membersOnlySettingFile), data)
}

// sealForSigning returns the document to sign for doc: doc itself, or its
// sealed public part and the members part's plaintext when the setting is
// on.
func (n *Network) sealForSigning(doc *trust.Document) (*trust.Document, []byte, error) {
	if !membersOnlyEnabled(n.dir) {
		return doc, nil, nil
	}
	return trust.SealMembersOnly(doc, rand.Reader)
}

// writeMembersPart keeps the owner's copy of a sealed version's members
// part. It is written before network.json and keeps the previous
// version too, so a crash between the two writes leaves both readable.
func writeMembersPart(dir string, version uint64, plain []byte) error {
	if plain == nil {
		return nil
	}
	copies := append(readMembersParts(dir), membersPartCopy{Version: version, Plain: plain})
	if len(copies) > 2 {
		copies = copies[len(copies)-2:]
	}
	data, err := json.Marshal(copies)
	if err != nil {
		return err
	}
	if err := securefile.Replace(filepath.Join(dir, membersPartFile), data); err != nil {
		return fmt.Errorf("write members part: %w", err)
	}
	return nil
}

// mergeMembersPart turns a verified sealed document read from dir back
// into the complete document. Unsealed documents are returned unchanged.
func mergeMembersPart(dir string, doc *trust.Document) (*trust.Document, error) {
	if !trust.IsMembersOnly(doc) {
		return doc, nil
	}
	data, err := securefile.ReadPrivate(filepath.Join(dir, membersPartFile), maxMembersPartFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrMembersPartMissing
		}
		return nil, fmt.Errorf("read members part: %w", err)
	}
	var copies []membersPartCopy
	if err := json.Unmarshal(data, &copies); err != nil {
		return nil, ErrMembersPartMissing
	}
	for _, c := range copies {
		if c.Version == doc.Version {
			return trust.MergeMembersPlain(doc, c.Plain)
		}
	}
	return nil, ErrMembersPartMissing
}

// readMembersParts returns the stored copies, or none when the file is
// missing or unreadable.
func readMembersParts(dir string) []membersPartCopy {
	data, err := securefile.ReadPrivate(filepath.Join(dir, membersPartFile), maxMembersPartFile)
	if err != nil {
		return nil
	}
	var copies []membersPartCopy
	if json.Unmarshal(data, &copies) != nil {
		return nil
	}
	return copies
}
