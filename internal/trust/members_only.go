package trust

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"

	"golang.org/x/crypto/chacha20poly1305"
)

// Members-only document (blind coordinator, #629, ADR-0178).
//
// When the owner turns it on, the signed document is split in two:
//
//   - the public part is the ordinary document with every device name
//     replaced by a pseudonym derived from its id (PublicDeviceName) and
//     without tags, aliases, rules, groups, exit users, DNS settings, DNS
//     profiles, MagicDNS, the display name, named hosts and policy tests.
//     It still carries device ids, keys, tunnel addresses, roles, routes,
//     endpoint hints, the version and the coordinator pins, so the
//     coordinator verifies and serves it exactly as before;
//   - the members part holds the removed fields. It is encrypted once and
//     its content key is wrapped for every device of the document
//     (SealPrivatePart, g1_private_part.go). A fresh content key is drawn
//     for every version, so a device added later can read the next version
//     and a removed device cannot.
//
// The root signature covers the public part, the ciphertext and the
// SHA-256 of the members part's plaintext, so it covers both parts. A
// member opens the part, checks the digest, merges it into the public part
// and validates the merged document with the normal rules before using it.
//
// Opt-in: documents without members_only encode exactly as before. Old
// clients refuse a document with the field (strict decoding), so turning
// it on requires min_client_version >= MembersOnlyMinClientVersion.

// MembersOnlyMinClientVersion is the first client version that can open a
// members-only document. A document with members_only must carry a
// min_client_version at least this high.
const MembersOnlyMinClientVersion = "1.0.0"

// membersPlainFormat names the plaintext encoding of the members part.
const membersPlainFormat = "openscale-members-part-v1"

// publicNamePrefix starts every pseudonymous device name of a public part.
const publicNamePrefix = "m"

// ErrMembersOnly is returned for members-only documents that cannot be
// sealed, opened or merged.
var ErrMembersOnly = errors.New("members-only document part is invalid")

// MembersOnly is the encrypted members part of a public document.
type MembersOnly struct {
	// Digest is the hex SHA-256 of the members part's plaintext.
	Digest string       `json:"digest"`
	Part   *PrivatePart `json:"part"`
}

// membersDevice is the private data of one device.
type membersDevice struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Tags    []string `json:"tags,omitempty"`
	Aliases []string `json:"aliases,omitempty"`
	// Icon is sealed too: a camera icon tells what a device is (ADR-0232).
	Icon DeviceIcon `json:"icon,omitempty"`
}

// membersPlain is the plaintext of the members part.
type membersPlain struct {
	Format      string            `json:"format"`
	Devices     []membersDevice   `json:"devices"`
	Rules       []Rule            `json:"rules"`
	Groups      []Group           `json:"groups,omitempty"`
	ExitUsers   *[]string         `json:"exit_users,omitempty"`
	DNS         *DNSSettings      `json:"dns,omitempty"`
	DNSProfiles []DNSProfile      `json:"dns_profiles,omitempty"`
	MagicDNS    *MagicDNSSettings `json:"magic_dns,omitempty"`
	DisplayName string            `json:"display_name,omitempty"`
	Hosts       []NamedAddress    `json:"hosts,omitempty"`
	PolicyTests []PolicyTest      `json:"policy_tests,omitempty"`
}

// PublicDeviceName is the pseudonym a device carries in the public part.
func PublicDeviceName(id string) string { return publicNamePrefix + id }

// IsMembersOnly reports whether doc is the public part of a members-only
// document, i.e. names, tags and rules are not in it.
func IsMembersOnly(doc *Document) bool { return doc != nil && doc.MembersOnly != nil }

// SealMembersOnly splits the complete document full into its public part,
// with the members part encrypted for every device of full, and returns
// the public part (to sign and publish) and the members part's plaintext
// (for the owner's own copy, see MergeMembersPlain). full is not modified.
func SealMembersOnly(full *Document, random io.Reader) (*Document, []byte, error) {
	if full == nil || full.MembersOnly != nil {
		return nil, nil, fmt.Errorf("%w: the document is already sealed", ErrMembersOnly)
	}
	normalizeSlices(full)
	if err := full.Validate(); err != nil {
		return nil, nil, fmt.Errorf("invalid document: %w", err)
	}
	if err := full.CheckPolicyTests(); err != nil {
		return nil, nil, err
	}
	if err := checkMembersOnlyCompatible(full); err != nil {
		return nil, nil, err
	}
	plain := membersPlain{Format: membersPlainFormat, Devices: make([]membersDevice, 0, len(full.Devices)),
		Rules: full.Rules, Groups: full.Groups, ExitUsers: full.ExitUsers, DNS: full.DNS, DNSProfiles: full.DNSProfiles,
		MagicDNS: full.MagicDNS, DisplayName: full.DisplayName, Hosts: full.Hosts, PolicyTests: full.PolicyTests}
	recipients := make([]PrivateRecipient, 0, len(full.Devices))
	for _, d := range full.Devices {
		plain.Devices = append(plain.Devices, membersDevice{ID: d.ID, Name: d.Name, Tags: d.Tags, Aliases: d.Aliases, Icon: d.Icon})
		recipients = append(recipients, PrivateRecipient{DeviceID: d.ID, WireGuardKey: d.WireGuardKey})
	}
	if len(recipients) == 0 {
		return nil, nil, fmt.Errorf("%w: a members-only document needs at least one device", ErrMembersOnly)
	}
	plainBytes, err := json.Marshal(plain)
	if err != nil {
		return nil, nil, err
	}
	part, err := SealPrivatePart(plainBytes, recipients, full.NetworkID, full.Version, random)
	if err != nil {
		return nil, nil, err
	}
	pub, err := cloneDocument(full)
	if err != nil {
		return nil, nil, err
	}
	stripMembersFields(pub)
	sum := sha256.Sum256(plainBytes)
	pub.MembersOnly = &MembersOnly{Digest: hex.EncodeToString(sum[:]), Part: part}
	normalizeSlices(pub)
	if err := pub.Validate(); err != nil {
		return nil, nil, fmt.Errorf("invalid public part: %w", err)
	}
	return pub, plainBytes, nil
}

// checkMembersOnlyCompatible refuses complete documents whose remaining
// public fields would reveal names or tags, and documents old clients could
// receive.
func checkMembersOnlyCompatible(full *Document) error {
	if !ClientVersionAtLeast(full.MinClientVersion, MembersOnlyMinClientVersion) || full.MinClientVersion == "" {
		return fmt.Errorf("%w: min_client_version must be at least %s", ErrMembersOnly, MembersOnlyMinClientVersion)
	}
	if full.Sensitive != nil {
		// Sensitive targets are device names and tags (ADR-0174) and are
		// enforced on the public part by every member's state.
		return fmt.Errorf("%w: the sensitive device policy names devices and cannot be sealed yet", ErrMembersOnly)
	}
	for _, inv := range full.Invites {
		if len(inv.Tags) > 0 {
			return fmt.Errorf("%w: invites with tags would reveal tags to the coordinator", ErrMembersOnly)
		}
	}
	return nil
}

func stripMembersFields(doc *Document) {
	for i := range doc.Devices {
		doc.Devices[i].Name = PublicDeviceName(doc.Devices[i].ID)
		doc.Devices[i].Tags = nil
		doc.Devices[i].Aliases = nil
		doc.Devices[i].Icon = ""
	}
	doc.Rules = []Rule{}
	doc.Groups = nil
	doc.ExitUsers = nil
	doc.DNS = nil
	doc.DNSProfiles = nil
	doc.MagicDNS = nil
	doc.DisplayName = ""
	doc.Hosts = nil
	doc.PolicyTests = nil
}

// validateMembersOnly checks the public part of a members-only document
// strictly: nothing private left in the clear, a well-formed encrypted
// part wrapped for exactly the document's devices and the client minimum.
func (doc *Document) validateMembersOnly() error {
	m := doc.MembersOnly
	if m == nil {
		return nil
	}
	bad := func(msg string) error { return fmt.Errorf("members_only: %s", msg) }
	if !isLowerHex256(m.Digest) {
		return bad("digest must be 64 lowercase hex characters")
	}
	if !ClientVersionAtLeast(doc.MinClientVersion, MembersOnlyMinClientVersion) || doc.MinClientVersion == "" {
		return bad("min_client_version must be at least " + MembersOnlyMinClientVersion)
	}
	switch {
	case len(doc.Rules) != 0, doc.Groups != nil, doc.ExitUsers != nil, doc.DNS != nil, doc.DNSProfiles != nil,
		doc.MagicDNS != nil, doc.DisplayName != "", doc.Hosts != nil, doc.PolicyTests != nil, doc.Sensitive != nil:
		return bad("private fields must not appear in the public part")
	}
	for _, inv := range doc.Invites {
		if len(inv.Tags) > 0 {
			return bad("invite tags must not appear in the public part")
		}
	}
	for _, d := range doc.Devices {
		if d.Name != PublicDeviceName(d.ID) || d.Tags != nil || d.Aliases != nil || d.Icon != "" {
			return bad("device names, tags and aliases must not appear in the public part")
		}
	}
	p := m.Part
	if p == nil || p.Format != privatePartFormat || p.Ephemeral.IsZero() || len(p.Nonce) != chacha20poly1305.NonceSizeX {
		return bad("part is malformed")
	}
	if len(p.Ciphertext) < chacha20poly1305.Overhead || len(p.Ciphertext) > maxPrivatePlaintext+chacha20poly1305.Overhead {
		return bad("ciphertext size is out of range")
	}
	if len(p.Recipients) != len(doc.Devices) {
		return bad("the part must be wrapped for exactly the document's devices")
	}
	ids := make(map[string]bool, len(doc.Devices))
	for _, d := range doc.Devices {
		ids[d.ID] = true
	}
	for i, r := range p.Recipients {
		if !ids[r.DeviceID] || len(r.Wrapped) != chacha20poly1305.KeySize+chacha20poly1305.Overhead {
			return bad("recipient is unknown or malformed")
		}
		if i > 0 && p.Recipients[i-1].DeviceID >= r.DeviceID {
			return bad("recipients must be sorted and distinct")
		}
	}
	return nil
}

func isLowerHex256(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == sha256.Size && hex.EncodeToString(b) == s
}

// OpenMembersOnly decrypts pub's members part with this device's id and
// WireGuard private key and returns the complete document. pub must
// already be verified (State.Accept); it is not modified. A document
// without members_only is returned unchanged.
func OpenMembersOnly(pub *Document, deviceID string, wgPriv []byte) (*Document, error) {
	if !IsMembersOnly(pub) {
		return pub, nil
	}
	plain, err := OpenPrivatePart(pub.MembersOnly.Part, deviceID, wgPriv, pub.NetworkID, pub.Version)
	if err != nil {
		return nil, err
	}
	defer wipe(plain)
	return MergeMembersPlain(pub, plain)
}

// MergeMembersPlain merges a members part's plaintext into the verified
// public part pub. The plaintext must match the signed digest; the merged
// document must pass Validate. The owner uses it with the copy of the
// plaintext kept next to network.json.
func MergeMembersPlain(pub *Document, plain []byte) (*Document, error) {
	if !IsMembersOnly(pub) {
		return nil, fmt.Errorf("%w: the document is not sealed", ErrMembersOnly)
	}
	sum := sha256.Sum256(plain)
	if hex.EncodeToString(sum[:]) != pub.MembersOnly.Digest {
		return nil, fmt.Errorf("%w: digest does not match the signed document", ErrMembersOnly)
	}
	var mp membersPlain
	if err := decodeStrict(plain, &mp); err != nil || mp.Format != membersPlainFormat {
		return nil, fmt.Errorf("%w: cannot decode the members part", ErrMembersOnly)
	}
	if len(mp.Devices) != len(pub.Devices) {
		return nil, fmt.Errorf("%w: device lists differ", ErrMembersOnly)
	}
	full, err := cloneDocument(pub)
	if err != nil {
		return nil, err
	}
	for i := range full.Devices {
		md := mp.Devices[i]
		if md.ID != full.Devices[i].ID {
			return nil, fmt.Errorf("%w: device lists differ", ErrMembersOnly)
		}
		full.Devices[i].Name, full.Devices[i].Tags, full.Devices[i].Aliases = md.Name, slices.Clone(md.Tags), slices.Clone(md.Aliases)
		full.Devices[i].Icon = md.Icon
	}
	full.Rules, full.Groups, full.ExitUsers, full.DNS = mp.Rules, mp.Groups, mp.ExitUsers, mp.DNS
	full.DNSProfiles, full.MagicDNS, full.DisplayName = mp.DNSProfiles, mp.MagicDNS, mp.DisplayName
	full.Hosts, full.PolicyTests = mp.Hosts, mp.PolicyTests
	full.MembersOnly = nil
	normalizeSlices(full)
	if err := full.Validate(); err != nil {
		return nil, fmt.Errorf("%w: merged document: %v", ErrMembersOnly, err)
	}
	return full, nil
}
