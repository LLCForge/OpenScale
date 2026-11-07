package trust

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Membership extensions (ADR-0028): ephemeral devices, preauthorized
// enrollment keys, multi-use invites, self-requested leave and the minimum
// client version. Every new field is optional and omitted when unused, so
// documents that do not use them keep their exact bytes.

// Membership limits.
const (
	// MaxEphemeralLife bounds an ephemeral device's membership.
	MaxEphemeralLife = 30 * 24 * time.Hour
	// DefaultEphemeralLife is the membership of a new ephemeral device.
	DefaultEphemeralLife = 24 * time.Hour
	// MaxInviteUses bounds how many devices one invite can enroll.
	MaxInviteUses = 64
	// LeaveMaxAge limits how long a leave request stays usable.
	LeaveMaxAge = 30 * 24 * time.Hour
	// LeaveContext is the signature context of a device's leave request.
	LeaveContext = "openscale/device-leave/v1"
	// MaxLeavePayload keeps a leave request inside one control datagram.
	MaxLeavePayload = 512
	// maxClientVersionPart bounds each number of a client version.
	maxClientVersionPart = 99999

	leavePrefix     = "osleave1."
	maxLeaveChars   = 2048
	preauthPrefix   = "osauth1."
	maxPreauthChars = 3 << 20
)

// Membership errors.
var (
	ErrInvalidClientVersion = errors.New("client version must look like 1.2.3")
	ErrPreauthExpired       = errors.New("the preauthorized device's membership has expired")
	ErrNotPreauthorized     = errors.New("this key does not belong to a preauthorized device of the document")
	ErrLeaveExpired         = errors.New("leave request is too old or dated in the future")
	ErrEphemeralLifetime    = errors.New("an ephemeral device's membership must not exceed 30 days")
)

// MultiUse reports whether the invite may enroll more than one device.
func (i Invite) MultiUse() bool { return i.MaxUses > 1 }

// Exhausted reports whether no further device may enroll with the invite.
func (i Invite) Exhausted() bool {
	if i.MultiUse() {
		return len(i.Uses) >= i.MaxUses
	}
	return i.UsedBy != ""
}

// UsedFor reports whether the invite was already approved for deviceID.
func (i Invite) UsedFor(deviceID string) bool {
	return deviceID != "" && (i.UsedBy == deviceID || slices.Contains(i.Uses, deviceID))
}

// Remaining returns how many more devices may enroll with the invite.
func (i Invite) Remaining() int {
	if i.Exhausted() {
		return 0
	}
	if i.MultiUse() {
		return i.MaxUses - len(i.Uses)
	}
	return 1
}

func (doc *Document) markMultiUse(idx int, deviceID string) error {
	inv := &doc.Invites[idx]
	if inv.Exhausted() || inv.UsedFor(deviceID) {
		return ErrInviteUsed
	}
	inv.Uses = append(inv.Uses, deviceID)
	if err := doc.Validate(); err != nil {
		inv.Uses = inv.Uses[:len(inv.Uses)-1]
		if len(inv.Uses) == 0 {
			inv.Uses = nil
		}
		return err
	}
	return nil
}

// InviteOptions describes a new invite.
type InviteOptions struct {
	Life time.Duration
	Tags []string
	// MaxUses above 1 makes a multi-use invite (ADR-0028, F-184).
	MaxUses int
}

// AddInviteWith lists a new invite with options.
func (doc *Document) AddInviteWith(id string, keys *InviteKeys, now time.Time, opts InviteOptions) (Invite, error) {
	if opts.MaxUses < 0 || opts.MaxUses > MaxInviteUses {
		return Invite{}, fmt.Errorf("an invite may enroll 1-%d devices", MaxInviteUses)
	}
	inv, err := doc.AddTaggedInvite(id, keys, now, opts.Life, opts.Tags)
	if err != nil {
		return Invite{}, err
	}
	if opts.MaxUses <= 1 {
		return inv, nil
	}
	idx := slices.IndexFunc(doc.Invites, func(i Invite) bool { return i.ID == id })
	doc.Invites[idx].MaxUses = opts.MaxUses
	if err := doc.Validate(); err != nil {
		doc.Invites = slices.Delete(doc.Invites, idx, idx+1)
		if len(doc.Invites) == 0 {
			doc.Invites = nil
		}
		return Invite{}, err
	}
	return doc.Invites[idx], nil
}

// validateMembership checks the fields added by ADR-0027 and ADR-0028.
func (doc *Document) validateMembership() error {
	if doc.RootEpoch > MaxRootEpoch {
		return errors.New("root_epoch is too large")
	}
	if doc.MinClientVersion != "" {
		if _, _, ok := parseMinVersion(doc.MinClientVersion); !ok { // 1.2.3 or 1.2.3-beta.N (ADR-0232)
			return ErrInvalidClientVersion
		}
	}
	if err := checkRecoveryKeys(doc.RecoveryKeys); err != nil {
		return err
	}
	if len(doc.RecoveryKeys) > 0 {
		used := doc.usedKeys()
		for _, k := range doc.RecoveryKeys {
			if used[k] {
				return errors.New("recovery key is already used by a device, invite or coordinator")
			}
		}
	}
	for _, d := range doc.Devices {
		if d.Ephemeral && d.ExpiresAt.Sub(d.AddedAt) > MaxEphemeralLife {
			return fmt.Errorf("device %s: %w", d.Name, ErrEphemeralLifetime)
		}
		if d.Preauthorized && d.HasRole(RoleAdmin) {
			return fmt.Errorf("device %s: a preauthorized device cannot be an admin", d.Name)
		}
	}
	for i, inv := range doc.Invites {
		switch {
		case inv.MaxUses < 0 || inv.MaxUses > MaxInviteUses:
			return fmt.Errorf("invite %d: max_uses must be 0-%d", i, MaxInviteUses)
		case !inv.MultiUse() && len(inv.Uses) != 0:
			return fmt.Errorf("invite %d: a single-use invite records its device in used_by", i)
		case inv.MultiUse() && inv.UsedBy != "":
			return fmt.Errorf("invite %d: a multi-use invite records its devices in uses", i)
		case len(inv.Uses) > inv.MaxUses && inv.MultiUse():
			return fmt.Errorf("invite %d: used more often than allowed", i)
		}
		for j, id := range inv.Uses {
			if !isValidID(id) || slices.Contains(inv.Uses[:j], id) {
				return fmt.Errorf("invite %d: invalid or duplicate use", i)
			}
		}
	}
	return nil
}

// usedKeys returns every key a device, invite, coordinator, revocation or
// retirement uses.
func (doc *Document) usedKeys() map[Key]bool {
	used := map[Key]bool{}
	for _, d := range doc.Devices {
		used[d.SigningKey], used[d.WireGuardKey] = true, true
	}
	for _, inv := range doc.Invites {
		used[inv.SigningKey], used[inv.WireGuardKey] = true, true
	}
	for _, r := range doc.Revoked {
		used[r.SigningKey], used[r.WireGuardKey] = true, true
	}
	for _, r := range doc.RetiredKeys {
		used[r.SigningKey], used[r.WireGuardKey] = true, true
	}
	if doc.Coordinator != nil {
		used[doc.Coordinator.WireGuardKey] = true
	}
	return used
}

// AddRecoveryKey publishes a recovery key's public half (ADR-0027).
func (doc *Document) AddRecoveryKey(k Key) error {
	if slices.Contains(doc.RecoveryKeys, k) {
		return errors.New("recovery key is already listed")
	}
	return doc.transact(func() error {
		doc.RecoveryKeys = append(doc.RecoveryKeys, k)
		return nil
	})
}

// SetMinClientVersion sets the oldest client version the coordinator
// serves; "" removes the minimum (F-027).
func (doc *Document) SetMinClientVersion(v string) error {
	v = strings.TrimSpace(v)
	if v != "" {
		if _, _, ok := parseMinVersion(v); !ok {
			return ErrInvalidClientVersion
		}
	}
	return doc.transact(func() error {
		doc.MinClientVersion = v
		return nil
	})
}

// parseStrictVersion parses "major.minor.patch" with plain decimal numbers.
func parseStrictVersion(s string) ([3]int, bool) {
	var out [3]int
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		if p == "" || len(p) > 5 || (len(p) > 1 && p[0] == '0') {
			return out, false
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > maxClientVersionPart {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

// ParseClientVersion parses a reported client version such as "1.2.3",
// "v1.2.3", "1.2.3-rc1" or "1.2.3 (abc)". A pre-release suffix is ignored:
// 1.2.3-rc1 counts as 1.2.3.
func ParseClientVersion(s string) ([3]int, bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if i := strings.IndexAny(s, " -+"); i >= 0 {
		s = s[:i]
	}
	return parseStrictVersion(s)
}

// ClientVersionAtLeast reports whether the reported version have is at
// least min. An unparsable reported version never satisfies a minimum.
func ClientVersionAtLeast(have, min string) bool {
	if min == "" {
		return true
	}
	m, mb, ok := parseMinVersion(min)
	if !ok {
		return false
	}
	h, ok := ParseClientVersion(have)
	if !ok {
		return false
	}
	for i := range h {
		if h[i] != m[i] {
			return h[i] > m[i]
		}
	}
	// A minimum with a beta suffix (ADR-0232) refuses older betas of the
	// same numbers; the release and any other suffix pass, as before.
	if mb == 0 {
		return true
	}
	hb := reportedBeta(have)
	return hb == 0 || hb >= mb
}

// RevokeDevices revokes several devices in one version, for example the
// inactive devices the owner selected (F-114). It returns the number of
// rules dropped because they had no source or destination left.
func (doc *Document) RevokeDevices(names []string, now time.Time) (int, error) {
	if len(names) == 0 {
		return 0, errors.New("no device selected")
	}
	dropped := 0
	err := doc.transact(func() error {
		seen := map[string]bool{}
		for _, name := range names {
			if seen[name] {
				continue
			}
			seen[name] = true
			n, err := doc.RevokeDevice(name, now)
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			dropped += n
		}
		return nil
	})
	return dropped, err
}

// PruneEphemeral revokes every ephemeral device whose membership has ended
// and returns their names (#22). The owner's tooling calls it on every
// signed version, so expired temporary devices leave the document without
// an extra step; the coordinator never removes anything itself.
func (doc *Document) PruneEphemeral(now time.Time) []string {
	var names []string
	for _, d := range doc.Devices {
		if d.Ephemeral && !now.Before(d.ExpiresAt) {
			names = append(names, d.Name)
		}
	}
	if len(names) == 0 {
		return nil
	}
	if _, err := doc.RevokeDevices(names, now); err != nil {
		return nil
	}
	return names
}

// SetDeviceEphemeral marks a device as ephemeral or permanent. Marking it
// ephemeral shortens a longer membership to DefaultEphemeralLife from now.
func (doc *Document) SetDeviceEphemeral(name string, on bool, now time.Time) error {
	idx := slices.IndexFunc(doc.Devices, func(d Device) bool { return d.Name == name })
	if idx < 0 {
		return ErrUnknownDevice
	}
	return doc.transact(func() error {
		d := &doc.Devices[idx]
		d.Ephemeral = on
		if on && d.ExpiresAt.Sub(d.AddedAt) > MaxEphemeralLife {
			end := roundTimestamp(now).Add(DefaultEphemeralLife)
			if !end.After(d.AddedAt) {
				end = d.AddedAt.Add(time.Second)
			}
			if end.Sub(d.AddedAt) > MaxEphemeralLife {
				return ErrEphemeralLifetime
			}
			d.ExpiresAt = end
		}
		return nil
	})
}

// --- Preauthorized enrollment keys (F-098) ---

// PreauthKey lets a server or container join without interaction. The
// owner generated the device keys and signed a document that already lists
// the device, so joining needs no further approval; the key is therefore a
// secret and works for exactly one device identity.
type PreauthKey struct {
	RootKey  Key           `json:"root_key"`
	Device   DeviceSecrets `json:"device"`
	Document Envelope      `json:"document"`
}

// PreauthOptions describes a preauthorized device.
type PreauthOptions struct {
	Name      string
	Tags      []string
	Lifetime  time.Duration
	Ephemeral bool
	ExitNode  bool
}

// AddPreauthorizedDevice lists a device whose keys the owner generated
// (secrets) under opts. It never gets the admin role.
func (doc *Document) AddPreauthorizedDevice(secrets *DeviceSecrets, opts PreauthOptions, now time.Time) (Device, error) {
	if err := secrets.validate(); err != nil {
		return Device{}, err
	}
	if opts.Ephemeral && opts.Lifetime > MaxEphemeralLife {
		return Device{}, ErrEphemeralLifetime
	}
	signing, wg, err := secrets.PublicKeys()
	if err != nil {
		return Device{}, err
	}
	for _, k := range []Key{signing, wg} {
		if err := doc.checkKeyFree(k); err != nil {
			return Device{}, err
		}
	}
	req := &EnrollmentRequest{DeviceID: secrets.DeviceID, SigningKey: signing, WireGuardKey: wg, Hostname: opts.Name, CreatedAt: roundTimestamp(now)}
	var roles []Role
	if opts.ExitNode {
		roles = []Role{RoleExitNode}
	}
	var out Device
	err = doc.transact(func() error {
		d, err := doc.AddDevice(req, opts.Name, roles, now, opts.Lifetime)
		if err != nil {
			return err
		}
		idx := slices.IndexFunc(doc.Devices, func(x Device) bool { return x.ID == d.ID })
		doc.Devices[idx].Preauthorized = true
		doc.Devices[idx].Ephemeral = opts.Ephemeral
		if len(opts.Tags) > 0 {
			doc.Devices[idx].Tags = cleanTags(opts.Tags)
		}
		out = doc.Devices[idx]
		return nil
	})
	return out, err
}

// EncodePreauthKey returns the single-line form of a preauthorized key.
func EncodePreauthKey(k *PreauthKey) (string, error) {
	if err := k.Device.validate(); err != nil {
		return "", err
	}
	data, err := json.Marshal(k)
	if err != nil {
		return "", fmt.Errorf("encode enrollment key: %w", err)
	}
	line := preauthPrefix + base64.RawURLEncoding.EncodeToString(data)
	if len(line) > maxPreauthChars {
		return "", errors.New("enrollment key is too large")
	}
	return line, nil
}

// OpenPreauthKey decodes a preauthorized key, verifies its document against
// the root key it carries (the key itself is the trust anchor, like an
// invite code) and checks that the document lists the device with exactly
// these keys and that its membership is still valid.
func OpenPreauthKey(line string, now time.Time) (*PreauthKey, Anchor, *Document, error) {
	line = strings.Join(strings.Fields(line), "")
	if len(line) > maxPreauthChars || !strings.HasPrefix(line, preauthPrefix) {
		return nil, Anchor{}, nil, errors.New("not an OpenScale enrollment key")
	}
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(line, preauthPrefix))
	if err != nil {
		return nil, Anchor{}, nil, errors.New("enrollment key is damaged")
	}
	var k PreauthKey
	if err := decodeStrict(data, &k); err != nil {
		return nil, Anchor{}, nil, errors.New("enrollment key is damaged")
	}
	if k.RootKey.IsZero() {
		return nil, Anchor{}, nil, errors.New("enrollment key has no root key")
	}
	if err := k.Device.validate(); err != nil {
		return nil, Anchor{}, nil, err
	}
	root := ed25519.PublicKey(append([]byte(nil), k.RootKey[:]...))
	doc, err := VerifyDocumentSignature(k.Document, root)
	if err != nil {
		return nil, Anchor{}, nil, err
	}
	signing, wg, err := k.Device.PublicKeys()
	if err != nil {
		return nil, Anchor{}, nil, err
	}
	idx := slices.IndexFunc(doc.Devices, func(d Device) bool { return d.ID == k.Device.DeviceID })
	if idx < 0 || doc.Devices[idx].SigningKey != signing || doc.Devices[idx].WireGuardKey != wg || !doc.Devices[idx].Preauthorized {
		return nil, Anchor{}, nil, ErrNotPreauthorized
	}
	if !now.Before(doc.Devices[idx].ExpiresAt) {
		return nil, Anchor{}, nil, ErrPreauthExpired
	}
	k.Device.lockSecrets()
	return &k, Anchor{RootKey: root, NetworkID: doc.NetworkID}, doc, nil
}

// --- Self-requested leave (F-106) ---

// LeaveRequest is a device's signed wish to leave the network. Only the
// owner's root signature removes it from the document; the device deletes
// its own keys right after sending the request.
type LeaveRequest struct {
	NetworkID  string    `json:"network_id"`
	DeviceID   string    `json:"device_id"`
	SigningKey Key       `json:"signing_key"`
	Nonce      string    `json:"nonce"`
	CreatedAt  time.Time `json:"created_at"`
}

// SignedLeave carries the payload and the device signature. DeviceID is
// repeated outside the payload so the signature is checked against the
// document before the payload is parsed.
type SignedLeave struct {
	DeviceID  string `json:"device_id"`
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

// NewLeaveRequest signs a leave request with the device key.
func (s *DeviceSecrets) NewLeaveRequest(random io.Reader, networkID string, now time.Time) (SignedLeave, error) {
	if err := s.validate(); err != nil {
		return SignedLeave{}, err
	}
	if !isValidID(networkID) {
		return SignedLeave{}, errors.New("network id must be 32 lowercase hex characters")
	}
	signing, _, err := s.PublicKeys()
	if err != nil {
		return SignedLeave{}, err
	}
	nonce, err := newRandomID(random)
	if err != nil {
		return SignedLeave{}, err
	}
	payload, err := json.Marshal(LeaveRequest{NetworkID: networkID, DeviceID: s.DeviceID, SigningKey: signing, Nonce: nonce, CreatedAt: roundTimestamp(now)})
	if err != nil {
		return SignedLeave{}, fmt.Errorf("encode leave request: %w", err)
	}
	sig, err := s.SigningKey().Sign(nil, payload, &ed25519.Options{Context: LeaveContext})
	if err != nil {
		return SignedLeave{}, err
	}
	return SignedLeave{DeviceID: s.DeviceID, Payload: payload, Signature: sig}, nil
}

// OpenLeaveRequest verifies a leave request against doc: the signature with
// the device's current signing key (before parsing), then the binding to
// the network, the device and that key, and the age.
func OpenLeaveRequest(doc *Document, sl SignedLeave, now time.Time) (*LeaveRequest, Device, error) {
	if len(sl.Payload) == 0 || len(sl.Payload) > MaxLeavePayload || !isValidID(sl.DeviceID) {
		return nil, Device{}, errors.New("leave request has an invalid size or device id")
	}
	idx := slices.IndexFunc(doc.Devices, func(d Device) bool { return d.ID == sl.DeviceID })
	if idx < 0 {
		return nil, Device{}, ErrUnknownDevice
	}
	dev := doc.Devices[idx]
	if len(sl.Signature) != ed25519.SignatureSize ||
		ed25519.VerifyWithOptions(dev.SigningKey[:], sl.Payload, sl.Signature, &ed25519.Options{Context: LeaveContext}) != nil {
		return nil, Device{}, ErrBadSignature
	}
	var req LeaveRequest
	if err := decodeStrict(sl.Payload, &req); err != nil {
		return nil, Device{}, fmt.Errorf("decode leave request: %w", err)
	}
	switch {
	case req.NetworkID != doc.NetworkID:
		return nil, Device{}, ErrWrongNetwork
	case req.DeviceID != sl.DeviceID || req.SigningKey != dev.SigningKey:
		return nil, Device{}, errors.New("leave request names another device or key")
	case !isValidID(req.Nonce):
		return nil, Device{}, errors.New("leave request has an invalid nonce")
	case req.CreatedAt.IsZero() || now.Before(req.CreatedAt.Add(-clockSkew)) || now.Sub(req.CreatedAt) > LeaveMaxAge:
		return nil, Device{}, ErrLeaveExpired
	}
	return &req, dev, nil
}

// ApplyLeave verifies a leave request and revokes the device in this
// version. It returns the device and the number of dropped rules.
func (doc *Document) ApplyLeave(sl SignedLeave, now time.Time) (Device, int, error) {
	_, dev, err := OpenLeaveRequest(doc, sl, now)
	if err != nil {
		return Device{}, 0, err
	}
	var dropped int
	err = doc.transact(func() error {
		var err error
		dropped, err = doc.RevokeDevice(dev.Name, now)
		return err
	})
	return dev, dropped, err
}

// EncodeLeave returns the single-line form of a leave request.
func EncodeLeave(sl SignedLeave) (string, error) {
	if len(sl.Payload) == 0 || len(sl.Payload) > MaxLeavePayload {
		return "", errors.New("leave request has an invalid size")
	}
	data, err := json.Marshal(sl)
	if err != nil {
		return "", fmt.Errorf("encode leave request: %w", err)
	}
	return leavePrefix + base64.RawURLEncoding.EncodeToString(data), nil
}

// DecodeLeave parses a line produced by EncodeLeave. The result is
// untrusted until OpenLeaveRequest succeeds.
func DecodeLeave(line string) (SignedLeave, error) {
	line = strings.Join(strings.Fields(line), "")
	if len(line) > maxLeaveChars || !strings.HasPrefix(line, leavePrefix) {
		return SignedLeave{}, errors.New("not an OpenScale leave request")
	}
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(line, leavePrefix))
	if err != nil {
		return SignedLeave{}, errors.New("leave request is damaged")
	}
	var sl SignedLeave
	if err := decodeStrict(data, &sl); err != nil {
		return SignedLeave{}, errors.New("leave request is damaged")
	}
	if len(sl.Payload) == 0 || len(sl.Payload) > MaxLeavePayload {
		return SignedLeave{}, errors.New("leave request has an invalid size")
	}
	return sl, nil
}
