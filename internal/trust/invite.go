package trust

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Signature contexts of an invite enrollment (ADR-0014). The new device
// signs with its own key (proof of possession) and with the invite key
// (proof that it holds the invite code the owner handed out).
const (
	InviteDeviceContext = "openscale/invite-enrollment-device/v1"
	InviteKeyContext    = "openscale/invite-enrollment-invite/v1"
)

// Invite limits.
const (
	MaxInvites        = 32
	DefaultInviteLife = time.Hour
	MaxInviteLife     = 7 * 24 * time.Hour
	InviteSeedSize    = 32
	invitePrefix      = "osinv1."
	maxInviteChars    = 2048
	maxInvitePayload  = 640
)

// Invite errors.
var (
	ErrInviteNotFound = errors.New("invite not found")
	ErrInviteExpired  = errors.New("invite has expired")
	ErrInviteUsed     = errors.New("invite was already used")
)

// Invite lets one new device reach the coordinator before it is a member.
// Its keys are derived from a seed that only travels inside the invite code.
type Invite struct {
	ID           string     `json:"id"`
	SigningKey   Key        `json:"signing_key"`
	WireGuardKey Key        `json:"wireguard_key"`
	IPv4         netip.Addr `json:"ipv4"`
	CreatedAt    time.Time  `json:"created_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
	// UsedBy is the device id the invite was approved for. A used invite
	// still lets that device download the document until it expires.
	UsedBy string `json:"used_by,omitempty"`
	// Tags are given to the device that joins with this invite (F-133,
	// ADR-0021). The owner can still change them when approving.
	Tags []string `json:"tags,omitempty"`
	// MaxUses lets one code enroll several devices (ADR-0028, F-184); every
	// enrollment still needs the owner's approval and root signature. 0 or
	// 1 is a single-use invite as before, recorded in UsedBy.
	MaxUses int `json:"max_uses,omitempty"`
	// Uses lists the devices approved with a multi-use invite.
	Uses []string `json:"uses,omitempty"`
}

// ActiveAt reports whether the invite can still be used at now.
func (i Invite) ActiveAt(now time.Time) bool { return now.Before(i.ExpiresAt) }

// InviteKeys are the private keys derived from an invite seed.
type InviteKeys struct {
	Signing          ed25519.PrivateKey
	WireGuardPrivate []byte
	SigningPublic    Key
	WireGuardPublic  Key
}

// NewInviteSeed returns a random invite seed.
func NewInviteSeed(random io.Reader) ([]byte, error) {
	seed := make([]byte, InviteSeedSize)
	if _, err := io.ReadFull(random, seed); err != nil {
		return nil, fmt.Errorf("generate invite seed: %w", err)
	}
	return seed, nil
}

// DeriveInviteKeys derives the invite's Ed25519 and WireGuard keys from its
// seed with HKDF-SHA256 and separate labels.
func DeriveInviteKeys(seed []byte) (*InviteKeys, error) {
	if len(seed) != InviteSeedSize {
		return nil, errors.New("invite seed must be 32 bytes")
	}
	sigSeed, err := hkdf.Key(sha256.New, seed, nil, "openscale/invite/signing/v1", ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	wg, err := hkdf.Key(sha256.New, seed, nil, "openscale/invite/wireguard/v1", 32)
	if err != nil {
		return nil, err
	}
	clampX25519(wg)
	signing := ed25519.NewKeyFromSeed(sigSeed)
	k := &InviteKeys{Signing: signing, WireGuardPrivate: wg}
	if k.SigningPublic, err = keyFromSlice(signing.Public().(ed25519.PublicKey)); err != nil {
		return nil, err
	}
	priv, err := ecdh.X25519().NewPrivateKey(wg)
	if err != nil {
		return nil, fmt.Errorf("load invite wireguard key: %w", err)
	}
	if k.WireGuardPublic, err = keyFromSlice(priv.PublicKey().Bytes()); err != nil {
		return nil, err
	}
	return k, nil
}

// InviteByID returns the invite with the given id.
func (doc *Document) InviteByID(id string) (Invite, bool) {
	for _, inv := range doc.Invites {
		if inv.ID == id {
			return inv, true
		}
	}
	return Invite{}, false
}

// InviteByAddr returns the invite using the overlay address a.
func (doc *Document) InviteByAddr(a netip.Addr) (Invite, bool) {
	for _, inv := range doc.Invites {
		if inv.IPv4 == a {
			return inv, true
		}
	}
	return Invite{}, false
}

// AddInvite lists a new invite with the public keys derived from its seed.
// Expired invites are removed first so they never block new ones.
func (doc *Document) AddInvite(id string, keys *InviteKeys, now time.Time, life time.Duration) (Invite, error) {
	return doc.AddTaggedInvite(id, keys, now, life, nil)
}

// AddTaggedInvite is AddInvite with tags that the joining device receives
// when the invite is approved (F-133).
func (doc *Document) AddTaggedInvite(id string, keys *InviteKeys, now time.Time, life time.Duration, tags []string) (Invite, error) {
	if life <= 0 || life > MaxInviteLife {
		return Invite{}, fmt.Errorf("invite lifetime must be between 1s and %d days", int(MaxInviteLife.Hours()/24))
	}
	if doc.Coordinator == nil {
		return Invite{}, errors.New("the network has no coordinator yet")
	}
	now = roundTimestamp(now)
	doc.PruneInvites(now)
	ipv4, err := doc.freeAddr(doc.IPv4Prefix)
	if err != nil {
		return Invite{}, err
	}
	inv := Invite{
		ID:           id,
		SigningKey:   keys.SigningPublic,
		WireGuardKey: keys.WireGuardPublic,
		IPv4:         ipv4,
		CreatedAt:    now,
		ExpiresAt:    now.Add(life),
		Tags:         cleanTags(tags),
	}
	doc.Invites = append(doc.Invites, inv)
	if err := doc.Validate(); err != nil {
		doc.Invites = doc.Invites[:len(doc.Invites)-1]
		return Invite{}, err
	}
	return inv, nil
}

// MarkInviteUsed records that the invite was approved for deviceID.
func (doc *Document) MarkInviteUsed(id, deviceID string) error {
	idx := slices.IndexFunc(doc.Invites, func(i Invite) bool { return i.ID == id })
	if idx < 0 {
		return ErrInviteNotFound
	}
	if doc.Invites[idx].MultiUse() {
		// Multi-use invites record every approved device (ADR-0028).
		return doc.markMultiUse(idx, deviceID)
	}
	if doc.Invites[idx].UsedBy != "" {
		return ErrInviteUsed
	}
	doc.Invites[idx].UsedBy = deviceID
	return doc.Validate()
}

// RemoveInvite deletes an invite.
func (doc *Document) RemoveInvite(id string) error {
	idx := slices.IndexFunc(doc.Invites, func(i Invite) bool { return i.ID == id })
	if idx < 0 {
		return ErrInviteNotFound
	}
	doc.Invites = slices.Delete(doc.Invites, idx, idx+1)
	if len(doc.Invites) == 0 {
		doc.Invites = nil
	}
	return nil
}

// PruneInvites removes expired invites and returns how many were removed.
func (doc *Document) PruneInvites(now time.Time) int {
	before := len(doc.Invites)
	doc.Invites = slices.DeleteFunc(doc.Invites, func(i Invite) bool { return !i.ActiveAt(now) })
	if len(doc.Invites) == 0 {
		doc.Invites = nil
	}
	return before - len(doc.Invites)
}

func (doc *Document) validateInvites() error {
	if len(doc.Invites) > MaxInvites {
		return fmt.Errorf("at most %d invites are allowed", MaxInvites)
	}
	keys := make(map[Key]bool, 2*len(doc.Devices)+2*len(doc.Invites)+1)
	addrs := make(map[netip.Addr]bool, len(doc.Devices)+len(doc.Invites)+2)
	addrs[doc.DNSResolverIPv4()] = true
	if doc.Coordinator != nil {
		keys[doc.Coordinator.WireGuardKey] = true
		addrs[doc.Coordinator.IPv4] = true
	}
	doc.reserveExtraCoordinators(keys, addrs) // ADR-0111
	for _, d := range doc.Devices {
		keys[d.SigningKey], keys[d.WireGuardKey] = true, true
		addrs[d.IPv4] = true
	}
	for _, r := range doc.Revoked {
		keys[r.SigningKey], keys[r.WireGuardKey] = true, true
	}
	ids := make(map[string]bool, len(doc.Invites))
	for i, inv := range doc.Invites {
		switch {
		case !isValidID(inv.ID) || ids[inv.ID]:
			return fmt.Errorf("invite %d: invalid or duplicate id", i)
		case inv.SigningKey.IsZero() || inv.WireGuardKey.IsZero() || inv.SigningKey == inv.WireGuardKey:
			return fmt.Errorf("invite %d: keys must not be zero or equal", i)
		case keys[inv.SigningKey] || keys[inv.WireGuardKey]:
			return fmt.Errorf("invite %d: key is already used", i)
		case !isHostAddr(doc.IPv4Prefix, inv.IPv4) || addrs[inv.IPv4]:
			return fmt.Errorf("invite %d: address is invalid or already used", i)
		case inv.CreatedAt.IsZero() || !inv.ExpiresAt.After(inv.CreatedAt) || inv.ExpiresAt.Sub(inv.CreatedAt) > MaxInviteLife:
			return fmt.Errorf("invite %d: invalid lifetime", i)
		case inv.UsedBy != "" && !isValidID(inv.UsedBy):
			return fmt.Errorf("invite %d: invalid used_by", i)
		}
		if err := validateTags(inv.Tags); err != nil {
			return fmt.Errorf("invite %d: %w", i, err)
		}
		ids[inv.ID] = true
		keys[inv.SigningKey], keys[inv.WireGuardKey] = true, true
		addrs[inv.IPv4] = true
	}
	return nil
}

// InviteCode is what the owner hands to a new device. It is the device's
// trust anchor: whoever carries it must be trusted not to alter it.
type InviteCode struct {
	RootKey     Key               `json:"r"`
	NetworkID   string            `json:"n"`
	InviteID    string            `json:"i"`
	Seed        []byte            `json:"s"`
	IPv4        netip.Addr        `json:"a"`
	Coordinator InviteCoordinator `json:"c"`
}

// InviteCoordinator is the coordinator data a new device needs to reach it.
type InviteCoordinator struct {
	Endpoint     string     `json:"e"`
	WireGuardKey Key        `json:"k"`
	IPv4         netip.Addr `json:"a"`
}

// NewInviteCode builds the code for an invite listed in doc.
func NewInviteCode(root ed25519.PublicKey, doc *Document, inv Invite, seed []byte) (*InviteCode, error) {
	if doc.Coordinator == nil {
		return nil, errors.New("the network has no coordinator yet")
	}
	root32, err := keyFromSlice(root)
	if err != nil {
		return nil, err
	}
	c := &InviteCode{
		RootKey:   root32,
		NetworkID: doc.NetworkID,
		InviteID:  inv.ID,
		Seed:      append([]byte(nil), seed...),
		IPv4:      inv.IPv4,
		Coordinator: InviteCoordinator{
			Endpoint:     doc.Coordinator.Endpoint,
			WireGuardKey: doc.Coordinator.WireGuardKey,
			IPv4:         doc.Coordinator.IPv4,
		},
	}
	return c, c.validate()
}

// Encode returns the single-line form of the code.
func (c *InviteCode) Encode() (string, error) {
	if err := c.validate(); err != nil {
		return "", err
	}
	data, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("encode invite code: %w", err)
	}
	return invitePrefix + base64.RawURLEncoding.EncodeToString(data), nil
}

// DecodeInviteCode parses and validates a code line.
func DecodeInviteCode(line string) (*InviteCode, error) {
	line = strings.Join(strings.Fields(line), "")
	if len(line) <= maxInviteChars && IsSplitInvite(line) { // #359, p02_invite_split.go
		return decodeSplitInvite(line)
	}
	if len(line) > maxInviteChars || !strings.HasPrefix(line, invitePrefix) {
		return nil, errors.New("not an OpenScale invite code")
	}
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(line, invitePrefix))
	if err != nil {
		return nil, errors.New("invite code is damaged")
	}
	var c InviteCode
	if err := decodeStrict(data, &c); err != nil {
		return nil, errors.New("invite code is damaged")
	}
	return &c, c.validate()
}

// Anchor returns the trust anchor carried by the code.
func (c *InviteCode) Anchor() Anchor {
	return Anchor{RootKey: append(ed25519.PublicKey(nil), c.RootKey[:]...), NetworkID: c.NetworkID}
}

func (c *InviteCode) validate() error {
	switch {
	case c.RootKey.IsZero():
		return errors.New("invite code has no root key")
	case !isValidID(c.NetworkID) || !isValidID(c.InviteID):
		return errors.New("invite code has an invalid id")
	case len(c.Seed) != InviteSeedSize:
		return errors.New("invite code has an invalid key")
	case !c.IPv4.Is4() || !c.Coordinator.IPv4.Is4() || c.IPv4 == c.Coordinator.IPv4:
		return errors.New("invite code has invalid addresses")
	case c.Coordinator.WireGuardKey.IsZero():
		return errors.New("invite code has no coordinator key")
	}
	host, port, err := net.SplitHostPort(c.Coordinator.Endpoint)
	if err != nil || host == "" || len(host) > maxEndpointHostLen {
		return errors.New("invite code has an invalid coordinator endpoint")
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return errors.New("invite code has an invalid coordinator port")
	}
	if _, err := netip.ParseAddr(host); err != nil && !isValidDomain(host) {
		return errors.New("invite code has an invalid coordinator host")
	}
	return nil
}

// InviteEnrollment is the payload a new device sends through the invite
// tunnel.
type InviteEnrollment struct {
	InviteID     string    `json:"invite_id"`
	NetworkID    string    `json:"network_id"`
	DeviceID     string    `json:"device_id"`
	SigningKey   Key       `json:"signing_key"`
	WireGuardKey Key       `json:"wireguard_key"`
	Hostname     string    `json:"hostname"`
	CreatedAt    time.Time `json:"created_at"`
}

// SignedInviteEnrollment is an InviteEnrollment with both signatures over
// the exact payload bytes.
type SignedInviteEnrollment struct {
	Payload         []byte
	DeviceSignature []byte
	InviteSignature []byte
}

// NewInviteEnrollment signs an enrollment for code with the device key and
// the invite key.
func (s *DeviceSecrets) NewInviteEnrollment(code *InviteCode, hostname string, now time.Time) (SignedInviteEnrollment, *EnrollmentRequest, error) {
	signing, wg, err := s.PublicKeys()
	if err != nil {
		return SignedInviteEnrollment{}, nil, err
	}
	keys, err := DeriveInviteKeys(code.Seed)
	if err != nil {
		return SignedInviteEnrollment{}, nil, err
	}
	p := InviteEnrollment{
		InviteID:     code.InviteID,
		NetworkID:    code.NetworkID,
		DeviceID:     s.DeviceID,
		SigningKey:   signing,
		WireGuardKey: wg,
		Hostname:     SanitizeHostname(hostname),
		CreatedAt:    roundTimestamp(now),
	}
	payload, err := json.Marshal(p)
	if err != nil {
		return SignedInviteEnrollment{}, nil, fmt.Errorf("encode invite enrollment: %w", err)
	}
	devSig, err := s.SigningKey().Sign(nil, payload, &ed25519.Options{Context: InviteDeviceContext})
	if err != nil {
		return SignedInviteEnrollment{}, nil, err
	}
	invSig, err := keys.Signing.Sign(nil, payload, &ed25519.Options{Context: InviteKeyContext})
	if err != nil {
		return SignedInviteEnrollment{}, nil, err
	}
	req := &EnrollmentRequest{DeviceID: p.DeviceID, SigningKey: signing, WireGuardKey: wg, Hostname: p.Hostname, CreatedAt: p.CreatedAt}
	return SignedInviteEnrollment{Payload: payload, DeviceSignature: devSig, InviteSignature: invSig}, req, nil
}

// OpenInviteEnrollment verifies a signed enrollment against an unused,
// unexpired invite in doc. The coordinator cannot forge one because it never
// sees the invite seed.
func OpenInviteEnrollment(doc *Document, se SignedInviteEnrollment, now time.Time) (*EnrollmentRequest, Invite, error) {
	if len(se.Payload) > maxInvitePayload {
		return nil, Invite{}, errors.New("invite enrollment is too large")
	}
	var p InviteEnrollment
	if err := decodeStrict(se.Payload, &p); err != nil {
		return nil, Invite{}, fmt.Errorf("decode invite enrollment: %w", err)
	}
	if p.NetworkID != doc.NetworkID {
		return nil, Invite{}, errors.New("invite enrollment is for another network")
	}
	inv, ok := doc.InviteByID(p.InviteID)
	if !ok {
		return nil, Invite{}, ErrInviteNotFound
	}
	if !inv.ActiveAt(now) {
		return nil, Invite{}, ErrInviteExpired
	}
	if inv.Exhausted() || inv.UsedFor(p.DeviceID) {
		return nil, Invite{}, ErrInviteUsed
	}
	if len(se.InviteSignature) != ed25519.SignatureSize ||
		ed25519.VerifyWithOptions(inv.SigningKey[:], se.Payload, se.InviteSignature, &ed25519.Options{Context: InviteKeyContext}) != nil {
		return nil, Invite{}, ErrBadSignature
	}
	req := &EnrollmentRequest{DeviceID: p.DeviceID, SigningKey: p.SigningKey, WireGuardKey: p.WireGuardKey, Hostname: p.Hostname, CreatedAt: p.CreatedAt}
	if err := req.check(now); err != nil {
		return nil, Invite{}, err
	}
	if len(se.DeviceSignature) != ed25519.SignatureSize ||
		ed25519.VerifyWithOptions(p.SigningKey[:], se.Payload, se.DeviceSignature, &ed25519.Options{Context: InviteDeviceContext}) != nil {
		return nil, Invite{}, ErrBadSignature
	}
	return req, inv, nil
}

// ShortCode is the 4-digit code shown on the new device and next to the
// pending request in the panel. It only tells requests apart; the invite
// signature is what keeps the coordinator from forging one.
func (r *EnrollmentRequest) ShortCode() string {
	id, _ := hex.DecodeString(r.DeviceID)
	h := sha256.New()
	h.Write([]byte("openscale/short-code/v1"))
	h.Write(id)
	h.Write(r.SigningKey[:])
	h.Write(r.WireGuardKey[:])
	sum := h.Sum(nil)
	return fmt.Sprintf("%04d", binary.BigEndian.Uint64(sum[:8])%10000)
}

// SameShortCode compares two short codes in constant time.
func SameShortCode(a, b string) bool {
	return len(a) == 4 && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
