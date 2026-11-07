package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

// Membership operations of ADR-0028: invite notes and multi-use invites,
// rejecting a pending enrollment, preauthorized enrollment keys, leave
// requests, inactive devices and the minimum client version.
//
// Invite notes, rejections and last-seen times are owner-only bookkeeping:
// they stay in the network directory and never enter the signed document,
// which every member and the coordinator can read (ADR-0008).

const (
	inviteNotesFile = "invite-notes.json"
	rejectedFile    = "rejected.json"
	lastSeenFile    = "last-seen.json"
	maxNoteLen      = 120
	maxRejected     = 256
	maxLocalFile    = 256 << 10
	// rejectionLife keeps a rejection when the invite has no expiry left
	// to bound it.
	rejectionLife = trust.MaxInviteLife
	// seenGranularity bounds how often last-seen.json is rewritten.
	seenGranularity = 10 * time.Minute
	// DefaultInactiveAfter is the default threshold of the inactive list.
	DefaultInactiveAfter = 30 * 24 * time.Hour
)

// Membership errors.
var (
	ErrInvalidNote     = errors.New("invite note must be at most 120 characters without control characters")
	ErrPendingRejected = errors.New("this enrollment was rejected")
)

// InviteRequest describes a new invite.
type InviteRequest struct {
	Life time.Duration
	Tags []string
	// MaxUses above 1 lets the code enroll that many devices, each still
	// approved by the owner (ADR-0028, F-184).
	MaxUses int
	// Note tells invites apart in the panel (F-132); kept locally only.
	Note string
}

// CreateInviteWith lists a new invite with options, signs it and returns
// the code. The note is saved next to the network, never in the document.
func (n *Network) CreateInviteWith(passphrase []byte, now time.Time, in InviteRequest) (*CreatedInvite, error) {
	note, err := cleanNote(in.Note)
	if err != nil {
		return nil, err
	}
	seed, err := trust.NewInviteSeed(n.random)
	if err != nil {
		return nil, err
	}
	defer wipe(seed)
	keys, err := trust.DeriveInviteKeys(seed)
	if err != nil {
		return nil, err
	}
	defer wipe(keys.Signing)
	defer wipe(keys.WireGuardPrivate)
	id, err := trust.NewNetworkID(n.random)
	if err != nil {
		return nil, err
	}
	var inv trust.Invite
	plan, err := n.Prepare(now, trust.DefaultValidity, func(doc *trust.Document) error {
		var err error
		inv, err = doc.AddInviteWith(id, keys, now, trust.InviteOptions{Life: in.Life, Tags: in.Tags, MaxUses: in.MaxUses})
		return err
	})
	if err != nil {
		return nil, err
	}
	if err := n.Commit(plan, passphrase); err != nil {
		return nil, err
	}
	if note != "" {
		// A lost note is cosmetic; the invite itself is already signed.
		_ = n.SetInviteNote(inv.ID, note)
	}
	code, err := trust.NewInviteCode(n.sealed.RootPublicKey(), plan.Next, inv, seed)
	if err != nil {
		return nil, err
	}
	line, err := code.Encode()
	if err != nil {
		return nil, err
	}
	return &CreatedInvite{Invite: inv, Code: line}, nil
}

func cleanNote(s string) (string, error) {
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > maxNoteLen || strings.IndexFunc(s, unicode.IsControl) >= 0 || !utf8.ValidString(s) {
		return "", ErrInvalidNote
	}
	return s, nil
}

// SetInviteNote stores a local note for an invite; "" removes it. Notes of
// invites no longer in the document are dropped.
func (n *Network) SetInviteNote(id, note string) error {
	note, err := cleanNote(note)
	if err != nil {
		return err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	notes := map[string]string{}
	_ = readLocalJSON(n.dir, inviteNotesFile, &notes)
	if note == "" {
		delete(notes, id)
	} else {
		notes[id] = note
	}
	for k := range notes {
		if _, ok := n.doc.InviteByID(k); !ok && k != id {
			delete(notes, k)
		}
	}
	return writeLocalJSON(n.dir, inviteNotesFile, notes)
}

// InviteNotes returns the local invite notes by invite id.
func (n *Network) InviteNotes() map[string]string {
	n.mu.Lock()
	defer n.mu.Unlock()
	notes := map[string]string{}
	_ = readLocalJSON(n.dir, inviteNotesFile, &notes)
	return notes
}

type rejection struct {
	InviteID string    `json:"invite_id"`
	DeviceID string    `json:"device_id"`
	Until    time.Time `json:"until"`
}

// RejectPending records that the owner refused one pending enrollment
// without revoking its invite (F-107). Rejected enrollments are never
// shown or approved again; the coordinator is also asked to drop it, but
// this local record is what counts, since the coordinator is untrusted.
func (n *Network) RejectPending(inviteID, deviceID string, now time.Time) error {
	if len(inviteID) != 32 || len(deviceID) != 32 {
		return errors.New("invalid invite or device id")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	until := now.Add(rejectionLife)
	if inv, ok := n.doc.InviteByID(inviteID); ok {
		until = inv.ExpiresAt
	}
	list := n.rejectionsLocked(now)
	for _, r := range list {
		if r.InviteID == inviteID && r.DeviceID == deviceID {
			return nil
		}
	}
	list = append(list, rejection{InviteID: inviteID, DeviceID: deviceID, Until: until})
	if len(list) > maxRejected {
		list = list[len(list)-maxRejected:]
	}
	return writeLocalJSON(n.dir, rejectedFile, list)
}

func (n *Network) rejectionsLocked(now time.Time) []rejection {
	var list []rejection
	_ = readLocalJSON(n.dir, rejectedFile, &list)
	return slices.DeleteFunc(list, func(r rejection) bool { return !now.Before(r.Until) })
}

// rejectedLocked reports whether the enrollment was rejected.
func (n *Network) rejectedLocked(inviteID, deviceID string, now time.Time) bool {
	return slices.ContainsFunc(n.rejectionsLocked(now), func(r rejection) bool {
		return r.InviteID == inviteID && r.DeviceID == deviceID
	})
}

// pendingKey identifies a pending enrollment: one per single-use invite,
// one per device for a multi-use invite.
func pendingKey(inv trust.Invite, deviceID string) string {
	if inv.MultiUse() {
		return inv.ID + "/" + deviceID
	}
	return inv.ID
}

// CreatePreauthKey generates a device identity, lists it as a
// preauthorized device in a new signed version and returns the enrollment
// key (F-098). The key holds the device's private keys: it is shown once
// and must be handled like a password.
func (n *Network) CreatePreauthKey(passphrase []byte, opts trust.PreauthOptions, now time.Time) (string, trust.Device, error) {
	if opts.Lifetime <= 0 {
		opts.Lifetime = trust.DefaultDeviceLife
		if opts.Ephemeral {
			opts.Lifetime = trust.DefaultEphemeralLife
		}
	}
	secrets, err := trust.GenerateDeviceSecrets(n.random, now)
	if err != nil {
		return "", trust.Device{}, err
	}
	defer func() {
		wipe(secrets.SigningSeed)
		wipe(secrets.WireGuardPrivate)
	}()
	var dev trust.Device
	plan, err := n.Prepare(now, trust.DefaultValidity, func(doc *trust.Document) error {
		var err error
		dev, err = doc.AddPreauthorizedDevice(secrets, opts, now)
		return err
	})
	if err != nil {
		return "", trust.Device{}, err
	}
	if err := n.Commit(plan, passphrase); err != nil {
		return "", trust.Device{}, err
	}
	n.mu.Lock()
	env, _, err := readEnvelope(filepath.Join(n.dir, documentFile), n.sealed.RootPublicKey())
	root := n.sealed.PublicKey
	n.mu.Unlock()
	if err != nil {
		return "", trust.Device{}, err
	}
	line, err := trust.EncodePreauthKey(&trust.PreauthKey{RootKey: root, Device: *secrets, Document: env})
	if err != nil {
		return "", trust.Device{}, err
	}
	return line, dev, nil
}

// PendingLeave is a leave request verified against the owner's document.
type PendingLeave struct {
	DeviceID  string
	Name      string
	CreatedAt time.Time
	Signed    trust.SignedLeave
}

// VerifyLeaves keeps the leave requests that verify against the current
// document; anything the coordinator made up is dropped.
func (n *Network) VerifyLeaves(list []trust.SignedLeave, now time.Time) []PendingLeave {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]PendingLeave, 0, len(list))
	seen := map[string]bool{}
	for _, sl := range list {
		req, dev, err := trust.OpenLeaveRequest(n.doc, sl, now)
		if err != nil || seen[dev.ID] {
			continue
		}
		seen[dev.ID] = true
		out = append(out, PendingLeave{DeviceID: dev.ID, Name: dev.Name, CreatedAt: req.CreatedAt, Signed: sl})
	}
	slices.SortFunc(out, func(a, b PendingLeave) int { return a.CreatedAt.Compare(b.CreatedAt) })
	return out
}

// InspectLeave decodes and verifies a leave request line.
func (n *Network) InspectLeave(line string, now time.Time) (*PendingLeave, error) {
	sl, err := trust.DecodeLeave(line)
	if err != nil {
		return nil, err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	req, dev, err := trust.OpenLeaveRequest(n.doc, sl, now)
	if err != nil {
		return nil, err
	}
	return &PendingLeave{DeviceID: dev.ID, Name: dev.Name, CreatedAt: req.CreatedAt, Signed: sl}, nil
}

// ApplyLeave removes the device that asked to leave, in one signed version
// (F-106). The request is verified again against the version it changes.
func (n *Network) ApplyLeave(passphrase []byte, sl trust.SignedLeave, now time.Time) (*Plan, error) {
	return n.Apply(passphrase, now, func(doc *trust.Document) error {
		_, _, err := doc.ApplyLeave(sl, now)
		return err
	})
}

// RemoveDevices revokes several devices with one signature (F-114).
func (n *Network) RemoveDevices(passphrase []byte, names []string, now time.Time) (*Plan, error) {
	return n.Apply(passphrase, now, func(doc *trust.Document) error {
		_, err := doc.RevokeDevices(names, now)
		return err
	})
}

// SetDeviceEphemeral marks a device as temporary or permanent (#22).
func (n *Network) SetDeviceEphemeral(passphrase []byte, name string, on bool, now time.Time) (*Plan, error) {
	return n.Apply(passphrase, now, func(doc *trust.Document) error {
		return doc.SetDeviceEphemeral(name, on, now)
	})
}

// SetMinClientVersion sets or clears the minimum client version (F-027).
func (n *Network) SetMinClientVersion(passphrase []byte, version string, now time.Time) (*Plan, error) {
	return n.Apply(passphrase, now, func(doc *trust.Document) error {
		return doc.SetMinClientVersion(version)
	})
}

// RecordSeen remembers when devices were last seen online (by device id),
// so the inactive list survives restarts of the tunnel and coordinator.
// Times only move forward; writes happen at most every seenGranularity
// per device.
func (n *Network) RecordSeen(seen map[string]time.Time) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	stored := map[string]time.Time{}
	_ = readLocalJSON(n.dir, lastSeenFile, &stored)
	changed := false
	known := map[string]bool{}
	for _, d := range n.doc.Devices {
		known[d.ID] = true
	}
	for id, t := range seen {
		if !known[id] || t.IsZero() {
			continue
		}
		t = t.UTC().Truncate(time.Minute)
		if t.Sub(stored[id]) >= seenGranularity {
			stored[id], changed = t, true
		}
	}
	for id := range stored {
		if !known[id] {
			delete(stored, id)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return writeLocalJSON(n.dir, lastSeenFile, stored)
}

// InactiveDevice is a device not seen for a long time (F-114).
type InactiveDevice struct {
	ID   string
	Name string
	// LastSeen is zero when the device was never seen online.
	LastSeen  time.Time
	AddedAt   time.Time
	ExpiresAt time.Time
	Ephemeral bool
	Admin     bool
	// Days since the device was last seen, or since it was added.
	Days int
}

// InactiveDevices lists the devices not seen for at least after (default
// 30 days), longest first. The coordinator cannot drop anyone (ADR-0003):
// the owner removes the chosen ones with RemoveDevices.
func (n *Network) InactiveDevices(live map[string]time.Time, after time.Duration, now time.Time) []InactiveDevice {
	if after <= 0 {
		after = DefaultInactiveAfter
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	stored := map[string]time.Time{}
	_ = readLocalJSON(n.dir, lastSeenFile, &stored)
	var out []InactiveDevice
	for _, d := range n.doc.Devices {
		last := stored[d.ID]
		if t := live[d.ID]; t.After(last) {
			last = t
		}
		ref := last
		if ref.IsZero() {
			ref = d.AddedAt
		}
		if now.Sub(ref) < after {
			continue
		}
		out = append(out, InactiveDevice{ID: d.ID, Name: d.Name, LastSeen: last, AddedAt: d.AddedAt, ExpiresAt: d.ExpiresAt,
			Ephemeral: d.Ephemeral, Admin: d.HasRole(trust.RoleAdmin), Days: int(now.Sub(ref).Hours() / 24)})
	}
	slices.SortFunc(out, func(a, b InactiveDevice) int { return b.Days - a.Days })
	return out
}

func readLocalJSON(dir, name string, v any) error {
	data, err := securefile.ReadPrivate(filepath.Join(dir, name), maxLocalFile)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	return json.Unmarshal(data, v)
}

func writeLocalJSON(dir, name string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if len(data) > maxLocalFile {
		return fmt.Errorf("%s is too large", name)
	}
	return securefile.Replace(filepath.Join(dir, name), append(data, '\n'))
}

// membershipChanges lists the ADR-0027/0028 changes between two versions
// for the diff shown before signing.
func membershipChanges(prev, next *trust.Document) []string {
	var out []string
	if len(prev.RecoveryKeys) != len(next.RecoveryKeys) {
		out = append(out, fmt.Sprintf("Kurtarma anahtarları: %d -> %d", len(prev.RecoveryKeys), len(next.RecoveryKeys)))
	}
	if prev.RootEpoch != next.RootEpoch {
		out = append(out, fmt.Sprintf("Kök anahtar dönemi: %d -> %d (yeni kök anahtar)", prev.RootEpoch, next.RootEpoch))
	}
	if prev.MinClientVersion != next.MinClientVersion {
		out = append(out, fmt.Sprintf("Asgari istemci sürümü: %s -> %s", versionOrNone(prev.MinClientVersion), versionOrNone(next.MinClientVersion)))
	}
	before := map[string]trust.Device{}
	for _, d := range prev.Devices {
		before[d.ID] = d
	}
	for _, d := range next.Devices {
		old, ok := before[d.ID]
		switch {
		case !ok && d.Preauthorized:
			out = append(out, d.Name+": ön onaylı kayıt anahtarıyla eklendi")
		case !ok:
		case old.Ephemeral != d.Ephemeral && d.Ephemeral:
			out = append(out, d.Name+": geçici cihaz yapıldı")
		case old.Ephemeral != d.Ephemeral:
			out = append(out, d.Name+": kalıcı cihaz yapıldı")
		}
		if !ok && d.Ephemeral {
			out = append(out, d.Name+": geçici cihaz (üyelik bitince kendiliğinden düşer)")
		}
	}
	uses := map[string]int{}
	for _, inv := range prev.Invites {
		uses[inv.ID] = len(inv.Uses)
	}
	for _, inv := range next.Invites {
		if inv.MultiUse() && len(inv.Uses) != uses[inv.ID] {
			out = append(out, fmt.Sprintf("Çok kullanımlık davet: %d/%d kullanıldı", len(inv.Uses), inv.MaxUses))
		}
	}
	return out
}

func versionOrNone(s string) string {
	if s == "" {
		return "(yok)"
	}
	return s
}
