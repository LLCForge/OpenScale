package admin

import (
	"errors"
	"slices"
	"time"

	"github.com/openscale/openscale/internal/trust"
)

// CreatedInvite is a new invite and the code to hand to the new device.
type CreatedInvite struct {
	Invite trust.Invite
	Code   string
}

// PendingInvite is an invite enrollment verified against the owner's own
// document, ready to be shown for approval.
type PendingInvite struct {
	InviteID    string
	Request     *trust.EnrollmentRequest
	ShortCode   string
	Fingerprint string
	Signed      trust.SignedInviteEnrollment
}

// CreateInvite lists a new invite in the document, signs it and returns
// the invite code. The seed exists only in the returned code.
func (n *Network) CreateInvite(passphrase []byte, now time.Time, life time.Duration) (*CreatedInvite, error) {
	return n.CreateTaggedInvite(passphrase, now, life, nil)
}

// CreateTaggedInvite is CreateInvite with tags that the joining device
// receives on approval (ADR-0021, F-133).
func (n *Network) CreateTaggedInvite(passphrase []byte, now time.Time, life time.Duration, tags []string) (*CreatedInvite, error) {
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
		inv, err = doc.AddTaggedInvite(id, keys, now, life, tags)
		return err
	})
	if err != nil {
		return nil, err
	}
	if err := n.Commit(plan, passphrase); err != nil {
		return nil, err
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

// VerifyPending keeps the enrollments that verify against the current
// document and whose keys are not already used or revoked. Anything the
// coordinator made up is dropped here.
func (n *Network) VerifyPending(list []trust.SignedInviteEnrollment, now time.Time) []PendingInvite {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]PendingInvite, 0, len(list))
	seen := map[string]bool{}
	for _, se := range list {
		req, inv, err := trust.OpenInviteEnrollment(n.doc, se, now)
		// Multi-use invites may have one pending enrollment per device;
		// rejected enrollments stay hidden (ADR-0028, membership.go).
		if err != nil || seen[pendingKey(inv, req.DeviceID)] || keysInUse(n.doc, req) || n.rejectedLocked(inv.ID, req.DeviceID, now) {
			continue
		}
		seen[pendingKey(inv, req.DeviceID)] = true
		out = append(out, PendingInvite{
			InviteID:    inv.ID,
			Request:     req,
			ShortCode:   req.ShortCode(),
			Fingerprint: req.Fingerprint(),
			Signed:      se,
		})
	}
	slices.SortFunc(out, func(a, b PendingInvite) int { return a.Request.CreatedAt.Compare(b.Request.CreatedAt) })
	return out
}

// ApproveOptions adjusts an invite approval.
type ApproveOptions struct {
	// OverrideTags replaces the invite's tags with Tags (which may be
	// empty). Without it the device receives the invite's tags.
	OverrideTags bool
	Tags         []string
	// Ephemeral adds a temporary device (#22); Lifetime overrides the
	// default membership (trust.DefaultDeviceLife, or DefaultEphemeralLife
	// for an ephemeral device).
	Ephemeral bool
	Lifetime  time.Duration
}

// ApproveInvite adds the device from a verified enrollment under name and
// marks its invite used, in one signed version. The device receives the
// invite's tags (F-133).
func (n *Network) ApproveInvite(passphrase []byte, se trust.SignedInviteEnrollment, name string, roles []trust.Role, now time.Time) (trust.Device, error) {
	return n.ApproveInviteWith(passphrase, se, name, roles, ApproveOptions{}, now)
}

// ApproveInviteWith is ApproveInvite with options, for example to change
// the tags the invite proposes.
func (n *Network) ApproveInviteWith(passphrase []byte, se trust.SignedInviteEnrollment, name string, roles []trust.Role, opts ApproveOptions, now time.Time) (trust.Device, error) {
	var added trust.Device
	plan, err := n.Prepare(now, trust.DefaultValidity, func(doc *trust.Document) error {
		req, inv, err := trust.OpenInviteEnrollment(doc, se, now)
		if err != nil {
			return err
		}
		if keysInUse(doc, req) {
			return ErrDuplicateRequest
		}
		life := trust.DefaultDeviceLife
		if opts.Ephemeral {
			life = trust.DefaultEphemeralLife
		}
		if opts.Lifetime > 0 {
			life = opts.Lifetime
		}
		if opts.Ephemeral && life > trust.MaxEphemeralLife {
			return trust.ErrEphemeralLifetime
		}
		if added, err = doc.AddDevice(req, name, roles, now, life); err != nil {
			return err
		}
		if opts.Ephemeral {
			if err := doc.SetDeviceEphemeral(name, true, now); err != nil {
				return err
			}
			added, _ = doc.DeviceByName(name)
		}
		tags := inv.Tags
		if opts.OverrideTags {
			tags = opts.Tags
		}
		if len(tags) > 0 {
			if err := doc.SetDeviceTags(name, tags); err != nil {
				return err
			}
			added, _ = doc.DeviceByName(name)
		}
		if err := doc.MarkInviteUsed(inv.ID, req.DeviceID); err != nil {
			return err
		}
		doc.PruneInvites(now)
		return nil
	})
	if err != nil {
		return trust.Device{}, err
	}
	if err := n.Commit(plan, passphrase); err != nil {
		return trust.Device{}, err
	}
	return added, nil
}

// RevokeInvite removes an invite before it is used.
func (n *Network) RevokeInvite(passphrase []byte, id string, now time.Time) error {
	plan, err := n.Prepare(now, trust.DefaultValidity, func(doc *trust.Document) error {
		doc.PruneInvites(now)
		if err := doc.RemoveInvite(id); err != nil && !errors.Is(err, trust.ErrInviteNotFound) {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	return n.Commit(plan, passphrase)
}

func keysInUse(doc *trust.Document, req *trust.EnrollmentRequest) bool {
	for _, d := range doc.Devices {
		if d.ID == req.DeviceID || d.SigningKey == req.SigningKey || d.WireGuardKey == req.WireGuardKey {
			return true
		}
	}
	for _, r := range doc.Revoked {
		if r.DeviceID == req.DeviceID || r.SigningKey == req.SigningKey || r.WireGuardKey == req.WireGuardKey {
			return true
		}
	}
	for _, r := range doc.RetiredKeys {
		if r.SigningKey == req.SigningKey || r.WireGuardKey == req.WireGuardKey ||
			r.SigningKey == req.WireGuardKey || r.WireGuardKey == req.SigningKey {
			return true
		}
	}
	return false
}
