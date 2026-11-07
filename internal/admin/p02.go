package admin

import (
	"time"

	"github.com/openscale/openscale/internal/trust"
)

// InviteExtra edits the document in the same version that lists a new
// invite; it sees the invite (for example to write a rule for its tags).
type InviteExtra func(doc *trust.Document, inv trust.Invite) error

// CreateInviteWithChange is CreateInviteWith whose single signed version
// also applies extra (guest wizard, #368): the invite and its rule are
// published with one signature, or not at all. dryRun prepares the version
// and returns its diff without signing; the code is then empty.
func (n *Network) CreateInviteWithChange(passphrase []byte, now time.Time, in InviteRequest, extra InviteExtra, dryRun bool) (*CreatedInvite, *Plan, error) {
	note, err := cleanNote(in.Note)
	if err != nil {
		return nil, nil, err
	}
	seed, err := trust.NewInviteSeed(n.random)
	if err != nil {
		return nil, nil, err
	}
	defer wipe(seed)
	keys, err := trust.DeriveInviteKeys(seed)
	if err != nil {
		return nil, nil, err
	}
	defer wipe(keys.Signing)
	defer wipe(keys.WireGuardPrivate)
	id, err := trust.NewNetworkID(n.random)
	if err != nil {
		return nil, nil, err
	}
	var inv trust.Invite
	plan, err := n.Prepare(now, trust.DefaultValidity, func(doc *trust.Document) error {
		var err error
		if inv, err = doc.AddInviteWith(id, keys, now, trust.InviteOptions{Life: in.Life, Tags: in.Tags, MaxUses: in.MaxUses}); err != nil {
			return err
		}
		if extra != nil {
			return extra(doc, inv)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	if dryRun {
		return &CreatedInvite{Invite: inv}, plan, nil
	}
	if err := n.Commit(plan, passphrase); err != nil {
		return nil, nil, err
	}
	if note != "" {
		// A lost note is cosmetic; the invite itself is already signed.
		_ = n.SetInviteNote(inv.ID, note)
	}
	code, err := trust.NewInviteCode(n.sealed.RootPublicKey(), plan.Next, inv, seed)
	if err != nil {
		return nil, nil, err
	}
	line, err := code.Encode()
	if err != nil {
		return nil, nil, err
	}
	return &CreatedInvite{Invite: inv, Code: line}, plan, nil
}
