package admin

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

// Turning members-only documents on or off as one signed step (blind
// coordinator, #629, ADR-0178). SetMembersOnly only changes the setting for
// a later signature; here the setting and a new version signed under it go
// together, and the minimum client version is raised in that same version
// because older clients cannot read a sealed document.

// ErrMembersOnlyUnchanged is returned when the setting already has the
// requested value and the current document already follows it.
var ErrMembersOnlyUnchanged = errors.New("members-only setting already has this value")

// MembersOnlyStatus describes the setting for the panel and the CLI.
type MembersOnlyStatus struct {
	Enabled bool `json:"enabled"`
	// Sealed: the signed network.json is a sealed public part.
	Sealed bool `json:"sealed"`
	// MinClientVersion is the current document's minimum client version.
	MinClientVersion string `json:"minClientVersion"`
	// RequiredClientVersion is the minimum a sealed document must carry.
	RequiredClientVersion string `json:"requiredClientVersion"`
	// RaisesMinClient: turning it on raises the minimum client version.
	RaisesMinClient bool `json:"raisesMinClient"`
	// Blockers are Turkish reasons why it cannot be turned on now.
	Blockers []string `json:"blockers"`
	// Warnings are Turkish notes to read before turning it on.
	Warnings []string `json:"warnings"`
}

// MembersOnlyState returns the current state of the setting.
func (n *Network) MembersOnlyState() (MembersOnlyStatus, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.membersOnlyStateLocked()
}

func (n *Network) membersOnlyStateLocked() (MembersOnlyStatus, error) {
	env, _, err := readEnvelope(filepath.Join(n.dir, documentFile), n.sealed.RootPublicKey())
	if err != nil {
		return MembersOnlyStatus{}, err
	}
	signed, err := trust.VerifyDocumentSignature(env, n.sealed.RootPublicKey())
	if err != nil {
		return MembersOnlyStatus{}, err
	}
	st := MembersOnlyStatus{
		Enabled: membersOnlyEnabled(n.dir), Sealed: trust.IsMembersOnly(signed),
		MinClientVersion: n.doc.MinClientVersion, RequiredClientVersion: trust.MembersOnlyMinClientVersion,
		Blockers: []string{}, Warnings: []string{},
	}
	st.RaisesMinClient = n.doc.MinClientVersion == "" || !trust.ClientVersionAtLeast(n.doc.MinClientVersion, trust.MembersOnlyMinClientVersion)
	if n.doc.Sensitive != nil {
		st.Blockers = append(st.Blockers, "Hassas cihaz politikası cihaz adları içerir ve henüz mühürlenemez; önce politikayı kaldırın.")
	}
	for _, inv := range n.doc.Invites {
		if len(inv.Tags) > 0 {
			st.Blockers = append(st.Blockers, "Etiketli davetler etiketleri koordinatöre gösterir; önce bu davetleri kaldırın.")
			break
		}
	}
	if len(n.doc.Devices) == 0 {
		st.Blockers = append(st.Blockers, "Mühürlü belge için ağda en az bir cihaz olmalı.")
	}
	if st.RaisesMinClient {
		st.Warnings = append(st.Warnings, fmt.Sprintf("Asgari istemci sürümü %s yapılır. Bu sürümün altındaki cihazlar yeni belgeyi reddeder ve ağdan kopar; önce bütün cihazları güncelleyin.", trust.MembersOnlyMinClientVersion))
	}
	st.Warnings = append(st.Warnings, "Koordinatörler de bu sürümde olmalı; eski koordinatör mühürlü belgeyi kabul etmez.")
	if docs, err := readEmergencyIndex(n.dir); err == nil && len(docs) > 0 {
		st.Warnings = append(st.Warnings, "Önceden hazırlanmış acil durum belgeleri mühürsüzdür; yayımlanırsa cihaz adları koordinatöre görünür.")
	}
	return st, nil
}

// PrepareMembersOnly returns the plan of the version that follows the
// setting: on raises the minimum client version when needed and is checked
// against sealing before anything is signed. Nothing is written.
func (n *Network) PrepareMembersOnly(on bool, now time.Time, validity time.Duration) (*Plan, error) {
	st, err := n.MembersOnlyState()
	if err != nil {
		return nil, err
	}
	if st.Enabled == on && st.Sealed == on {
		return nil, ErrMembersOnlyUnchanged
	}
	plan, err := n.Prepare(now, validity, func(doc *trust.Document) error {
		if on && st.RaisesMinClient {
			return doc.SetMinClientVersion(trust.MembersOnlyMinClientVersion)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if on {
		if _, _, err := trust.SealMembersOnly(plan.Next, rand.Reader); err != nil {
			return nil, err
		}
	}
	return plan, nil
}

// CommitMembersOnly writes the setting and signs plan with commit (a root
// passphrase or a token). If the signature fails the setting is put back, so
// the setting and network.json never disagree after a failed attempt.
func (n *Network) CommitMembersOnly(on bool, plan *Plan, commit func(*Plan) error) error {
	if plan == nil || plan.Next == nil {
		return ErrConcurrentChange
	}
	if on && !trust.ClientVersionAtLeast(plan.Next.MinClientVersion, trust.MembersOnlyMinClientVersion) {
		return fmt.Errorf("%w: the plan does not raise the minimum client version", trust.ErrMembersOnly)
	}
	prev := n.MembersOnlyEnabled()
	if err := n.writeMembersOnlySetting(on); err != nil {
		return err
	}
	if err := commit(plan); err != nil {
		if restore := n.writeMembersOnlySetting(prev); restore != nil {
			return errors.Join(err, restore)
		}
		return err
	}
	return nil
}

func (n *Network) writeMembersOnlySetting(on bool) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	data, err := json.Marshal(membersOnlySetting{Enabled: on})
	if err != nil {
		return err
	}
	return securefile.Replace(filepath.Join(n.dir, membersOnlySettingFile), data)
}
