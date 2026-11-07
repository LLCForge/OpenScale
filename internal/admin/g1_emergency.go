package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

// Pre-signed emergency documents and the panic button (#681, #682,
// ADR-0175). While the root key is at hand the owner prepares documents
// for a crisis: "lock everything" (emergency lock on, every invite
// withdrawn) and "remove device X". They are root-signed now, sealed with
// a separate emergency passphrase and kept in emergency/. In a crisis the
// panic button publishes one with only that passphrase: the root key is
// never opened.
//
// A prepared document carries version current + EmergencyVersionOffset (+
// its index), so normal versions signed later stay below it and the
// emergency version still supersedes them. Its content is the network as
// it was when prepared: devices enrolled later are not in it (they lose
// membership until the owner signs again), which EmergencyStatus reports as
// stale. Preparing again replaces the old set.

// EmergencyFormat is the sealed secret format of an emergency document.
const EmergencyFormat = "openscale-emergency-v1"

// EmergencyVersionOffset separates emergency versions from normal ones.
const EmergencyVersionOffset = 1 << 32

// An emergency document must supersede every administrator document on the
// same base; this constant underflows, and the build fails, if it does not.
const _ = uint64(EmergencyVersionOffset - trust.MaxAdminVersionStep - 1)

// Emergency kinds.
const (
	EmergencyLockdown = "lockdown"
	EmergencyRemove   = "remove"
)

const (
	emergencyDir       = "emergency"
	emergencyIndex     = "index.json"
	maxEmergencyDocs   = 32
	maxEmergencyIndex  = 64 << 10
	emergencyLockNote  = "acil durum: panik düğmesi"
	maxEmergencyPublic = trust.MaxSealedSecretSize
)

// Emergency errors.
var (
	ErrNoEmergency       = errors.New("no prepared emergency document of this kind")
	ErrEmergencyOutdated = errors.New("the network has moved past this emergency document; prepare it again")
)

// EmergencySpec names one document to prepare.
type EmergencySpec struct {
	Kind   string `json:"kind"`
	Device string `json:"device,omitempty"`
}

// EmergencyRecord describes a prepared document (public metadata only).
type EmergencyRecord struct {
	Kind        string    `json:"kind"`
	Device      string    `json:"device,omitempty"`
	BaseVersion uint64    `json:"base_version"`
	Version     uint64    `json:"version"`
	PreparedAt  time.Time `json:"prepared_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	File        string    `json:"file"`
	// NeedsApprovals: the network requires k-of-n or sensitive approvals
	// that this document does not carry yet (ADR-0121, ADR-0174).
	NeedsApprovals bool `json:"needs_approvals,omitempty"`
	// Stale and Expired are computed by EmergencyStatus.
	Stale   bool `json:"stale,omitempty"`
	Expired bool `json:"expired,omitempty"`
}

func (r EmergencyRecord) matches(kind, device string) bool {
	return r.Kind == kind && r.Device == device
}

// PrepareEmergency signs the given emergency documents with the root key
// and seals each with sealPass.
func (n *Network) PrepareEmergency(rootPass, sealPass []byte, specs []EmergencySpec, now time.Time, validity time.Duration) ([]EmergencyRecord, error) {
	if len(specs) == 0 || len(specs) > maxEmergencyDocs {
		return nil, fmt.Errorf("prepare between 1 and %d emergency documents", maxEmergencyDocs)
	}
	if err := trust.CheckPassphrase(sealPass); err != nil {
		return nil, err
	}
	if n.MembersOnlyEnabled() { // #629: a pre-signed document would publish the members part unsealed
		return nil, fmt.Errorf("%w: emergency documents are not supported while members-only sealing is on", trust.ErrMembersOnly)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	cur, onDisk, err := readEnvelope(filepath.Join(n.dir, documentFile), n.sealed.RootPublicKey())
	if err != nil {
		return nil, err
	}
	n.doc = onDisk
	root, err := n.sealed.Open(rootPass)
	if err != nil {
		return nil, err
	}
	defer wipe(root)
	if err := os.MkdirAll(filepath.Join(n.dir, emergencyDir), 0o700); err != nil {
		return nil, err
	}
	var out []EmergencyRecord
	for i, spec := range specs {
		next, err := n.doc.Next(now, validity)
		if err != nil {
			return nil, err
		}
		next.Version = n.doc.Version + EmergencyVersionOffset + uint64(i) //nolint:gosec // i < maxEmergencyDocs
		switch spec.Kind {
		case EmergencyLockdown:
			if spec.Device != "" {
				return nil, errors.New("lockdown takes no device")
			}
			if err := next.SetLockdown(true, emergencyLockNote, now); err != nil {
				return nil, err
			}
			next.Invites = nil
		case EmergencyRemove:
			if _, err := next.RevokeDevice(spec.Device, now); err != nil {
				return nil, fmt.Errorf("%s: %w", spec.Device, err)
			}
		default:
			return nil, fmt.Errorf("unknown emergency kind %q", spec.Kind)
		}
		next.PruneEphemeral(now)
		if next.VersionChainEnabled() {
			next.LinkVersionChain(cur)
		}
		env, err := trust.SignDocument(next, root)
		if err != nil {
			return nil, err
		}
		trust.CarrySensitiveApprovals(cur, &env, next)
		data, err := trust.MarshalEnvelope(env)
		if err != nil {
			return nil, err
		}
		label := spec.Kind + ":" + spec.Device
		sealed, err := trust.SealSecret(EmergencyFormat, label, data, sealPass, n.argon, n.randomReader())
		if err != nil {
			return nil, err
		}
		blob, err := trust.MarshalSealedSecret(sealed)
		if err != nil {
			return nil, err
		}
		name := emergencyFileName(spec)
		if err := securefile.Replace(filepath.Join(n.dir, emergencyDir, name), blob); err != nil {
			return nil, fmt.Errorf("write emergency document: %w", err)
		}
		rec := EmergencyRecord{Kind: spec.Kind, Device: spec.Device, BaseVersion: n.doc.Version, Version: next.Version,
			PreparedAt: now.UTC().Truncate(time.Second), ExpiresAt: next.ExpiresAt, File: name,
			NeedsApprovals: (next.Approval != nil && next.Approval.Check(env) != nil) || trust.SensitiveStatus(env, next, n.doc.Sensitive) != nil}
		out = append(out, rec)
	}
	if err := writeEmergencyIndex(n.dir, out); err != nil {
		return nil, err
	}
	return out, nil
}

func emergencyFileName(spec EmergencySpec) string {
	if spec.Kind == EmergencyRemove {
		return "remove-" + spec.Device + ".sealed"
	}
	return spec.Kind + ".sealed"
}

func readEmergencyIndex(dir string) ([]EmergencyRecord, error) {
	data, err := securefile.ReadPrivate(filepath.Join(dir, emergencyDir, emergencyIndex), maxEmergencyIndex)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var list []EmergencyRecord
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, errors.New("emergency index is corrupt")
	}
	return list, nil
}

// writeEmergencyIndex replaces the set: files of the previous set that the
// new one does not reuse are removed.
func writeEmergencyIndex(dir string, list []EmergencyRecord) error {
	old, _ := readEmergencyIndex(dir)
	for _, r := range old {
		if !slices.ContainsFunc(list, func(n EmergencyRecord) bool { return n.File == r.File }) && !strings.ContainsAny(r.File, `/\`) {
			_ = os.Remove(filepath.Join(dir, emergencyDir, r.File))
		}
	}
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return securefile.Replace(filepath.Join(dir, emergencyDir, emergencyIndex), append(data, '\n'))
}

// EmergencyStatus lists the prepared documents with their state.
func (n *Network) EmergencyStatus(now time.Time) ([]EmergencyRecord, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	list, err := readEmergencyIndex(n.dir)
	if err != nil {
		return nil, err
	}
	for i := range list {
		list[i].Stale = n.doc.Version > list[i].BaseVersion
		list[i].Expired = !now.Before(list[i].ExpiresAt)
	}
	return list, nil
}

// PublishEmergency opens a prepared document with the emergency
// passphrase, checks it against the root's public key and makes it the
// current network.json (history and ledger included). It returns the
// encoded envelope for distribution. The root key is not used.
func (n *Network) PublishEmergency(kind, device string, sealPass []byte, now time.Time) ([]byte, *trust.Document, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	list, err := readEmergencyIndex(n.dir)
	if err != nil {
		return nil, nil, err
	}
	i := slices.IndexFunc(list, func(r EmergencyRecord) bool { return r.matches(kind, device) })
	if i < 0 {
		return nil, nil, ErrNoEmergency
	}
	rec := list[i]
	if strings.ContainsAny(rec.File, `/\`) {
		return nil, nil, errors.New("emergency index is corrupt")
	}
	// One document per prepared set: after one was published, the others
	// (built on the same old base) would undo it, for example lift the
	// lock or re-list a removed device.
	if n.doc.Version >= rec.BaseVersion+EmergencyVersionOffset {
		return nil, nil, ErrEmergencyOutdated
	}
	blob, err := securefile.ReadPrivate(filepath.Join(n.dir, emergencyDir, rec.File), maxEmergencyPublic)
	if err != nil {
		return nil, nil, err
	}
	sealed, err := trust.UnmarshalSealedSecret(blob, EmergencyFormat)
	if err != nil {
		return nil, nil, err
	}
	if sealed.Label != kind+":"+device {
		return nil, nil, errors.New("emergency document does not match its index")
	}
	data, err := sealed.Open(EmergencyFormat, sealPass)
	if err != nil {
		return nil, nil, err
	}
	defer trust.WipeKey(data)
	env, err := trust.UnmarshalEnvelope(data)
	if err != nil {
		return nil, nil, err
	}
	doc, err := trust.OpenDocument(env, trust.Anchor{RootKey: n.sealed.RootPublicKey(), NetworkID: n.doc.NetworkID}, n.doc.Version+1, now)
	if errors.Is(err, trust.ErrRollback) {
		return nil, nil, ErrEmergencyOutdated
	}
	if err != nil {
		return nil, nil, err
	}
	out := append([]byte(nil), data...)
	if err := recordSigned(n.dir, env, doc); err != nil {
		return nil, nil, err
	}
	historyPath := filepath.Join(n.dir, historyDir, historyName(doc.Version))
	if err := securefile.WriteNew(historyPath, out); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, nil, fmt.Errorf("write history: %w", err)
	}
	if err := securefile.Replace(filepath.Join(n.dir, documentFile), out); err != nil {
		return nil, nil, fmt.Errorf("write network document: %w", err)
	}
	n.doc = doc
	return out, doc, nil
}
