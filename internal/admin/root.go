package admin

import (
	"bytes"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

// Root key rotation, recovery keys and recovery after a compromised root
// (ADR-0027, #7, F-116).
//
// The network directory gains:
//   - transitions.json: every root transition, in order. Members need them
//     to follow the root from one epoch to the next; the owner's device
//     publishes them to the coordinator.
//   - root.key.next: only while a root change is being committed.
//
// A recovery key's secret half never stays in the network directory: it is
// returned once (for an offline copy) and only read back for a recovery.

const (
	transitionsFile    = "transitions.json"
	nextRootKeyFile    = "root.key.next"
	recoveryKeyFormat  = "openscale-recovery-key-v1"
	maxTransitionsFile = 64 << 10
	maxRecoveryFile    = 8 << 10
)

// Root change errors.
var (
	ErrRecoveryKeyUnknown  = errors.New("this recovery key is not published in the network document")
	ErrRecoveryPassphrase  = errors.New("the recovery key needs a passphrase different from the root key's")
	ErrNotRecoveryKey      = errors.New("not an OpenScale recovery key file")
	ErrLastGoodUnavailable = errors.New("the chosen last good version is not in the history")
)

type recoveryKeyFile struct {
	Format    string          `json:"format"`
	NetworkID string          `json:"network_id"`
	Sealed    json.RawMessage `json:"sealed"`
}

type transitionsJSON struct {
	Transitions []string `json:"transitions"`
}

// RootChange describes a committed root rotation or recovery.
type RootChange struct {
	Kind           string
	Line           string
	Epoch          uint64
	Version        uint64
	OldFingerprint string
	NewFingerprint string
	// Revoked lists devices the recovery removed because the attacker
	// added them or changed their keys.
	Revoked []string
}

// AddRecoveryKey creates an offline recovery key, publishes its public half
// in a new signed version and returns the sealed key file (to be stored
// away from this computer) and its fingerprint. The recovery passphrase
// must differ from the root passphrase.
func (n *Network) AddRecoveryKey(passphrase, recoveryPassphrase []byte, now time.Time) ([]byte, string, error) {
	if subtle.ConstantTimeCompare(passphrase, recoveryPassphrase) == 1 {
		return nil, "", ErrRecoveryPassphrase
	}
	if err := trust.CheckPassphrase(recoveryPassphrase); err != nil {
		return nil, "", err
	}
	pub, priv, err := trust.GenerateRootKey(n.random)
	if err != nil {
		return nil, "", err
	}
	defer wipe(priv)
	var k trust.Key
	copy(k[:], pub)
	if subtle.ConstantTimeCompare(pub, n.sealed.RootPublicKey()) == 1 {
		return nil, "", errors.New("recovery key equals the root key")
	}
	sealed, err := trust.SealRootKey(priv, recoveryPassphrase, n.argon, n.random)
	if err != nil {
		return nil, "", err
	}
	inner, err := trust.MarshalSealedRootKey(sealed)
	if err != nil {
		return nil, "", err
	}
	doc, err := n.Document()
	if err != nil {
		return nil, "", err
	}
	file, err := json.MarshalIndent(recoveryKeyFile{Format: recoveryKeyFormat, NetworkID: doc.NetworkID, Sealed: bytes.TrimSpace(inner)}, "", "  ")
	if err != nil {
		return nil, "", err
	}
	if _, err := n.Apply(passphrase, now, func(doc *trust.Document) error { return doc.AddRecoveryKey(k) }); err != nil {
		return nil, "", err
	}
	return append(file, '\n'), trust.RootFingerprint(pub), nil
}

// OpenRecoveryKey decrypts a recovery key file.
func OpenRecoveryKey(data, passphrase []byte) (ed25519.PrivateKey, string, error) {
	if len(data) > maxRecoveryFile {
		return nil, "", ErrNotRecoveryKey
	}
	var f recoveryKeyFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil || f.Format != recoveryKeyFormat {
		return nil, "", ErrNotRecoveryKey
	}
	sealed, err := trust.UnmarshalSealedRootKey(f.Sealed)
	if err != nil {
		return nil, "", err
	}
	priv, err := sealed.Open(passphrase)
	if err != nil {
		return nil, "", err
	}
	return priv, f.NetworkID, nil
}

// RootTransitions returns the transitions stored in the network directory.
func (n *Network) RootTransitions() ([]trust.SignedRootTransition, error) {
	return readTransitions(n.dir)
}

// RotateRoot replaces the root key in an ordinary rotation: the old root
// signs the transition, the new root signs the next version at the next
// epoch. newPassphrase protects the new key (nil keeps the passphrase).
// Backups of the old key stop matching; new backups are needed.
func (n *Network) RotateRoot(passphrase, newPassphrase []byte, now time.Time) (*RootChange, error) {
	if newPassphrase == nil {
		newPassphrase = passphrase
	} else if err := trust.CheckPassphrase(newPassphrase); err != nil {
		return nil, err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	env, onDisk, err := readEnvelope(filepath.Join(n.dir, documentFile), n.sealed.RootPublicKey())
	if err != nil {
		return nil, err
	}
	if onDisk.Version != n.doc.Version {
		n.doc = onDisk
		return nil, ErrConcurrentChange
	}
	rootPriv, err := n.sealed.Open(passphrase)
	if err != nil {
		return nil, err
	}
	defer wipe(rootPriv)
	newPub, newPriv, err := trust.GenerateRootKey(n.random)
	if err != nil {
		return nil, err
	}
	defer wipe(newPriv)
	var oldKey, newKey trust.Key
	copy(oldKey[:], n.sealed.RootPublicKey())
	copy(newKey[:], newPub)
	epoch := n.doc.RootEpoch + 1
	st, err := trust.SignRootRotation(rootPriv, trust.RootTransition{
		NetworkID: n.doc.NetworkID, RevokedRoot: oldKey, NewRoot: newKey,
		LastGoodVersion: n.doc.Version, LastGoodDigest: trust.DocumentDigest(env), Epoch: epoch, IssuedAt: now,
	})
	if err != nil {
		return nil, err
	}
	next, err := n.doc.Next(now, trust.DefaultValidity)
	if err != nil {
		return nil, err
	}
	next.RootEpoch = epoch
	next.LinkVersionChain(env) // ADR-0144
	if err := next.Validate(); err != nil {
		return nil, err
	}
	sealed, err := trust.SealRootKey(newPriv, newPassphrase, n.argon, n.random)
	if err != nil {
		return nil, err
	}
	change, err := n.commitRootChangeLocked(sealed, newPriv, st, next)
	if err != nil {
		return nil, err
	}
	change.Kind = trust.TransitionRotation
	change.OldFingerprint = trust.RootFingerprint(ed25519.PublicKey(oldKey[:]))
	return change, nil
}

// RecoverOptions describes a recovery after the root key was compromised.
type RecoverOptions struct {
	// RecoveryKey is the recovery key file and RecoveryPassphrase its
	// passphrase.
	RecoveryKey        []byte
	RecoveryPassphrase []byte
	// NewPassphrase protects the new root key.
	NewPassphrase []byte
	// LastGoodVersion is the newest version the owner trusts; it must be in
	// the history.
	LastGoodVersion uint64
	// BadDocuments are envelopes signed by the compromised root after the
	// last good version (from the coordinator or a device's network.json).
	// Devices they added are revoked and keys they changed are retired.
	BadDocuments [][]byte
	// MinEpoch and MinVersion raise the new epoch and version above
	// anything the attacker published (the coordinator shows both).
	MinEpoch   uint64
	MinVersion uint64
}

// RecoverRoot rebuilds the network on a new root key from the last good
// version, signed off by an offline recovery key. The compromised root's
// passphrase is not needed. Members apply the recovery transition and the
// new first document together; every document of the compromised root
// stops verifying on them.
func RecoverRoot(dir string, ro RecoverOptions, opts Options, now time.Time) (*RootChange, error) {
	if err := trust.CheckPassphrase(ro.NewPassphrase); err != nil {
		return nil, err
	}
	n, err := Load(dir, opts)
	if err != nil {
		return nil, err
	}
	recPriv, networkID, err := OpenRecoveryKey(ro.RecoveryKey, ro.RecoveryPassphrase)
	if err != nil {
		return nil, err
	}
	defer wipe(recPriv)
	var recKey trust.Key
	copy(recKey[:], recPriv.Public().(ed25519.PublicKey))

	n.mu.Lock()
	defer n.mu.Unlock()
	if networkID != n.doc.NetworkID {
		return nil, ErrBackupKeyMismatch
	}
	roots := n.knownRootsLocked()
	goodEnv, good, err := readHistoryVersion(n.dir, ro.LastGoodVersion, roots)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(good.RecoveryKeys, recKey) {
		return nil, ErrRecoveryKeyUnknown
	}
	compromised := n.sealed.RootPublicKey()
	maxVersion := max(n.doc.Version, good.Version, ro.MinVersion)
	maxEpoch := max(n.doc.RootEpoch, good.RootEpoch, ro.MinEpoch)
	next, err := copyDocument(good)
	if err != nil {
		return nil, err
	}
	var revoked []string
	for i, data := range ro.BadDocuments {
		env, err := trust.UnmarshalEnvelope(data)
		if err != nil {
			return nil, fmt.Errorf("bad document %d: %w", i+1, err)
		}
		bad, err := trust.VerifyDocumentSignature(env, compromised)
		if err != nil {
			return nil, fmt.Errorf("bad document %d is not signed by the compromised root: %w", i+1, err)
		}
		if bad.NetworkID != good.NetworkID {
			return nil, fmt.Errorf("bad document %d: %w", i+1, trust.ErrWrongNetwork)
		}
		maxVersion, maxEpoch = max(maxVersion, bad.Version), max(maxEpoch, bad.RootEpoch)
		revoked = append(revoked, cutCompromise(next, bad, now)...)
	}
	version := maxVersion + 1
	if maxVersion == math.MaxUint64 {
		// Members follow the new epoch whatever the version; see ADR-0027.
		version = good.Version + 1
	}
	epoch := maxEpoch + 1
	nowRounded := now.UTC().Truncate(time.Minute)
	next.Version, next.IssuedAt, next.ExpiresAt, next.RootEpoch = version, nowRounded, nowRounded.Add(trust.DefaultValidity), epoch
	// A recovery continues from the last good version (ADR-0144).
	next.LinkVersionChain(goodEnv)
	next.PruneInvites(now)
	next.PruneEphemeral(now)
	if err := next.Validate(); err != nil {
		return nil, err
	}
	newPub, newPriv, err := trust.GenerateRootKey(n.random)
	if err != nil {
		return nil, err
	}
	defer wipe(newPriv)
	var oldKey, newKey trust.Key
	copy(oldKey[:], compromised)
	copy(newKey[:], newPub)
	st, err := trust.SignRootRecovery(recPriv, trust.RootTransition{
		NetworkID: good.NetworkID, RevokedRoot: oldKey, NewRoot: newKey,
		LastGoodVersion: good.Version, LastGoodDigest: trust.DocumentDigest(goodEnv), Epoch: epoch, IssuedAt: now,
	})
	if err != nil {
		return nil, err
	}
	sealed, err := trust.SealRootKey(newPriv, ro.NewPassphrase, n.argon, n.random)
	if err != nil {
		return nil, err
	}
	change, err := n.commitRootChangeLocked(sealed, newPriv, st, next)
	if err != nil {
		return nil, err
	}
	change.Kind = trust.TransitionRecovery
	change.OldFingerprint = trust.RootFingerprint(compromised)
	slices.Sort(revoked)
	change.Revoked = slices.Compact(revoked)
	return change, nil
}

// cutCompromise revokes in next the devices bad added and retires keys bad
// gave to devices of next; it returns the affected device names.
func cutCompromise(next, bad *trust.Document, now time.Time) []string {
	var names []string
	known := map[string]trust.Device{}
	for _, d := range next.Devices {
		known[d.ID] = d
	}
	revoked := map[string]bool{}
	for _, r := range next.Revoked {
		revoked[r.DeviceID] = true
	}
	retired := map[trust.Key]bool{}
	for _, r := range next.RetiredKeys {
		retired[r.SigningKey], retired[r.WireGuardKey] = true, true
	}
	at := now.UTC().Truncate(time.Second)
	for _, d := range bad.Devices {
		good, ok := known[d.ID]
		switch {
		case !ok && !revoked[d.ID]:
			next.Revoked = append(next.Revoked, trust.Revocation{DeviceID: d.ID, Name: d.Name, SigningKey: d.SigningKey, WireGuardKey: d.WireGuardKey, RevokedAt: at})
			revoked[d.ID] = true
			names = append(names, d.Name)
		case ok && (good.SigningKey != d.SigningKey || good.WireGuardKey != d.WireGuardKey) &&
			!retired[d.SigningKey] && !retired[d.WireGuardKey] && d.SigningKey != d.WireGuardKey:
			next.RetiredKeys = append(next.RetiredKeys, trust.RetiredKey{DeviceID: d.ID, SigningKey: d.SigningKey, WireGuardKey: d.WireGuardKey, RetiredAt: at})
			retired[d.SigningKey], retired[d.WireGuardKey] = true, true
			names = append(names, good.Name)
		}
	}
	return names
}

// commitRootChangeLocked writes a root change so that an interruption at
// any point is finished or undone by the next Load (finishRootChange):
// root.key.next, transitions.json, the history entry, network.json and
// finally root.key. Called with n.mu held.
func (n *Network) commitRootChangeLocked(sealed *trust.SealedRootKey, newPriv ed25519.PrivateKey, st trust.SignedRootTransition, next *trust.Document) (*RootChange, error) {
	if subtle.ConstantTimeCompare(newPriv.Public().(ed25519.PublicKey), sealed.PublicKey[:]) != 1 {
		return nil, errors.New("new root key does not match its sealed copy")
	}
	line, err := trust.EncodeRootTransition(st)
	if err != nil {
		return nil, err
	}
	signed, membersPlain, err := n.sealForSigning(next) // members-only (#629, members_only.go)
	if err != nil {
		return nil, err
	}
	env, err := trust.SignDocument(signed, newPriv)
	if err != nil {
		return nil, err
	}
	docData, err := trust.MarshalEnvelope(env)
	if err != nil {
		return nil, err
	}
	keyData, err := trust.MarshalSealedRootKey(sealed)
	if err != nil {
		return nil, err
	}
	historyPath := filepath.Join(n.dir, historyDir, historyName(next.Version))
	if _, err := os.Stat(historyPath); err == nil {
		return nil, ErrHistoryVersionUsed
	}
	nextPath := filepath.Join(n.dir, nextRootKeyFile)
	if err := securefile.Replace(nextPath, keyData); err != nil {
		return nil, fmt.Errorf("write new root key: %w", err)
	}
	abort := func(err error) (*RootChange, error) {
		_ = os.Remove(nextPath)
		_ = removeTransition(n.dir, st)
		return nil, err
	}
	if err := appendTransition(n.dir, st); err != nil {
		return abort(err)
	}
	if err := recordSigned(n.dir, env, signed); err != nil { // #342, ledger.go
		return abort(err)
	}
	if err := writeMembersPart(n.dir, next.Version, membersPlain); err != nil {
		return abort(err)
	}
	if err := securefile.WriteNew(historyPath, docData); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return abort(ErrHistoryVersionUsed)
		}
		return abort(fmt.Errorf("write history: %w", err))
	}
	// From here on the change is finished, never undone, by Load.
	if err := securefile.Replace(filepath.Join(n.dir, documentFile), docData); err != nil {
		return nil, fmt.Errorf("write network document (finished on next load): %w", err)
	}
	if err := securefile.Replace(filepath.Join(n.dir, rootKeyFile), keyData); err != nil {
		return nil, fmt.Errorf("write root key (finished on next load): %w", err)
	}
	_ = os.Remove(nextPath)
	n.sealed, n.doc = sealed, next
	return &RootChange{Line: line, Epoch: next.RootEpoch, Version: next.Version, NewFingerprint: sealed.Fingerprint()}, nil
}

// finishRootChange completes or undoes a root change interrupted before
// root.key was replaced. Load calls it first.
func finishRootChange(dir string) error {
	nextPath := filepath.Join(dir, nextRootKeyFile)
	keyData, err := securefile.ReadPrivate(nextPath, trust.MaxSealedKeySize)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read new root key: %w", err)
	}
	sealed, err := trust.UnmarshalSealedRootKey(keyData)
	if err != nil {
		_ = os.Remove(nextPath)
		return nil
	}
	pub := sealed.RootPublicKey()
	if _, err := readDocument(filepath.Join(dir, documentFile), pub); err == nil {
		return finishRootKey(dir, keyData)
	}
	// network.json was not replaced yet: take the history entry the new
	// root signed, if it was written.
	names, err := historyFiles(filepath.Join(dir, historyDir))
	if err != nil {
		return err
	}
	for i := len(names) - 1; i >= 0; i-- {
		data, err := securefile.ReadPrivate(filepath.Join(dir, historyDir, names[i]), trust.MaxEnvelopeSize)
		if err != nil {
			continue
		}
		env, err := trust.UnmarshalEnvelope(data)
		if err != nil {
			continue
		}
		if _, err := trust.VerifyDocumentSignature(env, pub); err == nil {
			if err := securefile.Replace(filepath.Join(dir, documentFile), data); err != nil {
				return fmt.Errorf("finish root change: %w", err)
			}
			return finishRootKey(dir, keyData)
		}
	}
	// Nothing was signed by the new root: undo.
	var k trust.Key
	copy(k[:], pub)
	_ = removeTransitionTo(dir, k)
	return os.Remove(nextPath)
}

func finishRootKey(dir string, keyData []byte) error {
	if err := securefile.Replace(filepath.Join(dir, rootKeyFile), keyData); err != nil {
		return fmt.Errorf("finish root change: %w", err)
	}
	return os.Remove(filepath.Join(dir, nextRootKeyFile))
}

func readTransitions(dir string) ([]trust.SignedRootTransition, error) {
	data, err := securefile.ReadPrivate(filepath.Join(dir, transitionsFile), maxTransitionsFile)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read root transitions: %w", err)
	}
	var f transitionsJSON
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, errors.New("transitions.json is corrupt")
	}
	out := make([]trust.SignedRootTransition, 0, len(f.Transitions))
	for _, line := range f.Transitions {
		st, err := trust.DecodeRootTransition(line)
		if err != nil {
			return nil, errors.New("transitions.json is corrupt")
		}
		out = append(out, st)
	}
	return out, nil
}

func writeTransitions(dir string, list []trust.SignedRootTransition) error {
	f := transitionsJSON{Transitions: []string{}}
	for _, st := range list {
		line, err := trust.EncodeRootTransition(st)
		if err != nil {
			return err
		}
		f.Transitions = append(f.Transitions, line)
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return securefile.Replace(filepath.Join(dir, transitionsFile), append(data, '\n'))
}

func appendTransition(dir string, st trust.SignedRootTransition) error {
	list, err := readTransitions(dir)
	if err != nil {
		return err
	}
	list = append(list, st)
	if len(list) > trust.MaxRootTransitions {
		list = list[len(list)-trust.MaxRootTransitions:]
	}
	return writeTransitions(dir, list)
}

func removeTransition(dir string, st trust.SignedRootTransition) error {
	list, err := readTransitions(dir)
	if err != nil {
		return err
	}
	out := slices.DeleteFunc(list, func(o trust.SignedRootTransition) bool {
		return bytes.Equal(o.Payload, st.Payload) && bytes.Equal(o.Signature, st.Signature)
	})
	return writeTransitions(dir, out)
}

func removeTransitionTo(dir string, newRoot trust.Key) error {
	list, err := readTransitions(dir)
	if err != nil {
		return err
	}
	out := slices.DeleteFunc(list, func(o trust.SignedRootTransition) bool {
		t, err := trust.ParseRootTransition(o)
		return err == nil && t.NewRoot == newRoot
	})
	return writeTransitions(dir, out)
}

// knownRootsLocked returns the current root followed by every earlier root
// named by the stored transitions, newest first. A transition only counts
// when it verifies: a rotation against the root it names, a recovery
// against a recovery key. Called with n.mu held.
func (n *Network) knownRootsLocked() []ed25519.PublicKey {
	return knownRoots(n.dir, n.sealed.RootPublicKey(), n.doc.RecoveryKeys)
}

func knownRoots(dir string, current ed25519.PublicKey, recovery []trust.Key) []ed25519.PublicKey {
	roots := []ed25519.PublicKey{current}
	list, err := readTransitions(dir)
	if err != nil {
		return roots
	}
	for i := len(list) - 1; i >= 0; i-- {
		t, err := trust.ParseRootTransition(list[i])
		if err != nil {
			continue
		}
		old := ed25519.PublicKey(append([]byte(nil), t.RevokedRoot[:]...))
		if _, err := trust.VerifyRootTransition(list[i], old, recovery); err != nil {
			continue
		}
		if !slices.ContainsFunc(roots, func(r ed25519.PublicKey) bool { return r.Equal(old) }) {
			roots = append(roots, old)
		}
	}
	return roots
}

// readHistoryVersion reads and verifies one history entry against any of
// the known roots.
func readHistoryVersion(dir string, version uint64, roots []ed25519.PublicKey) (trust.Envelope, *trust.Document, error) {
	if version == 0 {
		return trust.Envelope{}, nil, ErrLastGoodUnavailable
	}
	data, err := securefile.ReadPrivate(filepath.Join(dir, historyDir, historyName(version)), trust.MaxEnvelopeSize)
	if err != nil {
		return trust.Envelope{}, nil, ErrLastGoodUnavailable
	}
	env, err := trust.UnmarshalEnvelope(data)
	if err != nil {
		return trust.Envelope{}, nil, err
	}
	doc, err := verifyWithRoots(env, roots)
	if err != nil {
		return trust.Envelope{}, nil, err
	}
	if doc.Version != version {
		return trust.Envelope{}, nil, ErrLastGoodUnavailable
	}
	return env, doc, nil
}

func verifyWithRoots(env trust.Envelope, roots []ed25519.PublicKey) (*trust.Document, error) {
	var firstErr error
	for _, r := range roots {
		doc, err := trust.VerifyDocumentSignature(env, r)
		if err == nil {
			return doc, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		firstErr = trust.ErrBadSignature
	}
	return nil, firstErr
}

// readEnvelope reads network.json and verifies it against root.
func readEnvelope(path string, root ed25519.PublicKey) (trust.Envelope, *trust.Document, error) {
	data, err := securefile.ReadPrivate(path, trust.MaxEnvelopeSize)
	if err != nil {
		return trust.Envelope{}, nil, fmt.Errorf("read network document: %w", err)
	}
	env, err := trust.UnmarshalEnvelope(data)
	if err != nil {
		return trust.Envelope{}, nil, err
	}
	doc, err := trust.VerifyDocumentSignature(env, root)
	if err != nil {
		return trust.Envelope{}, nil, err
	}
	if doc, err = mergeMembersPart(filepath.Dir(path), doc); err != nil { // #629, members_only.go
		return trust.Envelope{}, nil, err
	}
	return env, doc, nil
}
