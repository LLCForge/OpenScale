// Package admin implements owner operations on a network directory. The
// CLI and the web panel both go through this package, so the panel never
// becomes a separate path to the root key.
package admin

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

// Errors specific to network administration.
var (
	ErrNetworkExists      = errors.New("a network already exists in this directory")
	ErrConcurrentChange   = errors.New("the network document was changed by another process")
	ErrSamePassphrase     = errors.New("the new passphrase must differ from the current one")
	ErrBackupKeyMismatch  = errors.New("backup does not belong to this network")
	ErrHistoryVersionUsed = errors.New("this version already exists in the history")
)

const (
	rootKeyFile  = "root.key"
	documentFile = "network.json"
	historyDir   = "history"
	backupsFile  = "backups.json"
	maxBackups   = 1000
)

// Network is a loaded network directory. Methods are safe for concurrent
// use; mutations are serialized.
type Network struct {
	mu     sync.Mutex
	dir    string
	sealed *trust.SealedRootKey
	doc    *trust.Document
	argon  trust.Argon2Params
	random io.Reader
}

// Options configures key derivation and randomness.
type Options struct {
	Argon2 trust.Argon2Params
	Random io.Reader
}

// InitOptions configures a new network.
type InitOptions struct {
	DNSDomain  string
	IPv4Prefix netip.Prefix
	Validity   time.Duration
}

// Init creates a new network in dir and returns it.
func Init(dir string, init InitOptions, passphrase []byte, opts Options, now time.Time) (*Network, error) {
	if _, err := os.Stat(filepath.Join(dir, rootKeyFile)); err == nil {
		return nil, ErrNetworkExists
	}
	if err := trust.CheckPassphrase(passphrase); err != nil {
		return nil, err
	}
	opts.Argon2 = calibratedArgon2(opts.Argon2) // #11, kdf.go
	_, rootPriv, err := trust.GenerateRootKey(opts.Random)
	if err != nil {
		return nil, err
	}
	defer wipe(rootPriv)
	networkID, err := trust.NewNetworkID(opts.Random)
	if err != nil {
		return nil, err
	}
	prefix6, err := trust.RandomULAPrefix(opts.Random)
	if err != nil {
		return nil, err
	}
	doc, err := trust.NewDocument(networkID, strings.ToLower(init.DNSDomain), init.IPv4Prefix, prefix6, now, init.Validity)
	if err != nil {
		return nil, err
	}
	sealed, err := trust.SealRootKey(rootPriv, passphrase, opts.Argon2, opts.Random)
	if err != nil {
		return nil, err
	}
	data, err := trust.MarshalSealedRootKey(sealed)
	if err != nil {
		return nil, err
	}
	if err := securefile.WriteNew(filepath.Join(dir, rootKeyFile), data); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return nil, ErrNetworkExists
		}
		return nil, fmt.Errorf("write root key: %w", err)
	}
	n := &Network{dir: dir, sealed: sealed, doc: doc, argon: opts.Argon2, random: opts.Random}
	if err := n.save(doc, rootPriv); err != nil {
		return nil, err
	}
	return n, nil
}

// Load opens an existing network directory and verifies the document
// signature against the root key.
func Load(dir string, opts Options) (*Network, error) {
	// Finish or undo an interrupted root key change (root.go, ADR-0027).
	if err := finishRootChange(dir); err != nil {
		return nil, err
	}
	sealed, err := readSealed(filepath.Join(dir, rootKeyFile))
	if err != nil {
		return nil, err
	}
	doc, err := readDocument(filepath.Join(dir, documentFile), sealed.RootPublicKey())
	if err != nil {
		return nil, err
	}
	// Re-sealing (passphrase change, backup) never lowers the KDF cost the
	// key already has (#11).
	argon := trust.StrongerArgon2(opts.Argon2, sealed.KDFParams())
	return &Network{dir: dir, sealed: sealed, doc: doc, argon: argon, random: opts.Random}, nil
}

// Dir returns the network directory.
func (n *Network) Dir() string { return n.dir }

// RootFingerprint returns the short root key fingerprint.
func (n *Network) RootFingerprint() string { return n.sealed.Fingerprint() }

// Document returns a deep copy of the current document.
func (n *Network) Document() (*trust.Document, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return copyDocument(n.doc)
}

// CheckPassphrase verifies the root key passphrase without keeping the
// decrypted key. The panel uses it to sign in.
func (n *Network) CheckPassphrase(passphrase []byte) error {
	n.mu.Lock()
	sealed := n.sealed
	n.mu.Unlock()
	priv, err := sealed.Open(passphrase)
	if err != nil {
		return err
	}
	wipe(priv)
	return nil
}

// JoinBundle returns the join bundle line for the current document: the
// root public key plus the signed document (ADR-0013).
func (n *Network) JoinBundle() (string, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	data, err := securefile.ReadPrivate(filepath.Join(n.dir, documentFile), trust.MaxEnvelopeSize)
	if err != nil {
		return "", fmt.Errorf("read network document: %w", err)
	}
	env, err := trust.UnmarshalEnvelope(data)
	if err != nil {
		return "", err
	}
	if _, err := trust.VerifyDocumentSignature(env, n.sealed.RootPublicKey()); err != nil {
		return "", err
	}
	return trust.EncodeJoinBundle(trust.JoinBundle{RootKey: n.sealed.PublicKey, Document: env})
}

// Change mutates the next document version.
type Change func(doc *trust.Document) error

// Plan is a prepared but unsigned change.
type Plan struct {
	Next *trust.Document
	Diff Diff
	base uint64
}

// Prepare applies change to a copy of the current document and returns the
// resulting version and its difference from the current one. Nothing is
// signed or written; this is also the dry-run path.
func (n *Network) Prepare(now time.Time, validity time.Duration, change Change) (*Plan, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	next, err := n.doc.Next(now, validity)
	if err != nil {
		return nil, err
	}
	if err := change(next); err != nil {
		return nil, err
	}
	// Expired ephemeral devices leave with every signed version (#22).
	next.PruneEphemeral(now)
	// Icons, ranges and support rules need clients that understand them;
	// older ones reject the document (ADR-0232, trust/f4a_schema.go).
	trust.RaiseMinClientForSchema(next)
	// Version chain: link to the signed network.json (ADR-0144, chain.go).
	if err := n.linkVersionChainLocked(next); err != nil {
		return nil, err
	}
	if err := next.Validate(); err != nil {
		return nil, err
	}
	// Policy tests run on the dry-run path too; SignDocument repeats the
	// check before the signature (F-076).
	if err := next.CheckPolicyTests(); err != nil {
		return nil, err
	}
	return &Plan{Next: next, Diff: ComputeDiff(n.doc, next), base: n.doc.Version}, nil
}

// Commit signs a prepared plan with the root key and saves it. It refuses
// if the document changed since Prepare, including changes made by another
// process such as the CLI while the panel is open.
func (n *Network) Commit(plan *Plan, passphrase []byte) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if plan == nil || plan.Next == nil || plan.base != n.doc.Version || plan.Next.Version <= plan.base {
		return ErrConcurrentChange
	}
	onDisk, err := readDocument(filepath.Join(n.dir, documentFile), n.sealed.RootPublicKey())
	if err != nil {
		return err
	}
	if onDisk.Version != n.doc.Version {
		n.doc = onDisk
		return ErrConcurrentChange
	}
	rootPriv, err := n.sealed.Open(passphrase)
	if err != nil {
		return err
	}
	defer wipe(rootPriv)
	if err := n.save(plan.Next, rootPriv); err != nil {
		return err
	}
	return nil
}

// Reload re-reads the document from disk.
func (n *Network) Reload() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	doc, err := readDocument(filepath.Join(n.dir, documentFile), n.sealed.RootPublicKey())
	if err != nil {
		return err
	}
	n.doc = doc
	return nil
}

// save signs doc, appends it to the history (never overwritten) and then
// atomically replaces network.json. Called with n.mu held or during Init.
func (n *Network) save(doc *trust.Document, rootPriv ed25519.PrivateKey) error {
	if subtle.ConstantTimeCompare(rootPriv.Public().(ed25519.PublicKey), n.sealed.PublicKey[:]) != 1 {
		return errors.New("root key does not match the sealed key")
	}
	signed, membersPlain, err := n.sealForSigning(doc) // members-only (#629, members_only.go)
	if err != nil {
		return err
	}
	env, err := trust.SignDocument(signed, rootPriv)
	if err != nil {
		return err
	}
	carrySensitive(filepath.Join(n.dir, documentFile), &env, signed) // ADR-0174, g1_admin.go
	data, err := trust.MarshalEnvelope(env)
	if err != nil {
		return err
	}
	// Signature ledger first (#342, ledger.go).
	if err := recordSigned(n.dir, env, signed); err != nil {
		return err
	}
	if err := writeMembersPart(n.dir, doc.Version, membersPlain); err != nil {
		return err
	}
	historyPath := filepath.Join(n.dir, historyDir, historyName(doc.Version))
	if err := securefile.WriteNew(historyPath, data); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return ErrHistoryVersionUsed
		}
		return fmt.Errorf("write history: %w", err)
	}
	if err := securefile.Replace(filepath.Join(n.dir, documentFile), data); err != nil {
		return fmt.Errorf("write network document: %w", err)
	}
	n.doc = doc
	return nil
}

// ChangePassphrase re-encrypts the root key with a new passphrase and a new
// salt. Existing backups keep their own passphrases.
func (n *Network) ChangePassphrase(current, next []byte) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if subtle.ConstantTimeCompare(current, next) == 1 {
		return ErrSamePassphrase
	}
	if err := trust.CheckPassphrase(next); err != nil {
		return err
	}
	rootPriv, err := n.sealed.Open(current)
	if err != nil {
		return err
	}
	defer wipe(rootPriv)
	sealed, err := trust.SealRootKey(rootPriv, next, n.argon, n.random)
	if err != nil {
		return err
	}
	data, err := trust.MarshalSealedRootKey(sealed)
	if err != nil {
		return err
	}
	if err := securefile.Replace(filepath.Join(n.dir, rootKeyFile), data); err != nil {
		return fmt.Errorf("write root key: %w", err)
	}
	n.sealed = sealed
	return nil
}

func readSealed(path string) (*trust.SealedRootKey, error) {
	data, err := securefile.ReadPrivate(path, trust.MaxSealedKeySize)
	if err != nil {
		return nil, fmt.Errorf("read root key: %w", err)
	}
	return trust.UnmarshalSealedRootKey(data)
}

func readDocument(path string, root ed25519.PublicKey) (*trust.Document, error) {
	data, err := securefile.ReadPrivate(path, trust.MaxEnvelopeSize)
	if err != nil {
		return nil, fmt.Errorf("read network document: %w", err)
	}
	env, err := trust.UnmarshalEnvelope(data)
	if err != nil {
		return nil, err
	}
	doc, err := trust.VerifyDocumentSignature(env, root)
	if err != nil {
		return nil, err
	}
	return mergeMembersPart(filepath.Dir(path), doc) // #629, members_only.go
}

func historyName(version uint64) string {
	return fmt.Sprintf("v%010d.json", version)
}

func copyDocument(doc *trust.Document) (*trust.Document, error) {
	data, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	var out trust.Document
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// wipe zeroes b and releases its memory lock if the root key was locked
// (#8, ADR-0060).
func wipe(b []byte) {
	trust.WipeKey(b)
}
