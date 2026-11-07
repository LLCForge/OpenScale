package admin

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strconv"
	"time"

	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

// Signature ledger (#342, ADR-0151). The owner's directory keeps a local,
// hash-chained list of every document version it signed. A valid
// root-signed version that is not in the ledger, and is newer than where
// the ledger starts, was signed somewhere else: the root key was used
// outside this directory. #24 catches two contents for one version; this
// catches a version the owner never signed at all.

const (
	ledgerFile = "signature-ledger.jsonl"
	// maxLedgerSize bounds the ledger read (about 200 bytes per version).
	maxLedgerSize = 64 << 20
	ledgerContext = "openscale/signature-ledger/v1"
)

// ErrLedgerBroken means the ledger's hash chain does not hold: it was
// edited or truncated in the middle.
var ErrLedgerBroken = errors.New("signature ledger hash chain is broken")

// LedgerEntry is one signed version.
type LedgerEntry struct {
	Seq       uint64    `json:"seq"`
	Version   uint64    `json:"version"`
	RootEpoch uint64    `json:"root_epoch,omitempty"`
	Digest    string    `json:"digest"`
	SignedAt  time.Time `json:"signed_at"`
	Prev      string    `json:"prev"`
	Hash      string    `json:"hash"`
}

func (e LedgerEntry) computeHash() string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\n%d\n%d\n%d\n%s\n%s\n%s\n", ledgerContext, e.Seq, e.Version, e.RootEpoch, e.Digest,
		e.SignedAt.UTC().Format(time.RFC3339Nano), e.Prev)
	return hex.EncodeToString(h.Sum(nil))
}

// readLedger returns the entries and verifies the chain. A missing file is
// an empty ledger.
func readLedger(dir string) ([]LedgerEntry, error) {
	data, err := securefile.ReadPrivate(filepath.Join(dir, ledgerFile), maxLedgerSize)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read signature ledger: %w", err)
	}
	var out []LedgerEntry
	prev := ""
	for i, line := range bytes.Split(data, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var e LedgerEntry
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&e); err != nil {
			return out, fmt.Errorf("%w: line %d: %v", ErrLedgerBroken, i+1, err)
		}
		if e.Seq != uint64(len(out)+1) || e.Prev != prev || e.Hash != e.computeHash() || len(e.Digest) != 64 {
			return out, fmt.Errorf("%w: line %d", ErrLedgerBroken, i+1)
		}
		prev = e.Hash
		out = append(out, e)
	}
	return out, nil
}

// recordSigned appends a just-signed envelope to the ledger. It is called
// before the version is written anywhere else, so a version on disk is
// never missing from the ledger; an entry for a version whose write later
// failed is harmless.
func recordSigned(dir string, env trust.Envelope, doc *trust.Document) error {
	entries, err := readLedger(dir)
	if err != nil {
		return err
	}
	e := LedgerEntry{Seq: uint64(len(entries) + 1), Version: doc.Version, RootEpoch: doc.RootEpoch,
		Digest: trust.DocumentDigest(env), SignedAt: doc.IssuedAt.UTC()}
	if len(entries) > 0 {
		e.Prev = entries[len(entries)-1].Hash
	}
	e.Hash = e.computeHash()
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, ledgerFile)
	old, err := securefile.ReadPrivate(path, maxLedgerSize)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return securefile.WriteNew(path, append(line, '\n'))
	case err != nil:
		return fmt.Errorf("read signature ledger: %w", err)
	}
	if int64(len(old)+len(line)+1) > maxLedgerSize {
		return errors.New("signature ledger is full")
	}
	if len(old) > 0 && old[len(old)-1] != '\n' {
		old = append(old, '\n')
	}
	return securefile.Replace(path, append(append(old, line...), '\n'))
}

// LedgerVerdict says what the ledger knows about one signed version.
type LedgerVerdict string

// Ledger verdicts.
const (
	// LedgerKnown: this directory signed exactly this version.
	LedgerKnown LedgerVerdict = "known"
	// LedgerForeign: valid root signature, newer than the ledger's start,
	// but never signed here. The root key was used elsewhere.
	LedgerForeign LedgerVerdict = "foreign"
	// LedgerUntracked: older than the ledger (signed before it existed).
	LedgerUntracked LedgerVerdict = "untracked"
	// LedgerEmpty: the ledger has no entries yet.
	LedgerEmpty LedgerVerdict = "empty"
)

// LedgerCheck is the result of checking one version.
type LedgerCheck struct {
	Verdict   LedgerVerdict `json:"verdict"`
	Version   uint64        `json:"version"`
	RootEpoch uint64        `json:"rootEpoch"`
	Digest    string        `json:"digest"`
}

func classify(entries []LedgerEntry, version, epoch uint64, digest string) LedgerVerdict {
	if len(entries) == 0 {
		return LedgerEmpty
	}
	for _, e := range entries {
		if e.Digest == digest {
			return LedgerKnown
		}
	}
	first := entries[0]
	if epoch < first.RootEpoch || (epoch == first.RootEpoch && version < first.Version) {
		return LedgerUntracked
	}
	return LedgerForeign
}

// CheckSigned verifies env against the current root key and says whether
// this directory signed it. A version under an older root epoch than the
// current key cannot be verified here and is refused.
func (n *Network) CheckSigned(env trust.Envelope) (LedgerCheck, error) {
	n.mu.Lock()
	root := n.sealed.RootPublicKey()
	n.mu.Unlock()
	doc, err := trust.VerifyDocumentSignature(env, root)
	if err != nil {
		return LedgerCheck{}, err
	}
	entries, err := readLedger(n.dir)
	if err != nil {
		return LedgerCheck{}, err
	}
	d := trust.DocumentDigest(env)
	return LedgerCheck{Verdict: classify(entries, doc.Version, doc.RootEpoch, d), Version: doc.Version, RootEpoch: doc.RootEpoch, Digest: d}, nil
}

// LedgerStatus summarizes the ledger and its problems.
type LedgerStatus struct {
	Entries     int        `json:"entries"`
	First       uint64     `json:"firstVersion"`
	Last        uint64     `json:"lastVersion"`
	LastEpoch   uint64     `json:"lastEpoch"`
	LastSigned  *time.Time `json:"lastSigned"`
	Problems    []string   `json:"problems"`
	ForeignSeen bool       `json:"foreignSeen"`
}

// LedgerStatus verifies the ledger chain and checks network.json and the
// history against it.
func (n *Network) LedgerStatus() (LedgerStatus, error) {
	st := LedgerStatus{Problems: []string{}}
	entries, err := readLedger(n.dir)
	if errors.Is(err, ErrLedgerBroken) {
		st.Entries = len(entries)
		st.Problems = append(st.Problems, "İmza defterinin karma zinciri bozuk: defter elle değiştirilmiş veya kesilmiş ("+err.Error()+").")
		return st, nil
	}
	if err != nil {
		return st, err
	}
	st.Entries = len(entries)
	if len(entries) == 0 {
		return st, nil
	}
	first, last := entries[0], entries[len(entries)-1]
	st.First, st.Last, st.LastEpoch = first.Version, last.Version, last.RootEpoch
	t := last.SignedAt
	st.LastSigned = &t
	n.mu.Lock()
	dir := n.dir
	n.mu.Unlock()
	data, err := securefile.ReadPrivate(filepath.Join(dir, documentFile), trust.MaxEnvelopeSize)
	if err != nil {
		return st, fmt.Errorf("read network document: %w", err)
	}
	env, err := trust.UnmarshalEnvelope(data)
	if err != nil {
		return st, err
	}
	if c, err := n.CheckSigned(env); err == nil && c.Verdict == LedgerForeign {
		st.ForeignSeen = true
		st.Problems = append(st.Problems, "KRİTİK: network.json (sürüm "+strconv.FormatUint(c.Version, 10)+") geçerli kök imzalı ama bu klasörün imza defterinde yok. Kök anahtar başka bir yerde kullanılmış olabilir.")
	}
	return st, nil
}

// CheckRunningVersion compares the version a member device runs with the
// ledger: a version above everything signed here (same or newer root
// epoch) means another signer. It returns a problem text or "".
func (n *Network) CheckRunningVersion(version uint64) (string, error) {
	entries, err := readLedger(n.dir)
	if err != nil || len(entries) == 0 {
		return "", err
	}
	highest := uint64(0)
	for _, e := range entries {
		highest = max(highest, e.Version)
	}
	if version > highest {
		return fmt.Sprintf("KRİTİK: bu bilgisayardaki cihaz ağ belgesi sürüm %d çalıştırıyor, ama bu klasör en çok sürüm %d imzaladı. Kök anahtar başka bir yerde kullanılmış olabilir.", version, highest), nil
	}
	return "", nil
}

// Ledger returns the ledger entries (verified).
func (n *Network) Ledger() ([]LedgerEntry, error) { return readLedger(n.dir) }
