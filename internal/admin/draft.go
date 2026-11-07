package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

// Change draft (#344, ADR-0151). Edits made in the panel or the CLI with
// "draft" collect in draft.json as one unsigned next version; signing the
// draft is one diff, one passphrase entry and one version increase, so
// dependent edits (a rename and the rule that uses the new name) are never
// published half done. The draft is unsigned owner-side state, like the
// rest of the network directory; nothing in it is trusted until the owner
// reviews the diff and signs.

const (
	draftFile       = "draft.json"
	maxDraftSize    = trust.MaxDocumentSize + 256<<10
	maxDraftEntries = 256
)

// ErrNoDraft means there is no draft to show, sign or discard.
var ErrNoDraft = errors.New("there is no change draft")

// ErrDraftStale means the document was signed since the draft was started;
// the draft must be discarded and made again.
var ErrDraftStale = errors.New("the network document changed since the draft was started; discard the draft")

type draftData struct {
	Base      uint64          `json:"base"`
	Created   time.Time       `json:"created"`
	Updated   time.Time       `json:"updated"`
	Entries   []string        `json:"entries"`
	Document  *trust.Document `json:"document"`
	Validated string          `json:"validated,omitempty"`
}

// Draft is a pending change draft.
type Draft struct {
	Base    uint64    `json:"base"`
	Created time.Time `json:"created"`
	Updated time.Time `json:"updated"`
	// Entries are the diff lines of each staged edit, in order.
	Entries []string `json:"entries"`
	// Lines is the diff of the whole draft against the current document.
	Lines []string `json:"lines"`
	// Problem is why the draft cannot be signed yet ("" when it can).
	Problem string `json:"problem"`
	Stale   bool   `json:"stale"`
}

func readDraft(dir string) (*draftData, error) {
	data, err := securefile.ReadPrivate(filepath.Join(dir, draftFile), maxDraftSize)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNoDraft
	}
	if err != nil {
		return nil, fmt.Errorf("read draft: %w", err)
	}
	var d draftData
	if err := json.Unmarshal(data, &d); err != nil || d.Document == nil {
		return nil, errors.New("draft.json is damaged; discard it")
	}
	return &d, nil
}

func writeDraft(dir string, d *draftData) error {
	data, err := json.Marshal(d)
	if err != nil {
		return err
	}
	if len(data) > maxDraftSize {
		return errors.New("draft is too large")
	}
	return securefile.Replace(filepath.Join(dir, draftFile), data)
}

// StageDraft applies change to the draft, starting one from the current
// document if there is none. Intermediate states need not validate; the
// whole draft is validated when it is signed. It returns the diff lines of
// this edit.
func (n *Network) StageDraft(now time.Time, change Change) ([]string, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	d, err := readDraft(n.dir)
	switch {
	case errors.Is(err, ErrNoDraft):
		next, err := n.doc.Next(now, trust.DefaultValidity)
		if err != nil {
			return nil, err
		}
		d = &draftData{Base: n.doc.Version, Created: now.UTC(), Document: next}
	case err != nil:
		return nil, err
	case d.Base != n.doc.Version:
		return nil, ErrDraftStale
	}
	if len(d.Entries) >= maxDraftEntries {
		return nil, fmt.Errorf("a draft holds at most %d edits; sign or discard it", maxDraftEntries)
	}
	before, err := copyDocument(d.Document)
	if err != nil {
		return nil, err
	}
	if err := change(d.Document); err != nil {
		return nil, err
	}
	a, errA := json.Marshal(before)
	b, errB := json.Marshal(d.Document)
	if errA != nil || errB != nil {
		return nil, errors.New("draft cannot be encoded")
	}
	if string(a) == string(b) {
		return nil, errors.New("this edit changes nothing")
	}
	// The version line is the same for every staged edit; leave it out.
	same := fmt.Sprintf("Sürüm %d -> %d", d.Document.Version, d.Document.Version)
	var lines []string
	for _, l := range ComputeDiff(before, d.Document).Lines() {
		if l != same {
			lines = append(lines, l)
		}
	}
	d.Entries = append(d.Entries, lines...)
	if len(d.Entries) > maxDraftEntries {
		d.Entries = d.Entries[:maxDraftEntries]
	}
	d.Updated = now.UTC()
	if err := writeDraft(n.dir, d); err != nil {
		return nil, err
	}
	return lines, nil
}

// Draft returns the pending draft.
func (n *Network) Draft() (*Draft, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	d, err := readDraft(n.dir)
	if err != nil {
		return nil, err
	}
	out := &Draft{Base: d.Base, Created: d.Created, Updated: d.Updated, Entries: append([]string{}, d.Entries...), Lines: []string{}}
	if d.Base != n.doc.Version {
		out.Stale = true
		out.Problem = "Taslak başladıktan sonra belge imzalandı; taslağı silip yeniden hazırlayın."
		return out, nil
	}
	out.Lines = ComputeDiff(n.doc, d.Document).Lines()
	probe, err := copyDocument(d.Document)
	if err != nil {
		return nil, err
	}
	if probe.VersionChainEnabled() {
		// Prepare links the chain when the draft is signed.
		probe.PrevDigest = strings.Repeat("1", 64)
	}
	if err := probe.Validate(); err != nil {
		out.Problem = err.Error()
	}
	return out, nil
}

// PrepareDraft turns the draft into a plan exactly like Prepare: a fresh
// version number, issue time and validity, the version chain link, full
// validation and the policy tests.
func (n *Network) PrepareDraft(now time.Time, validity time.Duration) (*Plan, error) {
	n.mu.Lock()
	d, err := readDraft(n.dir)
	base := n.doc.Version
	n.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if d.Base != base {
		return nil, ErrDraftStale
	}
	staged := d.Document
	return n.Prepare(now, validity, func(doc *trust.Document) error {
		if doc.Version != d.Base+1 {
			return ErrDraftStale
		}
		next := *staged
		// Fresh version metadata; Prepare relinks the version chain.
		// A staged edit may have raised the version (RevokeAdminGrant).
		next.Version, next.IssuedAt, next.ExpiresAt = max(doc.Version, staged.Version), doc.IssuedAt, doc.ExpiresAt
		*doc = next
		return nil
	})
}

// CommitDraft signs a plan made by PrepareDraft and removes the draft.
func (n *Network) CommitDraft(plan *Plan, passphrase []byte) error {
	if err := n.Commit(plan, passphrase); err != nil {
		return err
	}
	return n.DiscardDraft()
}

// DiscardDraft removes the draft.
func (n *Network) DiscardDraft() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	err := os.Remove(filepath.Join(n.dir, draftFile))
	if errors.Is(err, fs.ErrNotExist) {
		return ErrNoDraft
	}
	return err
}
