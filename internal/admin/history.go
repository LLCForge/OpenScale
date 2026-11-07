package admin

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

const maxHistoryEntries = 100_000

// HistoryEntry summarizes one signed version.
type HistoryEntry struct {
	Version   uint64    `json:"version"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Devices   int       `json:"devices"`
	Rules     int       `json:"rules"`
	Diff      *Diff     `json:"diff,omitempty"`
}

// HistoryReport is the result of verifying the whole history.
type HistoryReport struct {
	Entries  []HistoryEntry `json:"entries"`
	Problems []string       `json:"problems"`
	// versionOffset is the version jump of a root recovery (ADR-0027):
	// versions continue consecutively after it.
	versionOffset uint64
}

// OK reports whether the history verified without problems.
func (r HistoryReport) OK() bool { return len(r.Problems) == 0 }

// VerifyHistory checks every file in history/: valid root signature,
// consecutive versions starting at 1, file name matching the version,
// non-decreasing issue times, and that the latest entry equals
// network.json. Problems are collected rather than stopping at the first.
func (n *Network) VerifyHistory() (HistoryReport, error) {
	n.mu.Lock()
	current := n.doc
	// Entries before a root rotation or recovery verify against the roots
	// named by transitions.json (root.go, ADR-0027).
	roots := n.knownRootsLocked()
	dir := filepath.Join(n.dir, historyDir)
	n.mu.Unlock()

	report := HistoryReport{Entries: []HistoryEntry{}, Problems: []string{}}
	names, err := historyFiles(dir)
	if err != nil {
		return report, err
	}
	var prev *trust.Document
	var prevEnv trust.Envelope
	for i, name := range names {
		data, err := securefile.ReadPrivate(filepath.Join(dir, name), trust.MaxEnvelopeSize)
		if err != nil {
			report.Problems = append(report.Problems, fmt.Sprintf("%s okunamadı: %v", name, err))
			continue
		}
		env, err := trust.UnmarshalEnvelope(data)
		if err == nil {
			var doc *trust.Document
			doc, err = verifyWithRoots(env, roots)
			if err == nil {
				report.check(name, i, doc, prev)
				if prev != nil && chainForked(prevEnv, prev, doc) { // ADR-0144
					report.Problems = append(report.Problems, fmt.Sprintf("sürüm %d önceki sürümün özetini taşımıyor (çatallanmış geçmiş)", doc.Version))
				}
				prev, prevEnv = doc, env
				continue
			}
		}
		report.Problems = append(report.Problems, fmt.Sprintf("%s doğrulanamadı: %v", name, err))
	}
	switch {
	case prev == nil:
		report.Problems = append(report.Problems, "geçmişte hiç geçerli sürüm yok")
	case prev.Version != current.Version:
		report.Problems = append(report.Problems,
			fmt.Sprintf("network.json sürümü (%d) geçmişteki son sürümle (%d) aynı değil", current.Version, prev.Version))
	}
	return report, nil
}

func (r *HistoryReport) check(name string, index int, doc, prev *trust.Document) {
	if name != historyName(doc.Version) {
		r.Problems = append(r.Problems, fmt.Sprintf("%s dosya adı sürüm %d ile eşleşmiyor", name, doc.Version))
	}
	if want := uint64(index) + 1 + r.versionOffset; prev != nil && doc.RootEpoch > prev.RootEpoch && doc.Version > want {
		// A root recovery may skip versions the attacker used.
		r.versionOffset += doc.Version - want
	} else if doc.Version != want {
		r.Problems = append(r.Problems, fmt.Sprintf("sürüm %d bekleniyordu, %d bulundu (eksik veya fazla sürüm)", want, doc.Version))
	}
	entry := HistoryEntry{Version: doc.Version, IssuedAt: doc.IssuedAt, ExpiresAt: doc.ExpiresAt, Devices: len(doc.Devices), Rules: len(doc.Rules)}
	if prev != nil {
		if doc.NetworkID != prev.NetworkID {
			r.Problems = append(r.Problems, fmt.Sprintf("sürüm %d başka bir ağa ait", doc.Version))
		}
		if doc.IssuedAt.Before(prev.IssuedAt) {
			r.Problems = append(r.Problems, fmt.Sprintf("sürüm %d bir önceki sürümden daha eski tarihli", doc.Version))
		}
		d := ComputeDiff(prev, doc)
		entry.Diff = &d
	}
	r.Entries = append(r.Entries, entry)
}

func historyFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read history: %w", err)
	}
	var names []string
	for _, e := range entries {
		if e.Type().IsRegular() && strings.HasPrefix(e.Name(), "v") && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
		if len(names) > maxHistoryEntries {
			return nil, errors.New("history has too many entries")
		}
	}
	sort.Strings(names)
	return names, nil
}
