package coordinator

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/trust"
)

// Several independent coordinators and the cross-document check (#631,
// ADR-0183). Every coordinator answers TypeHead with what it serves: the
// root epoch, version and digest of its document. A device asks each
// coordinator of its document over the tunnel (WireGuard authenticates the
// coordinator by its pinned key) and compares the answers with CrossCheck:
//   - two coordinators serving different documents under the same epoch and
//     version is equivocation; both are root-signed, so the device can fetch
//     both as proof and must stop accepting either until the owner explains;
//   - a coordinator behind the others for longer than HeadStaleAfter hides
//     newer documents (censorship or a broken sync);
//   - a coordinator that does not answer is reported as unreachable.
// A forged document is impossible (root signature); what this catches is a
// coordinator, or a provider, withholding or splitting the network's view.

const (
	TypeHead    = "chead"
	FeatureHead = "chead"
	// HeadStaleAfter is how long a coordinator may lag behind the newest
	// version before it is reported.
	HeadStaleAfter = 10 * time.Minute
)

// Head is one coordinator's answer.
type Head struct {
	Schema    int       `json:"schema"`
	Epoch     uint64    `json:"epoch"`
	Version   uint64    `json:"version"`
	Digest    string    `json:"digest"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	ServedAt  time.Time `json:"served_at"`
	Emergency bool      `json:"emergency,omitempty"`
}

func (s *Server) head() control.Message {
	doc, _, digest := s.cfg.Store.Snapshot()
	h := Head{Schema: 1, Epoch: s.cfg.Store.Epoch(), Version: doc.Version, Digest: hexDigest(digest),
		IssuedAt: doc.IssuedAt.UTC(), ExpiresAt: doc.ExpiresAt.UTC(), ServedAt: s.cfg.Now().UTC(), Emergency: s.EmergencyActive()}
	data, err := json.Marshal(h)
	if err != nil || len(data) > control.ChunkSize {
		return control.Message{T: control.TypeError, Error: "head unavailable"}
	}
	return control.Message{T: TypeHead, Version: doc.Version, Digest: h.Digest, Data: data, Complete: true}
}

// ParseHead strictly decodes a TypeHead reply's data.
func ParseHead(data []byte) (Head, error) {
	var h Head
	if err := strictJSON(data, &h); err != nil {
		return Head{}, fmt.Errorf("coordinator head: %w", err)
	}
	if h.Schema != 1 || len(h.Digest) != 64 || strings.Trim(h.Digest, "0123456789abcdef") != "" {
		return Head{}, errors.New("coordinator head: bad fields")
	}
	return h, nil
}

// HeadObservation is what a device got from one coordinator.
type HeadObservation struct {
	Coordinator string    `json:"coordinator"` // label or key
	Head        *Head     `json:"head,omitempty"`
	Err         string    `json:"error,omitempty"`
	At          time.Time `json:"at"`
}

// Finding kinds of CrossCheck.
const (
	FindingEquivocation = "equivocation"
	FindingStale        = "stale"
	FindingUnreachable  = "unreachable"
	FindingSingle       = "single-coordinator"
	FindingSameRegion   = "same-region"
)

// HeadFinding is one problem found by CrossCheck.
type HeadFinding struct {
	Kind         string   `json:"kind"`
	Severity     string   `json:"severity"` // "critical", "warning", "info"
	Coordinators []string `json:"coordinators"`
	Message      string   `json:"message"`
}

// CrossReport is the result of CrossCheck.
type CrossReport struct {
	Newest   uint64        `json:"newest"`
	Epoch    uint64        `json:"epoch"`
	Findings []HeadFinding `json:"findings"`
	OK       bool          `json:"ok"`
}

// CrossCheck compares the heads of several coordinators. lastNewer maps a
// coordinator to when the device first saw a newer version elsewhere (the
// caller keeps it between checks); nil treats every lag as fresh.
func CrossCheck(obs []HeadObservation, lastNewer map[string]time.Time, now time.Time) CrossReport {
	r := CrossReport{OK: true}
	type key struct{ epoch, version uint64 }
	byKey := map[key]map[string][]string{}
	for _, o := range obs {
		if o.Head == nil {
			r.Findings = append(r.Findings, HeadFinding{Kind: FindingUnreachable, Severity: "warning", Coordinators: []string{o.Coordinator},
				Message: fmt.Sprintf("%s koordinatörü yanıt vermedi; belge yalnızca diğerlerinden doğrulanabildi.", o.Coordinator)})
			continue
		}
		h := o.Head
		if h.Epoch > r.Epoch || h.Epoch == r.Epoch && h.Version > r.Newest {
			r.Epoch, r.Newest = h.Epoch, h.Version
		}
		k := key{h.Epoch, h.Version}
		if byKey[k] == nil {
			byKey[k] = map[string][]string{}
		}
		byKey[k][h.Digest] = append(byKey[k][h.Digest], o.Coordinator)
	}
	keys := make([]key, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b key) int {
		if c := cmp.Compare(a.epoch, b.epoch); c != 0 {
			return c
		}
		return cmp.Compare(a.version, b.version)
	})
	for _, k := range keys {
		if len(byKey[k]) < 2 {
			continue
		}
		var who []string
		for _, cs := range byKey[k] {
			who = append(who, cs...)
		}
		slices.Sort(who)
		r.OK = false
		r.Findings = append(r.Findings, HeadFinding{Kind: FindingEquivocation, Severity: "critical", Coordinators: who,
			Message: fmt.Sprintf("Aynı sürüm (%d) için koordinatörler farklı belgeler sunuyor: kök anahtarla iki ayrı belge imzalanmış. Kök anahtarın ele geçirilmiş olabileceğini düşünün; belgeleri karşılaştırın.", k.version)})
	}
	for _, o := range obs {
		if o.Head == nil || o.Head.Epoch == r.Epoch && o.Head.Version == r.Newest {
			continue
		}
		since := now
		if t, ok := lastNewer[o.Coordinator]; ok {
			since = t
		}
		if now.Sub(since) < HeadStaleAfter {
			continue
		}
		r.OK = false
		r.Findings = append(r.Findings, HeadFinding{Kind: FindingStale, Severity: "warning", Coordinators: []string{o.Coordinator},
			Message: fmt.Sprintf("%s koordinatörü %s süredir eski sürümü (%d, en yenisi %d) sunuyor; yeni belgeleri saklıyor veya eşitleyemiyor olabilir.", o.Coordinator, now.Sub(since).Round(time.Minute), o.Head.Version, r.Newest)})
	}
	return r
}

// IndependenceAdvice reports whether doc lists coordinators that can check
// each other: at least two usable ones, in different regions.
func IndependenceAdvice(doc *trust.Document, now time.Time) []HeadFinding {
	cs := doc.UsableCoordinators(now)
	if len(cs) < 2 {
		return []HeadFinding{{Kind: FindingSingle, Severity: "info", Message: "Belgede tek koordinatör var; sahte belge veya sansürü ortaya çıkaracak ikinci, bağımsız bir koordinatör yok. Başka bir sağlayıcıda ek koordinatör ekleyin ('network coordinator add')."}}
	}
	regions := map[string][]string{}
	for _, c := range cs {
		regions[strings.ToLower(strings.TrimSpace(c.Region))] = append(regions[strings.ToLower(strings.TrimSpace(c.Region))], c.CoordinatorLabel())
	}
	if len(regions) == 1 {
		for reg, names := range regions {
			if reg == "" {
				return []HeadFinding{{Kind: FindingSameRegion, Severity: "info", Coordinators: names, Message: "Koordinatörlerin bölgesi belgede yazılı değil; bağımsız sağlayıcılarda olduklarını doğrulayın ve bölge etiketi verin."}}
			}
			return []HeadFinding{{Kind: FindingSameRegion, Severity: "warning", Coordinators: names, Message: "Bütün koordinatörler aynı bölgede (" + reg + "); tek bir sağlayıcı veya ülke hepsine aynı anda müdahale edebilir."}}
		}
	}
	return nil
}
