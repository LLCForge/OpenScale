package coordinator

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Coordinator migration preflight (#485, ADR-0153). Before the owner signs
// a document that makes another coordinator the primary one, the target
// coordinator (already listed as an additional coordinator, so every
// device keeps a WireGuard session with it) reports which devices have a
// recent handshake with its own key. Compared with the current primary's
// report, the devices that are online but cannot reach the target are
// listed; the signing command refuses while any are left.

// Preflight limits.
const (
	// MaxReportSkew is how far apart the two reach reports may be taken.
	MaxReportSkew = 15 * time.Minute
	// MaxPreflightAge is how old a preflight result may be at signing.
	MaxPreflightAge = time.Hour
)

// PreflightResult is the outcome of a migration preflight.
type PreflightResult struct {
	Schema      int       `json:"schema"`
	Coordinator string    `json:"coordinator"`
	Fingerprint string    `json:"fingerprint"`
	At          time.Time `json:"at"`
	DocVersion  uint64    `json:"doc_version"`
	// Compared is true when an online list from the current primary was
	// used; without it every device that does not reach the target counts
	// as unreachable (fail closed).
	Compared    bool     `json:"compared"`
	Reachable   []string `json:"reachable"`
	Unreachable []string `json:"unreachable"`
	// Offline devices reached neither coordinator; they learn the new
	// document from the old primary during the transition.
	Offline []string `json:"offline"`
}

// Preflight compares the target coordinator's reach report with the
// current primary's (online may be nil).
func Preflight(target ReachReport, online *ReachReport) (PreflightResult, error) {
	if target.Schema != opsSchema || target.Coordinator == "" {
		return PreflightResult{}, errors.New("invalid target reach report")
	}
	if target.Primary {
		return PreflightResult{}, errors.New("the target is already the primary coordinator; run the preflight on the coordinator you want to move to")
	}
	res := PreflightResult{
		Schema: opsSchema, Coordinator: target.Coordinator, Fingerprint: target.Fingerprint,
		At: target.At, DocVersion: target.DocVersion,
		Reachable: []string{}, Unreachable: []string{}, Offline: []string{},
	}
	onlineIDs := map[string]bool{}
	if online != nil {
		if online.Schema != opsSchema || online.Coordinator == "" {
			return PreflightResult{}, errors.New("invalid online reach report")
		}
		if online.Coordinator == target.Coordinator {
			return PreflightResult{}, errors.New("both reach reports come from the same coordinator")
		}
		if d := target.At.Sub(online.At); d > MaxReportSkew || d < -MaxReportSkew {
			return PreflightResult{}, fmt.Errorf("the reach reports were taken more than %s apart; take them again", MaxReportSkew)
		}
		res.Compared = true
		for _, d := range online.Devices {
			if d.Reached {
				onlineIDs[d.ID] = true
			}
		}
	}
	for _, d := range target.Devices {
		switch {
		case d.Reached:
			res.Reachable = append(res.Reachable, d.Name)
		case !res.Compared || onlineIDs[d.ID]:
			res.Unreachable = append(res.Unreachable, d.Name)
		default:
			res.Offline = append(res.Offline, d.Name)
		}
	}
	for _, l := range [][]string{res.Reachable, res.Unreachable, res.Offline} {
		slices.Sort(l)
	}
	return res, nil
}

// ParsePreflight decodes a saved preflight result strictly.
func ParsePreflight(data []byte) (PreflightResult, error) {
	var r PreflightResult
	if err := decodeOps(data, &r); err != nil {
		return PreflightResult{}, fmt.Errorf("preflight: %w", err)
	}
	if r.Schema != opsSchema || r.Coordinator == "" || r.At.IsZero() {
		return PreflightResult{}, errors.New("preflight: invalid result")
	}
	return r, nil
}

// CheckPreflight reports why res does not allow making the coordinator
// with key (its base64 WireGuard key) the primary at now; nil allows it.
func CheckPreflight(res PreflightResult, key string, now time.Time) error {
	if res.Coordinator != key {
		return errors.New("the preflight was run on a different coordinator")
	}
	if age := now.Sub(res.At); age > MaxPreflightAge || age < -MaxReportSkew {
		return fmt.Errorf("the preflight is older than %s; run it again", MaxPreflightAge)
	}
	if len(res.Unreachable) > 0 {
		return fmt.Errorf("%d device(s) cannot reach the new coordinator: %s", len(res.Unreachable), strings.Join(res.Unreachable, ", "))
	}
	return nil
}
