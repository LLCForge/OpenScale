package coordinator

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

// Relay admission (F-096, #287, ADR-0136). Besides the authority the signed
// document gives (only tunnel peers may relay to each other), the owner can
// narrow relaying with a local file on the coordinator. It only ever takes
// permission away: a pair must be allowed by the document AND by the file.
// When the file cannot be read or parsed, nothing is relayed (fail closed);
// there is no "open on error" mode.

// RelayAdmissionFile is the admission file's name inside the coordinator's
// state directory, which the Landlock sandbox keeps readable.
const RelayAdmissionFile = "relay-admission.json"

const (
	maxAdmissionFile      = 64 << 10
	maxAdmissionRules     = 256
	maxAdmissionSelectors = 64
	maxSelectorLen        = 80
	// admissionRecheck is how often the file is checked for changes.
	admissionRecheck = 5 * time.Second
)

// AdmissionRule allows relaying from any device matching From to any
// device matching To. A selector is "*", a device name or "tag:<name>".
type AdmissionRule struct {
	From []string `json:"from"`
	To   []string `json:"to"`
}

// AdmissionPolicy is the content of the admission file.
type AdmissionPolicy struct {
	Version int             `json:"version"`
	Allow   []AdmissionRule `json:"allow"`
}

// ParseAdmissionPolicy decodes and checks an admission file strictly:
// unknown fields, trailing data and malformed selectors are errors.
func ParseAdmissionPolicy(data []byte) (*AdmissionPolicy, error) {
	if len(data) > maxAdmissionFile {
		return nil, errors.New("relay admission file is too large")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var p AdmissionPolicy
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("relay admission file: %w", err)
	}
	if dec.More() {
		return nil, errors.New("relay admission file: trailing data")
	}
	if p.Version != 1 {
		return nil, fmt.Errorf("relay admission file: unsupported version %d", p.Version)
	}
	if len(p.Allow) > maxAdmissionRules {
		return nil, fmt.Errorf("relay admission file: at most %d rules", maxAdmissionRules)
	}
	for i, r := range p.Allow {
		for _, side := range [][]string{r.From, r.To} {
			if len(side) == 0 || len(side) > maxAdmissionSelectors {
				return nil, fmt.Errorf("relay admission rule %d: from and to need 1-%d selectors", i+1, maxAdmissionSelectors)
			}
			for _, s := range side {
				if err := validSelector(s); err != nil {
					return nil, fmt.Errorf("relay admission rule %d: %w", i+1, err)
				}
			}
		}
	}
	return &p, nil
}

func validSelector(s string) error {
	name := strings.TrimPrefix(s, "tag:")
	if s == "*" {
		return nil
	}
	if name == "" || len(s) > maxSelectorLen || strings.ContainsAny(name, " \t\r\n*:") {
		return fmt.Errorf("invalid selector %q", s)
	}
	return nil
}

func selectorMatches(s string, d trust.Device) bool {
	if s == "*" {
		return true
	}
	if tag, ok := strings.CutPrefix(s, "tag:"); ok {
		for _, t := range d.Tags {
			if t == tag {
				return true
			}
		}
		return false
	}
	return s == d.Name
}

func anyMatches(sel []string, d trust.Device) bool {
	for _, s := range sel {
		if selectorMatches(s, d) {
			return true
		}
	}
	return false
}

// Allows reports whether the policy admits relaying from one device to
// another. A nil policy admits nothing.
func (p *AdmissionPolicy) Allows(from, to trust.Device) bool {
	if p == nil {
		return false
	}
	for _, r := range p.Allow {
		if anyMatches(r.From, from) && anyMatches(r.To, to) {
			return true
		}
	}
	return false
}

// relayAdmission enforces an admission file and picks up its changes.
type relayAdmission struct {
	path   string
	logger *slog.Logger

	mu        sync.Mutex
	policy    *AdmissionPolicy // nil: deny everything
	checkedAt time.Time
	modTime   time.Time
	size      int64
	failing   bool
}

// loadRelayAdmission reads the file once. A coordinator configured with
// admission refuses to start when the file is missing or invalid.
func loadRelayAdmission(path string, logger *slog.Logger, now time.Time) (*relayAdmission, error) {
	a := &relayAdmission{path: path, logger: logger}
	if err := a.reload(now); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *relayAdmission) reload(now time.Time) error {
	a.checkedAt = now
	st, err := os.Stat(a.path)
	if err == nil && st.ModTime().Equal(a.modTime) && st.Size() == a.size && a.policy != nil {
		return nil
	}
	var p *AdmissionPolicy
	if err == nil {
		var data []byte
		data, err = securefile.ReadPrivate(a.path, maxAdmissionFile)
		if err == nil {
			p, err = ParseAdmissionPolicy(data)
		}
	}
	if err != nil {
		a.policy = nil
		if !a.failing && a.logger != nil {
			a.logger.Warn("relay admission file unusable; relaying nothing", "err", err)
		}
		a.failing = true
		return err
	}
	if a.failing && a.logger != nil {
		a.logger.Info("relay admission file usable again", "rules", len(p.Allow))
	}
	a.policy, a.modTime, a.size, a.failing = p, st.ModTime(), st.Size(), false
	return nil
}

// allow is the relayer's admission hook. It never takes the relayer lock.
func (a *relayAdmission) allow(from, to trust.Device, now time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if now.Sub(a.checkedAt) >= admissionRecheck || now.Before(a.checkedAt) {
		_ = a.reload(now) // a failure leaves policy nil: deny
	}
	return a.policy.Allows(from, to)
}
