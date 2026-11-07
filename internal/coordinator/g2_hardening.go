package coordinator

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"

	"github.com/openscale/openscale/internal/securefile"
)

// Coordinator hardening (G2, ADR-0180..ADR-0184). The options live in a
// small file in the state directory so the coordinator's command line and
// the service units stay unchanged: `openscale coordinator harden` writes
// it, the coordinator reads it once at start. A missing file means every
// option is off, exactly as before. A present but invalid file stops the
// coordinator (fail closed: an owner who asked for port hiding must never
// get an open port because of a typo).

// HardeningFile is the hardening options file in the state directory.
const HardeningFile = "coordinator-hardening.json"

const (
	hardeningSchema  = 1
	maxHardeningFile = 8 << 10
	// DefaultMetadataRetention is how long connection metadata stays in
	// memory in the no-metadata mode (#630).
	DefaultMetadataRetention = 10
	// MaxMetadataRetention bounds it (minutes).
	MaxMetadataRetention = 60
)

// Hardening holds the G2 options. The zero value turns everything off.
type Hardening struct {
	Schema int `json:"schema"`
	// SPA hides the UDP port (and the TCP transport) until a valid knock
	// arrives (#614, g2_spa.go).
	SPA bool `json:"spa,omitempty"`
	// NoMetadata keeps connection metadata in memory only, for at most
	// RetentionMinutes, and never writes it to disk or logs (#630).
	NoMetadata       bool `json:"no_metadata,omitempty"`
	RetentionMinutes int  `json:"retention_minutes,omitempty"`
	// RAMOnly refuses to start unless the state directory is a RAM file
	// system (#633, g2_ram.go).
	RAMOnly bool `json:"ram_only,omitempty"`
	// Blind serves endpoints without depending on names, tags or rules
	// when the policy is sealed for the members only (#629, g2_blind.go).
	Blind bool `json:"blind,omitempty"`
	// CloneQuarantine refuses control requests from an identity seen at two
	// places at once until the owner acts (#603, g2_clone.go).
	CloneQuarantine bool `json:"clone_quarantine,omitempty"`
	// NoEmergencyPriority turns off the emergency document priority (#681,
	// g2_emergency.go), which is on by default.
	NoEmergencyPriority bool `json:"no_emergency_priority,omitempty"`
}

// Validate checks the options strictly.
func (h Hardening) Validate() error {
	if h.Schema != hardeningSchema {
		return fmt.Errorf("unsupported hardening schema %d", h.Schema)
	}
	if h.RetentionMinutes < 0 || h.RetentionMinutes > MaxMetadataRetention {
		return fmt.Errorf("retention_minutes must be 0-%d", MaxMetadataRetention)
	}
	if h.RetentionMinutes != 0 && !h.NoMetadata {
		return errors.New("retention_minutes needs no_metadata")
	}
	return nil
}

// Retention returns the metadata retention in minutes.
func (h Hardening) Retention() int {
	if h.RetentionMinutes == 0 {
		return DefaultMetadataRetention
	}
	return h.RetentionMinutes
}

// ParseHardening strictly decodes and validates a hardening file.
func ParseHardening(data []byte) (Hardening, error) {
	if len(data) > maxHardeningFile {
		return Hardening{}, errors.New("hardening file too large")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var h Hardening
	if err := dec.Decode(&h); err != nil {
		return Hardening{}, fmt.Errorf("hardening file: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Hardening{}, errors.New("hardening file: trailing data")
	}
	if err := h.Validate(); err != nil {
		return Hardening{}, fmt.Errorf("hardening file: %w", err)
	}
	return h, nil
}

// EncodeHardening validates and encodes h for the hardening file.
func EncodeHardening(h Hardening) ([]byte, error) {
	h.Schema = hardeningSchema
	if err := h.Validate(); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(h, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// LoadHardening reads the hardening file of a state directory. A missing
// file returns the zero options.
func LoadHardening(dir string) (Hardening, error) {
	data, err := securefile.ReadPrivate(filepath.Join(dir, HardeningFile), maxHardeningFile)
	if errors.Is(err, fs.ErrNotExist) {
		return Hardening{Schema: hardeningSchema}, nil
	}
	if err != nil {
		return Hardening{}, fmt.Errorf("hardening file: %w", err)
	}
	return ParseHardening(data)
}

// SaveHardening writes the hardening file (owner only).
func SaveHardening(dir string, h Hardening) error {
	data, err := EncodeHardening(h)
	if err != nil {
		return err
	}
	return securefile.Replace(filepath.Join(dir, HardeningFile), data)
}
