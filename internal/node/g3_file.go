package node

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/openscale/openscale/internal/filter"
	"github.com/openscale/openscale/internal/obfs"
	"github.com/openscale/openscale/internal/securefile"
)

// OpsecFile is the device's local opsec settings file in its state
// directory (ADR-0186..0191). "openscale opsec ..." writes it; the engine
// reads it at start, so the desktop service and "openscale up" both use
// it. It is local and unsigned: nothing in it can widen what the document
// allows. Options set in Config.G3 by the caller win over the file.
const OpsecFileName = "opsec.json"

const maxOpsecFile = 64 << 10

// OpsecSettings is the file's content.
type OpsecSettings struct {
	Obfs struct {
		Mode     string          `json:"mode,omitempty"`
		Buckets  []int           `json:"buckets,omitempty"`
		JitterMS int             `json:"jitter_ms,omitempty"`
		TLS      *obfs.ClientTLS `json:"tls,omitempty"`
	} `json:"obfs"`
	ExitChainEntry        string         `json:"exit_chain_entry,omitempty"`
	ExitCanary            []CanaryTarget `json:"exit_canary,omitempty"`
	ExitCanaryMinutes     int            `json:"exit_canary_minutes,omitempty"`
	ExitDNSPins           []string       `json:"exit_dns_pins,omitempty"`
	ExitDNSRequirePins    bool           `json:"exit_dns_require_pins,omitempty"`
	DecoyPorts            []uint16       `json:"decoy_ports,omitempty"`
	QuarantineOnScan      bool           `json:"quarantine_on_scan,omitempty"`
	QuarantineMinutes     int            `json:"quarantine_minutes,omitempty"`
	CloneWatchOff         bool           `json:"clone_watch_off,omitempty"`
	DHCPRandomName        bool           `json:"dhcp_random_name,omitempty"`
	DHCPConnection        string         `json:"dhcp_connection,omitempty"`
	BlockWebRTCOutsideVPN bool           `json:"block_webrtc,omitempty"`
}

// LoadOpsecSettings reads OpsecFileName from dir; a missing file is the
// zero value. Unknown keys are refused.
func LoadOpsecSettings(dir string) (OpsecSettings, error) {
	var s OpsecSettings
	if dir == "" {
		return s, nil
	}
	data, err := securefile.ReadLimited(filepath.Join(dir, OpsecFileName), maxOpsecFile)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return OpsecSettings{}, fmt.Errorf("%s bozuk: %w", OpsecFileName, err)
	}
	var g G3Config
	if err := s.Apply(&g); err != nil {
		return OpsecSettings{}, fmt.Errorf("%s: %w", OpsecFileName, err)
	}
	return s, nil
}

// SaveOpsecSettings validates s and writes it to dir.
func SaveOpsecSettings(dir string, s OpsecSettings) error {
	var g G3Config
	if err := s.Apply(&g); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return securefile.Replace(filepath.Join(dir, OpsecFileName), append(data, '\n'))
}

// Apply fills the zero parts of g from s and checks the values.
func (s OpsecSettings) Apply(g *G3Config) error {
	mode, err := obfs.ParseMode(s.Obfs.Mode)
	if err != nil {
		return err
	}
	if g.Obfs.Mode == obfs.ModeOff && mode != obfs.ModeOff {
		g.Obfs.Mode = mode
		g.Obfs.Padding = obfs.Padding{Buckets: s.Obfs.Buckets}
		if err := g.Obfs.Padding.Validate(); err != nil {
			return err
		}
		g.Obfs.Jitter = obfs.Jitter{Max: time.Duration(s.Obfs.JitterMS) * time.Millisecond}
		if err := g.Obfs.Jitter.Validate(); err != nil {
			return err
		}
	} else if mode == obfs.ModeOff && (s.Obfs.JitterMS != 0 || len(s.Obfs.Buckets) > 0) {
		return errors.New("dolgu ve zamanlama gürültüsü yalnızca gizleme açıkken ayarlanabilir")
	}
	if g.Obfs.TLS == nil && s.Obfs.TLS != nil {
		if _, err := s.Obfs.TLS.Config(nil); err != nil {
			return err
		}
		t := *s.Obfs.TLS
		g.Obfs.TLS = &t
	}
	if g.ExitChain.Entry == "" {
		g.ExitChain.Entry = s.ExitChainEntry
	}
	if len(g.ExitCanary.Targets) == 0 {
		g.ExitCanary = ExitCanaryConfig{Targets: s.ExitCanary, Interval: time.Duration(s.ExitCanaryMinutes) * time.Minute}
		if err := g.ExitCanary.validate(); err != nil {
			return err
		}
	}
	if len(g.ExitDNSPins) == 0 && !g.ExitDNSRequirePins {
		if _, err := obfs.ParsePins(s.ExitDNSPins); err != nil {
			return err
		}
		g.ExitDNSPins, g.ExitDNSRequirePins = s.ExitDNSPins, s.ExitDNSRequirePins
	}
	if len(g.Decoys.DecoyPorts) == 0 && !g.Decoys.QuarantineOnScan {
		g.Decoys = filter.G3Config{DecoyPorts: s.DecoyPorts, QuarantineOnScan: s.QuarantineOnScan,
			QuarantineFor: time.Duration(s.QuarantineMinutes) * time.Minute}
		if err := g.Decoys.Validate(); err != nil {
			return err
		}
	}
	if s.CloneWatchOff {
		g.CloneWatch.Disable = true
	}
	return nil
}

// loadG3File merges the state directory's settings file into the config.
func (e *Engine) loadG3File() error {
	if e.cfg.Store == nil {
		return nil
	}
	s, err := LoadOpsecSettings(e.cfg.Store.Dir())
	if err != nil {
		return err
	}
	return s.Apply(&e.cfg.G3)
}
