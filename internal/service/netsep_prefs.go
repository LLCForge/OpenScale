package service

import (
	"log/slog"
	"sync"

	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/privsep"
)

// Network and privilege separation preferences (ADR-0230 sealed endpoint
// candidates, ADR-0231 birthday port scan, ADR-0233 parsing helper). They
// live in transportOptions, so "openscale set" changes restart the tunnel
// like the other transport options. Empty values are the defaults.

func (t transportOptions) validateNetSep() error {
	if _, err := node.ParseSealedCandidatesMode(t.SealedCandidates); err != nil {
		return err
	}
	_, err := privsep.ParseMode(t.ParserSandbox)
	return err
}

func sealedModeText(s string) string {
	m, err := node.ParseSealedCandidatesMode(s)
	if err != nil {
		return s
	}
	return m.String()
}

func parserModeText(s string) string {
	m, err := privsep.ParseMode(s)
	if err != nil {
		return s
	}
	return m.String()
}

// applyNetSepPref changes one of these keys; ok is false for other keys.
func applyNetSepPref(t *transportOptions, key, v string) (bool, error) {
	switch key {
	case "sealed-candidates":
		m, err := node.ParseSealedCandidatesMode(v)
		if err != nil {
			return true, err
		}
		t.SealedCandidates = storedMode(m.String())
	case "birthday-scan":
		on, err := parseBoolPref(key, v)
		if err != nil {
			return true, err
		}
		t.BirthdayScanOff = !on
	case "parser-sandbox":
		m, err := privsep.ParseMode(v)
		if err != nil {
			return true, err
		}
		t.ParserSandbox = storedMode(m.String())
	default:
		return false, nil
	}
	return true, nil
}

// storedMode keeps the default out of settings.json.
func storedMode(s string) string {
	if s == "auto" {
		return ""
	}
	return s
}

// withNetSepOptions copies the options into the engine configuration; a
// value the engine would refuse is left at the default with a warning.
func (r *Runtime) withNetSepOptions(t transportOptions, cfg node.Config) node.Config {
	if m, err := node.ParseSealedCandidatesMode(t.SealedCandidates); err != nil {
		r.logger.Warn("saved sealed candidate mode is not usable", "error", err.Error())
	} else {
		cfg.SealedCandidates = m
	}
	cfg.DisableBirthdayScan = t.BirthdayScanOff
	mode, err := privsep.ParseMode(t.ParserSandbox)
	if err != nil {
		r.logger.Warn("saved parser sandbox mode is not usable", "error", err.Error())
		mode = privsep.ModeAuto
	}
	if g := sharedParserGate(mode, r.logger); g != nil {
		cfg.DocumentSanitizer = g.SanitizeEnvelope
	} else {
		cfg.DocumentSanitizer = nil
	}
	return cfg
}

// The service process keeps one parsing helper for every tunnel start; the
// helper dies with the service (Windows job object, Linux parent-death
// signal).
var parserGates struct {
	mu   sync.Mutex
	gate *privsep.Gate
	mode privsep.Mode
}

// sharedParserGate returns the process-wide gate for mode (nil when off)
// and makes it the default for release manifests (updater).
func sharedParserGate(mode privsep.Mode, logger *slog.Logger) *privsep.Gate {
	parserGates.mu.Lock()
	defer parserGates.mu.Unlock()
	if parserGates.gate != nil && parserGates.mode == mode {
		return parserGates.gate
	}
	if parserGates.gate != nil {
		_ = parserGates.gate.Close()
		parserGates.gate = nil
	}
	if mode == privsep.ModeOff {
		privsep.SetDefault(nil)
		return nil
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	parserGates.gate = privsep.NewGate(privsep.GateConfig{Mode: mode, Logger: logger.With("role", "privsep")})
	parserGates.mode = mode
	privsep.SetDefault(parserGates.gate)
	return parserGates.gate
}
