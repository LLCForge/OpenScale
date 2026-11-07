package cli

import (
	"log/slog"

	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/privsep"
)

// Network and privilege separation options of "openscale up": sealed
// endpoint candidates (ADR-0230), the birthday port scan (ADR-0231) and the
// parsing helper (ADR-0233).

type upNetSepOptions struct {
	sealed   node.SealedCandidatesMode
	birthday bool
	parser   privsep.Mode
	// gate is started by startParserGate; nil until then.
	gate *privsep.Gate
}

func resolveNetSep(f upTransportFlags) (upNetSepOptions, error) {
	var o upNetSepOptions
	var err error
	if o.sealed, err = node.ParseSealedCandidatesMode(*f.sealed); err != nil {
		return o, usageError("--sealed-candidates: %v", err)
	}
	if o.parser, err = privsep.ParseMode(*f.parser); err != nil {
		return o, usageError("--parser-sandbox: %v", err)
	}
	o.birthday = *f.birthday
	return o, nil
}

// startParserGate prepares the parsing helper; it starts on the first
// document. The caller closes it when the tunnel stops.
func (o *upTransportOptions) startParserGate(logger *slog.Logger) *privsep.Gate {
	o.netsep.gate = privsep.NewGate(privsep.GateConfig{Mode: o.netsep.parser, Logger: logger.With("role", "privsep")})
	privsep.SetDefault(o.netsep.gate)
	return o.netsep.gate
}

func (o upNetSepOptions) apply(cfg node.Config) node.Config {
	cfg.SealedCandidates = o.sealed
	cfg.DisableBirthdayScan = !o.birthday
	if o.gate != nil && o.parser != privsep.ModeOff {
		cfg.DocumentSanitizer = o.gate.SanitizeEnvelope
	}
	return cfg
}
