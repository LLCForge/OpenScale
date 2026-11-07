package cli

import (
	"log/slog"

	"github.com/openscale/openscale/internal/audit"
	"github.com/openscale/openscale/internal/coordinator"
)

// coordinatorRejectionSink writes the registrations a stand-alone
// coordinator refused to the hash-chained audit log in its state directory
// (#187), audit.jsonl next to the coordinator key. A log that cannot
// be opened does not stop the coordinator: the refusals are then only
// counted in its log.
func coordinatorRejectionSink(env *Env, stateDir string, logger *slog.Logger) coordinator.RejectionSink {
	l, err := audit.Open(stateDir, env.Now)
	if err != nil {
		logger.Warn("audit log unavailable; refused registrations are not recorded", "error", err.Error())
		return nil
	}
	return func(kind, severity, message string) {
		if err := l.Append(kind, severity, message); err != nil {
			logger.Warn("audit record not written", "kind", kind, "error", err.Error())
		}
	}
}
