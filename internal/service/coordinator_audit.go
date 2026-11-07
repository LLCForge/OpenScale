package service

import (
	"github.com/openscale/openscale/internal/audit"
	"github.com/openscale/openscale/internal/panel"
)

// coordinatorRejection writes a registration the local coordinator refused
// to this computer's audit log and the event stream (#187,
// coordinator/rejaudit.go). The coordinator already masked and rate
// limited it; a critical one (a refused root transition) is announced.
func (r *Runtime) coordinatorRejection(kind, severity, message string) {
	r.observer().Security(kind, severity, panel.CategorySecurity, "", message, severity == audit.SeverityCritical)
}
