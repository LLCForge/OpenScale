package cli

import "github.com/openscale/openscale/internal/panel"

// Observability implements panel.ObservabilitySource for a foreground
// tunnel ("openscale up", ADR-0105). The audit log and the switches live in
// the state directory, readable only by the user who started the tunnel.
func (u *upDiag) Observability() panel.Observability {
	if u.obs == nil {
		return nil
	}
	return u.obs
}
