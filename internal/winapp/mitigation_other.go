//go:build !windows

package winapp

// applyMitigations: the Windows policies have no counterpart here; the
// Unix hardening (no core dumps, no ptrace) is in internal/privacy.
func applyMitigations(mitigationSet) []MitigationResult { return nil }
