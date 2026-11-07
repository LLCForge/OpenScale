//go:build !linux

package coordinator

// SandboxResult says what the sandbox did; Landlock exists only on Linux
// (#147, ADR-0111).
type SandboxResult struct {
	Applied bool
	ABI     int
	Reason  string
}

// RestrictFiles is a no-op outside Linux.
func RestrictFiles(string) SandboxResult {
	return SandboxResult{Reason: "Landlock yalnızca Linux'ta var"}
}

func (s *Server) applySandbox() {
	s.logger.Info("Landlock sandbox skipped", "reason", RestrictFiles(s.cfg.Store.Dir()).Reason)
}
