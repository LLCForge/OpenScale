package panel

import (
	"log/slog"
	"net"
	"net/http"
)

// callerAllowed applies a peer check (ADR-0050) to a request that already
// carried a valid token. A nil check allows; a request without a known
// local address is refused when a check is set.
func callerAllowed(check func(remote, local string) error, r *http.Request, logger *slog.Logger) bool {
	if check == nil {
		return true
	}
	local, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if !ok || local == nil {
		logger.Warn("local API caller refused", "reason", "no local address")
		return false
	}
	if err := check(r.RemoteAddr, local.String()); err != nil {
		logger.Warn("local API caller refused", "reason", err.Error())
		return false
	}
	return true
}
