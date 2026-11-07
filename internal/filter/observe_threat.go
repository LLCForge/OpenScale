package filter

// threatBlockedPeerLocked reports, without changing anything, whether the
// peer is blocked after a scan; used to explain a refusal. Called with
// f.mu held.
func (f *Filter) threatBlockedPeerLocked(peer string) bool {
	t := f.threats
	if t == nil || peer == "" {
		return false
	}
	until, ok := t.blocked[peer]
	return ok && f.now().Before(until)
}
