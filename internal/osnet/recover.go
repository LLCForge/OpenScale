package osnet

import "strings"

// Crash recovery (ADR-0051, F-007, #163). The service and "openscale up"
// write a change journal before they touch routes or DNS; after a crash
// the next start calls these functions for what the journal still lists.
// They only remove what OpenScale itself names (fixed rule comments,
// tables and route prefixes), so running them when nothing is left is
// harmless. The persistent kill switch is deliberately not part of this:
// it must survive a crash (ADR-0023).

// validRecoverInterface reports whether an interface name from the journal
// is safe to pass to a system tool.
func validRecoverInterface(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, r := range name {
		if r < 0x20 {
			return false
		}
	}
	return !strings.ContainsAny(name, " \"'`;&|$\\")
}
