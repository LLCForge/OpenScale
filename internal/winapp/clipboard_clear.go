package winapp

import "time"

// SecretClipboardTTL is how long a copied secret (an invite code, a
// one-time token) stays on the clipboard (#47).
const SecretClipboardTTL = 60 * time.Second

// clearDecision reports whether the clipboard should be emptied: only
// when nothing was copied since the secret, so text the user copied later
// is never lost.
func clearDecision(seqAfterSet, seqNow uint32) bool {
	return seqAfterSet != 0 && seqAfterSet == seqNow
}
