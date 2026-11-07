//go:build windows

package winapp

import (
	"time"
)

var procGetClipboardSequenceNumber = modUser32.NewProc("GetClipboardSequenceNumber")

// clipboardSequence returns the clipboard sequence number of the current
// window station; it changes on every clipboard write.
func clipboardSequence() uint32 {
	r, _, _ := procGetClipboardSequenceNumber.Call()
	return uint32(r)
}

// SetClipboardSecret puts s on the clipboard and empties the clipboard
// after ttl if it still holds s (#47). The check uses the clipboard
// sequence number, so the secret is never read back and anything copied
// in the meantime is kept. The returned function cancels the timer.
func SetClipboardSecret(s string, ttl time.Duration) (cancel func(), err error) {
	if err := SetClipboardText(s); err != nil {
		return func() {}, err
	}
	seq := clipboardSequence()
	if ttl <= 0 {
		ttl = SecretClipboardTTL
	}
	t := time.AfterFunc(ttl, func() {
		if !clearDecision(seq, clipboardSequence()) {
			return
		}
		if r, _, _ := procOpenClipboard.Call(0); r == 0 {
			return
		}
		defer procCloseClipboard.Call()
		// Re-checked with the clipboard open: no other writer can slip in.
		if clearDecision(seq, clipboardSequence()) {
			procEmptyClipboard.Call()
		}
	})
	return func() { t.Stop() }, nil
}
