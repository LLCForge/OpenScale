//go:build !windows

package rdesk

// NewSystemLocalLock reports ErrUnsupported: on X11 blanking would need an
// override-redirect window that the GetImage capture would also see (no
// capture exclusion), and grabbing the keyboard would also block XTEST
// input on some servers. Screen blanking and input lock are Windows only
// (ADR-0103).
func NewSystemLocalLock() (LocalLock, error) { return nil, ErrUnsupported }
