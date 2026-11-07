//go:build !linux

package dbuswire

// Read reads bytes; descriptor passing exists only on Linux here.
func (t *fdConn) Read(p []byte) (int, error) { return t.Conn.Read(p) }

const (
	abstractSupported = false
	unixFDSupported   = false
)
