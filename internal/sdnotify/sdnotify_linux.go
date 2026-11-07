//go:build linux

package sdnotify

import (
	"net"
	"os"
	"time"
)

// Notify sends one or more newline-separated assignments to systemd. It
// reports false without an error when the process does not run under a
// Type=notify unit.
func Notify(state string) (bool, error) {
	socket := os.Getenv("NOTIFY_SOCKET")
	if socket == "" || state == "" {
		return false, nil
	}
	if !validSocket(socket) {
		return false, ErrBadSocket
	}
	// Go maps a leading "@" to the abstract namespace.
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: socket, Net: "unixgram"})
	if err != nil {
		return false, err
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte(state)); err != nil {
		return false, err
	}
	return true, nil
}
