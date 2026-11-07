// Package sdnotify tells systemd about the state of a Type=notify service
// (F-149, #308). It speaks the sd_notify datagram protocol directly over
// the socket in NOTIFY_SOCKET, so no libsystemd and no new dependency is
// needed (ADR-0002). Outside systemd, and on other systems, every call is
// a no-op that reports false.
package sdnotify

import (
	"errors"
	"strings"
)

// Well-known states.
const (
	stateReady    = "READY=1"
	stateStopping = "STOPPING=1"
	// maxStatus keeps STATUS short; systemctl shows a single line.
	maxStatus = 200
)

// ErrBadSocket is returned for a NOTIFY_SOCKET that is neither an
// absolute path nor an abstract socket name.
var ErrBadSocket = errors.New("NOTIFY_SOCKET geçersiz")

// Ready reports that the service finished starting; status is optional.
func Ready(status string) (bool, error) {
	return Notify(join(stateReady, statusLine(status)))
}

// Stopping reports that the service is shutting down.
func Stopping() (bool, error) { return Notify(stateStopping) }

// Status updates the one-line status systemctl shows.
func Status(status string) (bool, error) {
	line := statusLine(status)
	if line == "" {
		return false, nil
	}
	return Notify(line)
}

// statusLine formats STATUS=..., keeping it on one line.
func statusLine(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r < 0x20 {
			return ' '
		}
		return r
	}, strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	if r := []rune(s); len(r) > maxStatus {
		s = string(r[:maxStatus])
	}
	return "STATUS=" + s
}

func join(lines ...string) string {
	var out []string
	for _, l := range lines {
		if l != "" {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

// validSocket accepts what systemd puts in NOTIFY_SOCKET: an absolute
// path or "@" followed by an abstract socket name.
func validSocket(s string) bool {
	if len(s) < 2 || len(s) > 108 {
		return false
	}
	return s[0] == '/' || s[0] == '@'
}
