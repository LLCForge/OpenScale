package rdesk

import (
	"errors"
	"fmt"
	"sync/atomic"
	"time"
)

// Mandatory "remotely connected" frame (#671) and the instant disconnect
// shortcut (#672), ADR-0200.
//
// When Config.NewFrame is set, every session opens a frame on the
// device's physical screen before the first pixel leaves: a red border
// around the desktop with "Uzaktan bağlı: <device>". It cannot be closed
// from the session (it takes no input and ignores close requests) and it
// is kept on top while the session lasts. With Config.RequireFrame a
// session whose frame cannot be shown does not start, so unattended
// access is never silent.
//
// KillAll ends every session at once and refuses new ones for a while;
// the service binds it to a global shortcut (WatchKillHotkey,
// Ctrl+Alt+Shift+K by default).

// FrameInfo describes the session a frame announces.
type FrameInfo struct {
	Peer      string
	Mode      Mode
	OSUser    string
	Recording bool
}

// Text is the frame's label.
func (fi FrameInfo) Text() string {
	what := "izleniyor"
	if fi.Mode == ModeControl {
		what = "denetleniyor"
	}
	s := fmt.Sprintf("Uzaktan bağlı: %s (%s)", fi.Peer, what)
	if fi.Recording {
		s += " - kaydediliyor"
	}
	return s + " - kesmek için Ctrl+Alt+Shift+K"
}

// SessionFrame is the on-screen frame of one session.
type SessionFrame interface {
	// Close removes the frame; it must restore the screen.
	Close() error
}

// ErrKilled is the welcome reason while the shortcut's block lasts.
var ErrKilled = errors.New("rdesk: yerel kullanıcı uzak oturumları kesti")

// killState holds the block set by KillAll.
type killState struct {
	until atomic.Int64 // unix nanoseconds; 0 means no block
}

// KillAll ends every running session at once and refuses new ones for
// block (#672). It returns the number of sessions ended. The block is
// kept in memory: restarting the service lifts it.
func (s *Server) KillAll(block time.Duration, reason string) int {
	if block > 0 {
		s.kill.until.Store(time.Now().Add(block).UnixNano())
	}
	if reason == "" {
		reason = "yerel kullanıcı bağlantıyı kesti"
	}
	s.mu.Lock()
	list := make([]*session, 0, len(s.sessions))
	for sess := range s.sessions {
		list = append(list, sess)
	}
	s.mu.Unlock()
	for _, sess := range list {
		sess.end(byeRevoked, reason)
	}
	s.log.Warn("uzak masaüstü oturumları yerel kısayolla kesildi", "sessions", len(list), "block", block.String())
	return len(list)
}

// KillBlockedUntil reports the end of the block set by KillAll.
func (s *Server) KillBlockedUntil() (time.Time, bool) {
	u := s.kill.until.Load()
	if u == 0 || time.Now().UnixNano() >= u {
		return time.Time{}, false
	}
	return time.Unix(0, u), true
}

// LiftKillBlock removes the block set by KillAll (the owner's choice on
// the device).
func (s *Server) LiftKillBlock() { s.kill.until.Store(0) }

// openFrame shows the session's frame; it returns false when the
// session must not start.
func (sess *session) openFrame() (SessionFrame, bool) {
	cfg := &sess.srv.cfg
	if cfg.NewFrame == nil {
		return nil, !cfg.RequireFrame
	}
	f, err := cfg.NewFrame(FrameInfo{Peer: sess.peer, Mode: sess.mode, OSUser: sess.osUser, Recording: cfg.Recording != nil})
	if err != nil {
		sess.srv.log.Warn("uzaktan bağlı çerçevesi gösterilemedi", "peer", sess.peer, "err", err)
		return nil, !cfg.RequireFrame
	}
	return f, true
}

// Default kill shortcut: Ctrl+Alt+Shift+K.
const (
	HotkeyModControl = 1 << 0
	HotkeyModAlt     = 1 << 1
	HotkeyModShift   = 1 << 2
	HotkeyModSuper   = 1 << 3
)

// Hotkey is a global key combination: modifier bits and an ASCII letter
// or digit.
type Hotkey struct {
	Mods uint8
	Key  byte
}

// DefaultKillHotkey is Ctrl+Alt+Shift+K.
var DefaultKillHotkey = Hotkey{Mods: HotkeyModControl | HotkeyModAlt | HotkeyModShift, Key: 'K'}

// Valid reports whether h has at least two modifiers and a letter or
// digit, so it does not swallow ordinary typing.
func (h Hotkey) Valid() bool {
	n := 0
	for m := h.Mods; m != 0; m &= m - 1 {
		n++
	}
	return n >= 2 && h.Mods&^(HotkeyModControl|HotkeyModAlt|HotkeyModShift|HotkeyModSuper) == 0 &&
		((h.Key >= 'A' && h.Key <= 'Z') || (h.Key >= '0' && h.Key <= '9'))
}

// String is "Ctrl+Alt+Shift+K".
func (h Hotkey) String() string {
	s := ""
	for _, m := range []struct {
		bit  uint8
		name string
	}{{HotkeyModControl, "Ctrl"}, {HotkeyModAlt, "Alt"}, {HotkeyModShift, "Shift"}, {HotkeyModSuper, "Win"}} {
		if h.Mods&m.bit != 0 {
			s += m.name + "+"
		}
	}
	return s + string(rune(h.Key))
}

// ParseHotkey reads "Ctrl+Alt+Shift+K" (case-insensitive).
func ParseHotkey(s string) (Hotkey, bool) {
	var h Hotkey
	parts := splitPlus(s)
	if len(parts) < 2 {
		return Hotkey{}, false
	}
	for i, p := range parts {
		up := toUpperASCII(p)
		if i == len(parts)-1 {
			if len(up) != 1 {
				return Hotkey{}, false
			}
			h.Key = up[0]
			continue
		}
		switch up {
		case "CTRL", "CONTROL":
			h.Mods |= HotkeyModControl
		case "ALT", "OPTION":
			h.Mods |= HotkeyModAlt
		case "SHIFT":
			h.Mods |= HotkeyModShift
		case "WIN", "SUPER", "CMD", "COMMAND":
			h.Mods |= HotkeyModSuper
		default:
			return Hotkey{}, false
		}
	}
	return h, h.Valid()
}

func splitPlus(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '+' {
			if part := trimSpaceASCII(s[start:i]); part != "" {
				out = append(out, part)
			} else {
				return nil
			}
			start = i + 1
		}
	}
	return out
}

func trimSpaceASCII(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

func toUpperASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 32
		}
	}
	return string(b)
}
