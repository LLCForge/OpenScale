package rdesk

import (
	"errors"
	"strings"
	"sync"
)

// Second viewer (#853) and the shared frame text.
//
// A device runs at most Config.MaxSessions sessions (default 2) and at
// most one of them controls (Server.register). A second administrator
// device that asks to control while another one does is told so with
// reasonControlTaken, which the client turns into ErrControlTaken: it can
// join the same screen as a viewer instead. Every session has its own key
// exchange, so each viewer gets its own keys and its own verification
// code; input is only read from the control session (view sessions never
// open an injector). The frame on the device's screen names every
// viewer: each session's frame shows the text of all running sessions, so
// the frames, which lie on top of each other, read as one.

// reasonControlTaken is the busy reason when another session controls.
const reasonControlTaken = "control-taken"

// ErrControlTaken means another device controls the screen; a view
// session is still possible.
var ErrControlTaken = errors.New("rdesk: başka bir yönetici cihaz denetimde; yalnızca izleyici olarak katılabilirsiniz")

// busyReason explains a refused registration.
func (s *Server) busyReason(sess *session) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess.mode == ModeControl && s.control > 0 && len(s.sessions) < s.cfg.MaxSessions {
		return reasonControlTaken
	}
	return ""
}

// FrameTextSetter is implemented by frames whose label can change while
// they are shown.
type FrameTextSetter interface {
	SetText(text string)
}

type frameEntry struct {
	sess  *session
	info  FrameInfo
	frame SessionFrame
}

// frames are the shown frames of one server, in start order.
type frameSet struct {
	mu   sync.Mutex
	list []frameEntry
}

var serverFrames sync.Map // *Server -> *frameSet

func (s *Server) frameSet() *frameSet {
	v, _ := serverFrames.LoadOrStore(s, &frameSet{})
	return v.(*frameSet)
}

// FramesText is the label for every session in fis; one session keeps
// FrameInfo.Text.
func FramesText(fis []FrameInfo) string {
	switch len(fis) {
	case 0:
		return ""
	case 1:
		return fis[0].Text()
	}
	tr := uiTurkish()
	parts := make([]string, 0, len(fis))
	rec := false
	for _, fi := range fis {
		what := "izliyor"
		if !tr {
			what = "viewing"
		}
		if fi.Mode == ModeControl {
			what = "denetliyor"
			if !tr {
				what = "controlling"
			}
		}
		parts = append(parts, fi.Peer+" ("+what+")")
		rec = rec || fi.Recording
	}
	if tr {
		s := "Uzaktan bağlı " + itoaSmall(len(fis)) + " cihaz: " + strings.Join(parts, ", ")
		if rec {
			s += " - kaydediliyor"
		}
		return s + " - kesmek için Ctrl+Alt+Shift+K"
	}
	s := "Remotely connected, " + itoaSmall(len(fis)) + " devices: " + strings.Join(parts, ", ")
	if rec {
		s += " - recording"
	}
	return s + " - press Ctrl+Alt+Shift+K to disconnect"
}

func itoaSmall(n int) string {
	if n < 0 || n > 99 {
		return "?"
	}
	if n < 10 {
		return string(rune('0' + n))
	}
	return string([]rune{rune('0' + n/10), rune('0' + n%10)})
}

// addFrame records a shown frame and relabels every frame.
func (s *Server) addFrame(sess *session, f SessionFrame) {
	if f == nil {
		return
	}
	fs := s.frameSet()
	fs.mu.Lock()
	fs.list = append(fs.list, frameEntry{sess: sess, info: FrameInfo{Peer: sess.peer, Mode: sess.mode, OSUser: sess.osUser, Recording: s.cfg.Recording != nil}, frame: f})
	fs.relabelLocked()
	fs.mu.Unlock()
}

// removeFrame forgets the session's frame and relabels the others.
func (s *Server) removeFrame(sess *session) {
	fs := s.frameSet()
	fs.mu.Lock()
	for i, e := range fs.list {
		if e.sess == sess {
			fs.list = append(fs.list[:i], fs.list[i+1:]...)
			break
		}
	}
	fs.relabelLocked()
	empty := len(fs.list) == 0
	fs.mu.Unlock()
	if empty {
		serverFrames.CompareAndDelete(s, fs)
	}
}

func (fs *frameSet) relabelLocked() {
	infos := make([]FrameInfo, 0, len(fs.list))
	for _, e := range fs.list {
		infos = append(infos, e.info)
	}
	text := FramesText(infos)
	for _, e := range fs.list {
		if ts, ok := e.frame.(FrameTextSetter); ok {
			ts.SetText(text)
		}
	}
}

// Viewers lists the peers of the running sessions with their modes, in no
// particular order (for the indicator and the tests).
func (s *Server) Viewers() []FrameInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]FrameInfo, 0, len(s.sessions))
	for sess := range s.sessions {
		out = append(out, FrameInfo{Peer: sess.peer, Mode: sess.mode, OSUser: sess.osUser})
	}
	return out
}
