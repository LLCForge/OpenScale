package rdesk

import "strings"

// Separate permissions for the parts of a session (#670, ADR-0201).
//
// A Decision may name the channels a session gets. Without them (the
// zero value) the older rules apply: a view session only watches, a
// control session also sends input, may turn clipboard sharing on and may
// blank the screen, and files need Decision.Files. With
// Config.StrictChannels the zero value means only the screen and, for a
// control session, input: clipboard, files, audio and the privacy curtain
// need an explicit channel. Channels are asked again on every request
// that uses them, so a rule change applies at once.

// Channels is a set of session channels.
type Channels uint8

// Session channels.
const (
	// ChanView sends the screen; every session has it.
	ChanView Channels = 1 << 0
	// ChanInput injects keyboard and mouse (control sessions).
	ChanInput Channels = 1 << 1
	// ChanClipboard shares the clipboard in both directions.
	ChanClipboard Channels = 1 << 2
	// ChanFiles browses and fetches files from Config.FileRoots.
	ChanFiles Channels = 1 << 3
	// ChanAudio forwards sound. The protocol carries no audio yet; the
	// bit is reserved so rules can already say it.
	ChanAudio Channels = 1 << 4
	// ChanCurtain blanks the physical screen and locks local input
	// (#666).
	ChanCurtain Channels = 1 << 5

	allChannels = ChanView | ChanInput | ChanClipboard | ChanFiles | ChanAudio | ChanCurtain
)

// Has reports whether c contains every channel in want.
func (c Channels) Has(want Channels) bool { return c&want == want }

// String lists the channel names the trust rules use.
func (c Channels) String() string {
	var parts []string
	for _, n := range channelNames {
		if c.Has(n.c) {
			parts = append(parts, n.name)
		}
	}
	return strings.Join(parts, ",")
}

var channelNames = []struct {
	c    Channels
	name string
}{
	{ChanView, "view"}, {ChanInput, "input"}, {ChanClipboard, "clipboard"},
	{ChanFiles, "files"}, {ChanAudio, "audio"}, {ChanCurtain, "curtain"},
}

// ParseChannels reads a comma separated list of channel names; unknown
// names are an error so a typo never grants or hides a permission.
func ParseChannels(s string) (Channels, bool) {
	var c Channels
	for part := range strings.SplitSeq(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		found := false
		for _, n := range channelNames {
			if n.name == part {
				c |= n.c
				found = true
			}
		}
		if !found {
			return 0, false
		}
	}
	return c, true
}

// effectiveChannels returns the channels d grants for a session of mode.
func (s *Server) effectiveChannels(d Decision, mode Mode) Channels {
	c := d.Channels
	if c == 0 {
		c = ChanView
		if mode == ModeControl {
			c |= ChanInput
			if !s.cfg.StrictChannels {
				c |= ChanClipboard | ChanCurtain
			}
		}
		if d.Files {
			c |= ChanFiles
		}
	} else {
		c |= ChanView
		if d.Files {
			// The older files flag still works next to explicit channels.
			c |= ChanFiles
		}
	}
	if mode != ModeControl {
		// Watching never injects, shares the clipboard or touches files.
		c &= ChanView | ChanAudio
	}
	return c & allChannels
}

// decisionPermits reports whether d allows a session of mode at all: a
// control session needs the input channel.
func (s *Server) decisionPermits(d Decision, mode Mode) bool {
	if !d.Allowed {
		return false
	}
	if mode == ModeControl && !s.effectiveChannels(d, mode).Has(ChanInput) {
		return false
	}
	return true
}

// sessionHas asks the rules again whether the running session has want.
func (sess *session) sessionHas(want Channels) bool {
	d := sess.srv.cfg.Authorize(sess.remote, sess.mode)
	return sess.srv.decisionPermits(d, sess.mode) && sess.srv.effectiveChannels(d, sess.mode).Has(want)
}
