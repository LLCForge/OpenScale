package privacy

import (
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
)

// Screen sharing detection (#689, ADR-0206). While a meeting or recording
// program that can show this screen to others is running, the panel blurs
// secrets (keys, invite codes, recovery words, addresses) on its own.
//
// Detection uses only the process list: OpenScale never captures the
// screen and never inspects other programs. A share started from a
// browser tab (Google Meet, Teams or Zoom on the web) cannot be seen this
// way; only desktop programs are recognised, and the panel says so.
//
// Levels: "active" means a process that exists only while the screen is
// being shared or recorded (Zoom's share host, OBS); "possible" means a
// meeting or remote support program is open and could share at any time.

// Screen share levels.
const (
	ShareNone     = "none"
	SharePossible = "possible"
	ShareActive   = "active"
)

const maxProcesses = 8192

// ErrScreenShareUnsupported is returned where processes cannot be listed.
var ErrScreenShareUnsupported = errors.New("bu sistemde süreç listesi okunamıyor")

// shareApp maps a lowercased executable name (without .exe) to a display
// name and level.
type shareApp struct {
	display string
	level   string
}

var shareApps = map[string]shareApp{
	// Zoom: the share host only runs while sharing.
	"cpthost": {"Zoom (ekran paylaşımı)", ShareActive},
	"zoom":    {"Zoom", SharePossible},
	// Microsoft Teams (new and classic).
	"ms-teams":        {"Microsoft Teams", SharePossible},
	"teams":           {"Microsoft Teams", SharePossible},
	"msteams":         {"Microsoft Teams", SharePossible},
	"microsoft teams": {"Microsoft Teams", SharePossible},
	// Webex.
	"webex":           {"Webex", SharePossible},
	"webexmta":        {"Webex", SharePossible},
	"ciscowebexstart": {"Webex", SharePossible},
	"atmgr":           {"Webex", SharePossible},
	// Recording and streaming.
	"obs":   {"OBS Studio", ShareActive},
	"obs32": {"OBS Studio", ShareActive},
	"obs64": {"OBS Studio", ShareActive},
	// Other meeting and remote viewing programs.
	"discord":    {"Discord", SharePossible},
	"slack":      {"Slack", SharePossible},
	"skype":      {"Skype", SharePossible},
	"anydesk":    {"AnyDesk", SharePossible},
	"teamviewer": {"TeamViewer", SharePossible},
	"rustdesk":   {"RustDesk", SharePossible},
}

// ScreenShareStatus is what the panel needs to decide on blurring.
type ScreenShareStatus struct {
	Level string   `json:"level"`
	Apps  []string `json:"apps"`
	// Blur is the recommended state: true for active and possible.
	Blur bool `json:"blur"`
	// BrowserNote is always set: shares from a browser tab are not seen.
	BrowserNote string    `json:"browser_note"`
	Supported   bool      `json:"supported"`
	CheckedAt   time.Time `json:"checked_at"`
}

const browserNote = "Tarayıcı sekmesinden yapılan paylaşımlar (Google Meet, web üzerinden Teams veya Zoom) algılanamaz; yalnızca masaüstü uygulamaları tanınır."

// ClassifyProcesses turns process names into a status. It is pure so it
// can be tested on any system.
func ClassifyProcesses(names []string) ScreenShareStatus {
	st := ScreenShareStatus{Level: ShareNone, Apps: []string{}, BrowserNote: browserNote, Supported: true}
	seen := map[string]bool{}
	for _, n := range names {
		k := strings.ToLower(strings.TrimSpace(n))
		k = strings.TrimSuffix(k, ".exe")
		// The macOS Zoom process is named after its web domain; match it
		// by prefix so no host name is embedded in the binary.
		if strings.HasPrefix(k, "zoom.") {
			k = "zoom"
		}
		app, ok := shareApps[k]
		if !ok {
			continue
		}
		if !seen[app.display] {
			seen[app.display] = true
			st.Apps = append(st.Apps, app.display)
		}
		if app.level == ShareActive || st.Level == ShareNone {
			st.Level = app.level
		}
	}
	sort.Strings(st.Apps)
	st.Blur = st.Level != ShareNone
	return st
}

var shareCache struct {
	mu sync.Mutex
	st ScreenShareStatus
}

// DetectScreenShare lists processes now, at most every two seconds; the
// panel polls it.
func DetectScreenShare(now time.Time) ScreenShareStatus {
	shareCache.mu.Lock()
	defer shareCache.mu.Unlock()
	if !shareCache.st.CheckedAt.IsZero() && now.Sub(shareCache.st.CheckedAt) < 2*time.Second && now.After(shareCache.st.CheckedAt) {
		return shareCache.st
	}
	names, err := processNames()
	var st ScreenShareStatus
	if err != nil {
		st = ScreenShareStatus{Level: ShareNone, Apps: []string{}, BrowserNote: browserNote}
	} else {
		st = ClassifyProcesses(names)
	}
	st.CheckedAt = now
	shareCache.st = st
	return st
}
