// Package support is the target side of the remote support toolbox (#852,
// ADR-0232): read-only views of the running processes, services, recent
// system events, disk usage and startup programs, and ending a process as a
// separate permission.
//
// Nothing here decides who may ask. The service passes an Authorize
// function that consults the root-signed document (trust.AllowsSupport),
// a Consent function that asks the person at the device and an Indicator
// that shows the "remotely connected" notice while a session lasts; all
// three are mandatory. Every answer is bounded in size and personal data
// (user names in paths, e-mail and IP addresses, account names, SIDs) is
// masked before it leaves the device. Command lines and environment
// variables are never collected.
package support

import (
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Kinds of snapshot.
const (
	KindProcesses = "processes"
	KindServices  = "services"
	KindEvents    = "events"
	KindDisks     = "disks"
	KindStartup   = "startup"
)

// Kinds lists every snapshot kind.
func Kinds() []string {
	return []string{KindProcesses, KindServices, KindEvents, KindDisks, KindStartup}
}

// ValidKind reports whether k is a snapshot kind.
func ValidKind(k string) bool {
	for _, x := range Kinds() {
		if x == k {
			return true
		}
	}
	return false
}

// Limits on what one snapshot carries.
const (
	MaxProcesses   = 600
	MaxServices    = 600
	MaxEvents      = 100
	MaxDisks       = 64
	MaxStartup     = 200
	MaxNameLen     = 128
	MaxMessageLen  = 512
	MaxResponse    = 1 << 20
	maxCommandOut  = 8 << 20
	collectTimeout = 15 * time.Second
)

// Errors.
var (
	ErrUnsupported = errors.New("destek araçları bu sistemde desteklenmiyor")
	ErrProtected   = errors.New("bu süreç sistem için kritik; sonlandırılamaz")
	ErrNoProcess   = errors.New("süreç bulunamadı veya adı değişti")
)

// Process is one running process. Only the program name is kept; the
// command line can hold passwords and is never read.
type Process struct {
	PID      int    `json:"pid"`
	Name     string `json:"name"`
	MemoryKB uint64 `json:"memory_kb"`
}

// Service is one system service.
type Service struct {
	Name    string `json:"name"`
	Display string `json:"display,omitempty"`
	State   string `json:"state"`
	Start   string `json:"start,omitempty"`
}

// Event is one recent warning or error of the system log.
type Event struct {
	Time    time.Time `json:"time"`
	Level   string    `json:"level"`
	Source  string    `json:"source"`
	ID      int       `json:"id,omitempty"`
	Message string    `json:"message"`
}

// Disk is the usage of one mounted file system.
type Disk struct {
	Mount      string `json:"mount"`
	TotalBytes uint64 `json:"total_bytes"`
	FreeBytes  uint64 `json:"free_bytes"`
}

// StartupItem is one program started at boot or sign-in.
type StartupItem struct {
	Name     string `json:"name"`
	Location string `json:"location"`
	Command  string `json:"command,omitempty"`
}

// Snapshot is the answer to one request.
type Snapshot struct {
	Kind        string        `json:"kind"`
	CollectedAt time.Time     `json:"collected_at"`
	Truncated   bool          `json:"truncated"`
	Processes   []Process     `json:"processes,omitempty"`
	Services    []Service     `json:"services,omitempty"`
	Events      []Event       `json:"events,omitempty"`
	Disks       []Disk        `json:"disks,omitempty"`
	Startup     []StartupItem `json:"startup,omitempty"`
}

// --- masking ---

var (
	reWinProfile = regexp.MustCompile(`(?i)([a-z]:\\(?:users|documents and settings)\\)[^\\/\s"';,]+`)
	reUnixHome   = regexp.MustCompile(`(/(?:home|Users|var/home)/)[^/\s"';,]+`)
	reEmail      = regexp.MustCompile(`([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)`)
	reIPv4       = regexp.MustCompile(`\b(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}\b`)
	reIPv6       = regexp.MustCompile(`(?i)\b[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}\b`)
	reSID        = regexp.MustCompile(`\bS-1-5-21(?:-\d+){1,5}\b`)
	reMAC        = regexp.MustCompile(`(?i)\b([0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2})[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}\b`)
	reAccount    = regexp.MustCompile(`(?i)((?:account name|user ?name|workstation name|client name|hesap adı|kullanıcı adı|iş istasyonu adı)\s*[:=]\s*)[^\s,;]+`)
	reUserKV     = regexp.MustCompile(`(?i)\b((?:user|uid|_uid|login)=)[^\s,;]+`)
)

// Mask removes personal data from s: user names in profile paths, e-mail
// addresses (first letter kept), the last two parts of IPv4 addresses,
// IPv6 addresses, MAC addresses, Windows SIDs and account name fields.
// Go's regular expressions run in linear time, so a hostile log line
// cannot stall it.
func Mask(s string) string {
	if s == "" {
		return s
	}
	s = reWinProfile.ReplaceAllString(s, `${1}***`)
	s = reUnixHome.ReplaceAllString(s, `${1}***`)
	s = reEmail.ReplaceAllString(s, `${1}***@${2}`)
	s = reSID.ReplaceAllString(s, `S-1-5-21-***`)
	s = reMAC.ReplaceAllString(s, `${1}:**:**:**`)
	s = reIPv6.ReplaceAllStringFunc(s, func(m string) string {
		if looksIPv6(m) {
			return "***:***"
		}
		return m
	})
	s = reIPv4.ReplaceAllString(s, `${1}.${2}.***.***`)
	s = reAccount.ReplaceAllString(s, `${1}***`)
	s = reUserKV.ReplaceAllString(s, `${1}***`)
	return s
}

// looksIPv6 tells an IPv6 address from times ("12:30:45") and C++ scope
// names ("Class::Method"): "::" or five colons, at least two non-empty
// groups and a digit.
func looksIPv6(m string) bool {
	if !strings.Contains(m, "::") && strings.Count(m, ":") < 5 {
		return false
	}
	groups := 0
	for _, g := range strings.Split(m, ":") {
		if g != "" {
			groups++
		}
	}
	return groups >= 2 && strings.ContainsAny(m, "0123456789")
}

// clean masks s, removes control characters and cuts it to max bytes on a
// character boundary.
func clean(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\t' || r == '\r':
			return ' '
		case unicode.IsControl(r) || r == utf8.RuneError:
			return -1
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	s = Mask(s)
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

// Clean prepares one snapshot for sending: every text field is masked and
// cut, and the lists are bounded; Truncated is set when a list was cut.
func (s *Snapshot) Clean() {
	if len(s.Processes) > MaxProcesses {
		s.Processes, s.Truncated = s.Processes[:MaxProcesses], true
	}
	for i := range s.Processes {
		s.Processes[i].Name = clean(s.Processes[i].Name, MaxNameLen)
	}
	if len(s.Services) > MaxServices {
		s.Services, s.Truncated = s.Services[:MaxServices], true
	}
	for i := range s.Services {
		v := &s.Services[i]
		v.Name, v.Display, v.State, v.Start = clean(v.Name, MaxNameLen), clean(v.Display, MaxNameLen), clean(v.State, 32), clean(v.Start, 32)
	}
	if len(s.Events) > MaxEvents {
		s.Events, s.Truncated = s.Events[:MaxEvents], true
	}
	for i := range s.Events {
		v := &s.Events[i]
		v.Level, v.Source, v.Message = clean(v.Level, 32), clean(v.Source, MaxNameLen), clean(v.Message, MaxMessageLen)
	}
	if len(s.Disks) > MaxDisks {
		s.Disks, s.Truncated = s.Disks[:MaxDisks], true
	}
	for i := range s.Disks {
		s.Disks[i].Mount = clean(s.Disks[i].Mount, MaxNameLen)
	}
	if len(s.Startup) > MaxStartup {
		s.Startup, s.Truncated = s.Startup[:MaxStartup], true
	}
	for i := range s.Startup {
		v := &s.Startup[i]
		v.Name, v.Location, v.Command = clean(v.Name, MaxNameLen), clean(v.Location, MaxNameLen), clean(v.Command, MaxMessageLen)
	}
}
