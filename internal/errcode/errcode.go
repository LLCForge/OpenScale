// Package errcode gives OpenScale's errors stable codes (#550, ADR-0165).
//
// A code ("OS-3001") names one kind of problem for good: it is printed
// next to the Turkish message on the command line, returned by the panel
// API, explained offline by "openscale explain <kod>" and used as the
// anchor of the troubleshooting guide (docs/sorun-giderme.md). Codes are
// never renumbered or reused; a code that no longer happens stays in the
// catalog marked Deprecated so old messages, scripts and forum posts keep
// pointing to an explanation.
package errcode

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Areas group the codes; the thousands digit of a code is its area.
const (
	AreaDocument   = "belge"       // 1xxx: trust document and root key
	AreaMembership = "uyelik"      // 2xxx: devices, invites, enrollment
	AreaConnection = "baglanti"    // 3xxx: coordinator, NAT, relay, tunnel
	AreaDNS        = "dns"         // 4xxx: MagicDNS and the system resolver
	AreaKillSwitch = "kill-switch" // 5xxx: kill switch and firewalls
	AreaSystem     = "sistem"      // 6xxx: permissions, ports, files, services
	AreaPanel      = "panel"       // 7xxx: panel and local API
)

// CatalogVersion is raised whenever codes are added. Removing or changing
// the meaning of a code is not allowed (ADR-0165).
const CatalogVersion = 1

// codePattern is the only accepted form of a code.
var codePattern = regexp.MustCompile(`^OS-[1-7][0-9]{3}$`)

// Entry explains one code.
type Entry struct {
	Code  string `json:"code"`
	Area  string `json:"area"`
	Title string `json:"title"`
	// Cause says why the problem happens, in one or two sentences.
	Cause string `json:"cause"`
	// Steps are what the owner does, in order.
	Steps []string `json:"steps"`
	// Commands are read-only commands that show more.
	Commands []string `json:"commands,omitempty"`
	// Doc is the section of the troubleshooting guide, relative to docs/.
	Doc string `json:"doc"`
	// Since is the catalog version that added the code.
	Since int `json:"since"`
	// Deprecated codes no longer happen but stay explainable.
	Deprecated bool `json:"deprecated,omitempty"`
}

// Valid reports whether s has the form of a code (it may still be unknown).
func Valid(s string) bool { return codePattern.MatchString(s) }

// Normalize accepts "os-3001", "OS3001" and "3001" and returns "OS-3001";
// anything else returns "" (input is bounded and never echoed raw).
func Normalize(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if len(s) > 16 {
		return ""
	}
	s = strings.TrimPrefix(s, "OS-")
	s = strings.TrimPrefix(s, "OS")
	s = "OS-" + s
	if !Valid(s) {
		return ""
	}
	return s
}

// docAnchor is the guide section of a code; the guide uses the lower-case
// code as its heading anchor.
func docAnchor(code string) string {
	return "sorun-giderme.md#" + strings.ToLower(code)
}

var byCode = func() map[string]*Entry {
	m := make(map[string]*Entry, len(catalog))
	for i := range catalog {
		e := &catalog[i]
		if e.Doc == "" {
			e.Doc = docAnchor(e.Code)
		}
		if e.Since == 0 {
			e.Since = 1
		}
		m[e.Code] = e
	}
	return m
}()

// Lookup returns the entry of a code in any accepted spelling.
func Lookup(code string) (Entry, bool) {
	e, ok := byCode[Normalize(code)]
	if !ok {
		return Entry{}, false
	}
	return clone(*e), true
}

// All returns every entry in code order.
func All() []Entry {
	out := make([]Entry, 0, len(catalog))
	for _, e := range byCode {
		out = append(out, clone(*e))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Code < out[j].Code })
	return out
}

// Search returns the entries whose code, title or cause contains every
// word of q (case-insensitive, Turkish letters folded to ASCII).
func Search(q string) []Entry {
	words := strings.Fields(fold(q))
	var out []Entry
	for _, e := range All() {
		hay := fold(e.Code + " " + e.Area + " " + e.Title + " " + e.Cause + " " + strings.Join(e.Steps, " "))
		ok := len(words) > 0
		for _, w := range words {
			if !strings.Contains(hay, w) {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, e)
		}
	}
	return out
}

func fold(s string) string {
	return strings.NewReplacer("ı", "i", "İ", "i", "ş", "s", "Ş", "s", "ğ", "g", "Ğ", "g",
		"ü", "u", "Ü", "u", "ö", "o", "Ö", "o", "ç", "c", "Ç", "c").Replace(strings.ToLower(s))
}

func clone(e Entry) Entry {
	e.Steps = append([]string(nil), e.Steps...)
	e.Commands = append([]string(nil), e.Commands...)
	return e
}

// Classify returns the code of err, or "" when err has none. Sentinel
// errors are matched with errors.Is, operating system errors by their
// errno and, last, a few messages from tools and the local API by text.
func Classify(err error) string {
	if err == nil {
		return ""
	}
	for _, m := range sentinelMatchers {
		if errors.Is(err, m.target) {
			return m.code
		}
	}
	if code := classifyErrno(err); code != "" {
		return code
	}
	msg := strings.ToLower(err.Error())
	for _, m := range textMatchers {
		if strings.Contains(msg, m.text) {
			return m.code
		}
	}
	for _, m := range lateMatchers {
		if errors.Is(err, m.target) {
			return m.code
		}
	}
	return ""
}

// Suffix is the line printed after an error message on the command line.
func Suffix(code string) string {
	if code == "" {
		return ""
	}
	return fmt.Sprintf("kod: %s (ayrıntı ve çözüm: openscale explain %s)", code, code)
}
