package sysinfo

import (
	"bufio"
	"io"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Shared folders (ADR-0226). The detailed inventory lists the SMB shares
// this computer offers, so an admin Windows device can add them under
// "Ağdaki konumlar" without the owner typing addresses. Only the share
// name and its optional comment are sent: no folder path, user, password
// or permission ever leaves the computer. Like the rest of the inventory
// it reaches admin devices only, through the tunnel; the coordinator
// never receives it.
//
// A report may come from a hostile device, so every name is checked again
// on the receiving side (normalizeShares in Detail.sanitize) and once more
// where a network location is made (netdrive).

// Share is one SMB disk share offered by the computer.
type Share struct {
	Name    string `json:"name"`
	Comment string `json:"comment,omitempty"`
}

// Limits of the share list.
const (
	MaxShares       = 64
	maxShareName    = 80
	maxShareComment = 64
	// smbPort is where an SMB server listens; without it the shares are
	// not reachable and none are reported.
	smbPort = 445
)

// windowsReserved are names Windows cannot use for a folder; a share
// named like this could not become a network location.
var windowsReserved = []string{"con", "prn", "aux", "nul",
	"com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9",
	"lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9"}

// ValidShareName reports whether s is a share name OpenScale passes on:
// 1-80 bytes of letters, digits, space, '.', '_' and '-', not starting or
// ending with a space or dot, without "..", not hidden (no trailing '$')
// and not a reserved Windows device name. Path separators, ':' and every
// other punctuation are refused, so the name can never leave the share
// part of a UNC path or the folder it is shown in.
func ValidShareName(s string) bool {
	if s == "" || len(s) > maxShareName || !utf8.ValidString(s) || strings.Contains(s, "..") {
		return false
	}
	first, _ := utf8.DecodeRuneInString(s)
	last, _ := utf8.DecodeLastRuneInString(s)
	if first == ' ' || first == '.' || last == ' ' || last == '.' {
		return false
	}
	for _, r := range s {
		switch {
		case r == ' ' || r == '.' || r == '_' || r == '-':
		case r < 0x80 && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'):
		case r >= 0x80 && (unicode.IsLetter(r) || unicode.IsDigit(r)):
		default:
			return false
		}
	}
	base := strings.ToLower(s)
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	return !slices.Contains(windowsReserved, strings.TrimSpace(base))
}

// normalizeShares keeps valid shares, cleans comments, drops duplicates
// (case-insensitive, as SMB names are), sorts by name and caps the list.
func normalizeShares(in []Share) []Share {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []Share
	for _, s := range in {
		key := strings.ToLower(s.Name)
		if !ValidShareName(s.Name) || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, Share{Name: s.Name, Comment: shareComment(s.Comment)})
		if len(out) == MaxShares {
			break
		}
	}
	slices.SortFunc(out, func(a, b Share) int { return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)) })
	return out
}

func shareComment(s string) string {
	s = cleanText(s)
	if len(s) > maxShareComment {
		s = s[:maxShareComment]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return strings.TrimSpace(s)
}

// shareSources are the platform's share readers; tests replace them.
var (
	shareListening = func() []uint16 { return ListeningPorts() }
	shareList      = listShares
)

// collectShares fills d.Shares when an SMB server listens on an address
// other devices can reach.
func collectShares(d *Detail) {
	if !slices.Contains(shareListening(), smbPort) {
		d.Shares = nil
		return
	}
	d.Shares = normalizeShares(shareList())
}

// ---- Samba (Linux) ----

// maxSambaConf bounds the configuration text read.
const maxSambaConf = 1 << 20

// ParseSambaConfig reads the share sections of a Samba configuration, as
// printed by "testparm -s" or written in smb.conf. Left out are [global],
// [homes] (a per-user template), printer shares ([printers], [print$],
// "printable = yes"), hidden shares (name ending in '$', "browseable =
// no") and disabled ones ("available = no"). Paths and users are never
// read.
func ParseSambaConfig(r io.Reader) []Share {
	type section struct {
		name      string
		comment   string
		hidden    bool
		printable bool
		off       bool
	}
	var (
		out []Share
		cur *section
	)
	flush := func() {
		if cur == nil {
			return
		}
		n := strings.ToLower(cur.name)
		switch {
		case n == "global" || n == "homes" || n == "printers" || n == "print$" || n == "ipc$":
		case strings.HasSuffix(n, "$"), cur.hidden, cur.printable, cur.off:
		default:
			out = append(out, Share{Name: cur.name, Comment: cur.comment})
		}
		cur = nil
	}
	sc := bufio.NewScanner(io.LimitReader(r, maxSambaConf))
	sc.Buffer(make([]byte, 0, 4096), 64<<10)
	var pending string
	for sc.Scan() {
		line := pending + strings.TrimSpace(sc.Text())
		pending = ""
		if strings.HasSuffix(line, `\`) {
			pending = strings.TrimSuffix(line, `\`)
			continue
		}
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '[' {
			flush()
			end := strings.IndexByte(line, ']')
			if end < 0 {
				continue
			}
			cur = &section{name: strings.TrimSpace(line[1:end])}
			continue
		}
		if cur == nil {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.NewReplacer(" ", "", "\t", "", "_", "").Replace(key))
		value = strings.TrimSpace(value)
		switch key {
		case "comment":
			cur.comment = value
		case "browseable", "browsable":
			cur.hidden = !sambaBool(value, true)
		case "printable", "printok":
			cur.printable = sambaBool(value, false)
		case "available":
			cur.off = !sambaBool(value, true)
		}
	}
	flush()
	return out
}

// ParseUsershareList reads "net usershare list" output: one share name
// per line.
func ParseUsershareList(r io.Reader) []Share {
	var out []Share
	sc := bufio.NewScanner(io.LimitReader(r, maxSambaConf))
	for sc.Scan() {
		name := strings.TrimSpace(sc.Text())
		if name == "" || strings.HasSuffix(name, "$") {
			continue
		}
		out = append(out, Share{Name: name})
	}
	return out
}

func sambaBool(v string, def bool) bool {
	switch strings.ToLower(v) {
	case "yes", "true", "1", "on":
		return true
	case "no", "false", "0", "off":
		return false
	}
	return def
}
