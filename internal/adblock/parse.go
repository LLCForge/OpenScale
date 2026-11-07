package adblock

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"

	"github.com/openscale/openscale/internal/dnsblock"
)

// Line formats are exactly those of internal/dnsblock (ADR-0102 §3): plain
// names, hosts file lines, "||name^", "@@||name^" exceptions and "*.name".
// Rules with options, paths or other patterns are skipped, never guessed.
// dnsblock does not expose the names it read, so the grammar is kept here
// line for line and TestParseMatchesDnsblock / FuzzParseList prove both
// readers decide every name the same way.

// Limits shared with dnsblock, plus the download limit of a subscription.
const (
	MaxFileSize     = dnsblock.MaxFileSize
	MaxNames        = dnsblock.MaxEntries
	MaxDownloadSize = 32 << 20
	maxLine         = 4096
)

// ErrTooManyNames is returned when the merged index would exceed MaxNames.
var ErrTooManyNames = fmt.Errorf("engel listelerinde en fazla %d ad olabilir", MaxNames)

// hostsSkip are hosts file names that are never blocked (as in dnsblock).
var hostsSkip = map[string]bool{
	"localhost": true, "localhost.localdomain": true, "local": true, "broadcasthost": true,
	"ip6-localhost": true, "ip6-loopback": true, "ip6-localnet": true, "ip6-mcastprefix": true,
	"ip6-allnodes": true, "ip6-allrouters": true, "ip6-allhosts": true, "0.0.0.0": true,
}

// ParseList reads a list of at most limit bytes and calls fn for every
// name with allow set for "@@" exceptions. It returns the number of
// skipped lines. Names are lowercase and absolute.
func ParseList(r io.Reader, limit int64, fn func(name string, allow bool) error) (int, error) {
	if limit <= 0 || limit > MaxFileSize {
		limit = MaxFileSize
	}
	br := bufio.NewReaderSize(io.LimitReader(r, limit+1), 64<<10)
	var read int64
	skipped := 0
	for {
		line, err := br.ReadString('\n')
		read += int64(len(line))
		if read > limit {
			return skipped, fmt.Errorf("engel listesi %d bayttan büyük olamaz", limit)
		}
		if len(line) > 0 {
			if len(line) > maxLine {
				skipped++
			} else {
				n, allow, kind := parseLine(line)
				switch kind {
				case lineSkip:
					skipped++
				case lineName:
					if e := fn(n, allow); e != nil {
						return skipped, e
					}
				case lineHosts:
					for _, h := range hostsNames(line) {
						if e := fn(h, false); e != nil {
							return skipped, e
						}
					}
				}
			}
		}
		if errors.Is(err, io.EOF) {
			return skipped, nil
		}
		if err != nil {
			return skipped, fmt.Errorf("engel listesi okunamadı: %w", err)
		}
	}
}

type lineKind int

const (
	lineNone lineKind = iota
	lineSkip
	lineName
	lineHosts
)

// clean strips the byte order mark, spaces and trailing comments.
func clean(line string) string {
	s := strings.TrimSpace(strings.TrimPrefix(line, "\xef\xbb\xbf"))
	if s == "" || s[0] == '#' || s[0] == '!' || strings.HasPrefix(s, "[") {
		return ""
	}
	if i := strings.Index(s, " #"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	if i := strings.Index(s, "\t#"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	return s
}

func parseLine(line string) (string, bool, lineKind) {
	s := clean(line)
	if s == "" {
		return "", false, lineNone
	}
	switch {
	case strings.HasPrefix(s, "@@||"):
		if n, ok := adblockName(s[2:]); ok {
			return n, true, lineName
		}
		return "", false, lineSkip
	case strings.HasPrefix(s, "||"):
		if n, ok := adblockName(s); ok {
			return n, false, lineName
		}
		return "", false, lineSkip
	}
	f := strings.Fields(s)
	if len(f) >= 2 {
		if _, err := netip.ParseAddr(f[0]); err == nil {
			return "", false, lineHosts
		}
		return "", false, lineSkip
	}
	n, ok := normalize(strings.TrimPrefix(s, "*."))
	if !ok || hostsSkip[strings.TrimSuffix(n, ".")] {
		return "", false, lineSkip
	}
	return n, false, lineName
}

// hostsNames returns the valid names of a hosts file line.
func hostsNames(line string) []string {
	f := strings.Fields(clean(line))
	var out []string
	for _, h := range f[1:] {
		n, ok := normalize(h)
		if !ok || hostsSkip[strings.TrimSuffix(n, ".")] {
			continue
		}
		out = append(out, n)
	}
	return out
}

// adblockName reads "||name^" with nothing after the separator.
func adblockName(s string) (string, bool) {
	s = strings.TrimPrefix(s, "||")
	s, ok := strings.CutSuffix(s, "^")
	if !ok {
		return "", false
	}
	return normalize(strings.TrimPrefix(s, "*."))
}

// normalize checks a host name and returns it lowercase with the trailing
// dot. Single-label names and addresses are refused: a list must not block
// a whole top-level domain by accident.
func normalize(h string) (string, bool) {
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	if h == "" || len(h) > 253 || !strings.Contains(h, ".") {
		return "", false
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return "", false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '_') {
				return "", false
			}
		}
	}
	return h + ".", true
}

// NormalizeName checks a name typed by the owner (exceptions, allow once).
func NormalizeName(s string) (string, error) {
	n, ok := normalize(strings.TrimPrefix(strings.TrimSpace(s), "*."))
	if !ok {
		return "", fmt.Errorf("geçersiz alan adı: %q", s)
	}
	return n, nil
}

// queryName lowercases a queried name and makes it absolute.
func queryName(name string) string {
	n := strings.ToLower(name)
	if !strings.HasSuffix(n, ".") {
		n += "."
	}
	return n
}

// eachSuffix calls fn for n and every name above it (not the root).
func eachSuffix(n string, fn func(s string) bool) {
	for s := n; s != "" && s != "."; {
		if !fn(s) {
			return
		}
		i := strings.IndexByte(s, '.')
		if i < 0 || i == len(s)-1 {
			return
		}
		s = s[i+1:]
	}
}

// under reports whether n is d or a name below d (both absolute).
func under(n, d string) bool {
	return n == d || strings.HasSuffix(n, "."+d)
}
