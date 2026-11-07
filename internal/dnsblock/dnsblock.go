// Package dnsblock reads the owner's domain block lists for the exit
// node's resolver (#91, F-059, ADR-0102). Lists come only from a local
// file the owner puts on the exit node; OpenScale never downloads one
// (ADR-0008: no address the owner did not configure is contacted).
//
// Accepted line formats, mixed freely in one file:
//
//	ads.example                  plain name
//	0.0.0.0 ads.example b.example hosts file (any address; extra names)
//	||ads.example^               adblock-style name rule
//	@@||good.example^            exception: never blocked
//	*.ads.example                same as ads.example
//
// A name blocks itself and every name below it. Comments start with '#'
// or '!'. Adblock rules with options ($...), paths or other patterns are
// skipped, never guessed: a block list must not block more than it says.
package dnsblock

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
)

// Limits on a list.
const (
	MaxFileSize = 64 << 20
	MaxEntries  = 2_000_000
	maxLine     = 4096
)

// List is an immutable set of blocked names; safe for concurrent use.
type List struct {
	block map[string]struct{}
	allow map[string]struct{}
	// Skipped counts lines that were not understood.
	Skipped int
}

// hostsSkip are hosts file names that are never blocked.
var hostsSkip = map[string]bool{
	"localhost": true, "localhost.localdomain": true, "local": true, "broadcasthost": true,
	"ip6-localhost": true, "ip6-loopback": true, "ip6-localnet": true, "ip6-mcastprefix": true,
	"ip6-allnodes": true, "ip6-allrouters": true, "ip6-allhosts": true, "0.0.0.0": true,
}

// Load reads a list from a regular file of at most MaxFileSize bytes.
func Load(path string) (*List, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("engel listesi açılamadı: %w", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("engel listesi düzenli bir dosya olmalı")
	}
	if st.Size() > MaxFileSize {
		return nil, fmt.Errorf("engel listesi %d MiB'tan büyük olamaz", MaxFileSize>>20)
	}
	return Parse(f)
}

// Parse reads a list.
func Parse(r io.Reader) (*List, error) {
	l := &List{block: map[string]struct{}{}, allow: map[string]struct{}{}}
	br := bufio.NewReaderSize(io.LimitReader(r, MaxFileSize+1), 64<<10)
	read := 0
	for {
		line, err := br.ReadString('\n')
		read += len(line)
		if read > MaxFileSize {
			return nil, fmt.Errorf("engel listesi %d MiB'tan büyük olamaz", MaxFileSize>>20)
		}
		if len(line) > 0 {
			if len(line) > maxLine {
				l.Skipped++
			} else if err := l.addLine(line); err != nil {
				return nil, err
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("engel listesi okunamadı: %w", err)
		}
	}
	return l, nil
}

func (l *List) addLine(line string) error {
	s := strings.TrimSpace(strings.TrimPrefix(line, "\xef\xbb\xbf")) // UTF-8 byte order mark
	if s == "" || s[0] == '#' || s[0] == '!' || strings.HasPrefix(s, "[") {
		return nil
	}
	if i := strings.Index(s, " #"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	if i := strings.Index(s, "\t#"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	switch {
	case strings.HasPrefix(s, "@@||"):
		if n, ok := adblockName(s[2:]); ok {
			l.allow[n] = struct{}{}
			return nil
		}
		l.Skipped++
		return nil
	case strings.HasPrefix(s, "||"):
		if n, ok := adblockName(s); ok {
			return l.add(n)
		}
		l.Skipped++
		return nil
	}
	f := strings.Fields(s)
	if len(f) >= 2 {
		if _, err := netip.ParseAddr(f[0]); err == nil {
			for _, h := range f[1:] {
				n, ok := normalize(h)
				if !ok || hostsSkip[strings.TrimSuffix(n, ".")] {
					continue
				}
				if err := l.add(n); err != nil {
					return err
				}
			}
			return nil
		}
		l.Skipped++
		return nil
	}
	n, ok := normalize(strings.TrimPrefix(s, "*."))
	if !ok || hostsSkip[strings.TrimSuffix(n, ".")] {
		l.Skipped++
		return nil
	}
	return l.add(n)
}

func (l *List) add(n string) error {
	if _, ok := l.block[n]; ok {
		return nil
	}
	if len(l.block) >= MaxEntries {
		return fmt.Errorf("engel listesinde en fazla %d ad olabilir", MaxEntries)
	}
	l.block[n] = struct{}{}
	return nil
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

// Len is the number of blocked names.
func (l *List) Len() int {
	if l == nil {
		return 0
	}
	return len(l.block)
}

// Blocked reports whether name (absolute or not, any case) or a name
// above it is on the list and no exception covers it.
func (l *List) Blocked(name string) bool {
	if l == nil || len(l.block) == 0 {
		return false
	}
	n := strings.ToLower(name)
	if !strings.HasSuffix(n, ".") {
		n += "."
	}
	blocked := false
	for s := n; s != "" && s != "."; {
		if _, ok := l.allow[s]; ok {
			return false
		}
		if _, ok := l.block[s]; ok {
			blocked = true
		}
		i := strings.IndexByte(s, '.')
		if i < 0 || i == len(s)-1 {
			break
		}
		s = s[i+1:]
	}
	return blocked
}
