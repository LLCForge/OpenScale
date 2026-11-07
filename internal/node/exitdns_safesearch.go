package node

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// Safe search mapping (#417). The owner puts a local file on the exit node
// whose lines map a search engine name to its safe search name:
//
//	# kaynak               hedef
//	www.arama.example      guvenli.arama.example
//
// Members of a profile with safe_search asking for a source name get a
// CNAME to the target, resolved through the exit node's own upstream; no
// extra service is asked. OpenScale ships no built-in names (ADR-0008);
// docs/adr has an example for the common search engines.

// Limits of a safe search map file.
const (
	maxSafeSearchFile    = 1 << 20
	maxSafeSearchEntries = 4096
)

// LoadSafeSearchMap reads a map from a regular file.
func LoadSafeSearchMap(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("güvenli arama eşlemesi açılamadı: %w", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("güvenli arama eşlemesi düzenli bir dosya olmalı")
	}
	if st.Size() > maxSafeSearchFile {
		return nil, fmt.Errorf("güvenli arama eşlemesi %d KiB'tan büyük olamaz", maxSafeSearchFile>>10)
	}
	return ParseSafeSearchMap(f)
}

// ParseSafeSearchMap reads "source target" lines; '#' starts a comment.
// A malformed line fails the whole file: a half-read map would leave a
// search engine unfiltered without a word.
func ParseSafeSearchMap(r io.Reader) (map[string]string, error) {
	out := map[string]string{}
	s := bufio.NewScanner(io.LimitReader(r, maxSafeSearchFile+1))
	s.Buffer(make([]byte, 0, 4096), 4096)
	line, read := 0, 0
	for s.Scan() {
		line++
		read += len(s.Bytes()) + 1
		if read > maxSafeSearchFile+1 {
			return nil, fmt.Errorf("güvenli arama eşlemesi %d KiB'tan büyük olamaz", maxSafeSearchFile>>10)
		}
		text := s.Text()
		if i := strings.IndexByte(text, '#'); i >= 0 {
			text = text[:i]
		}
		f := strings.Fields(strings.TrimPrefix(text, "\xef\xbb\xbf"))
		if len(f) == 0 {
			continue
		}
		if len(f) != 2 {
			return nil, fmt.Errorf("güvenli arama eşlemesi satır %d: \"kaynak hedef\" bekleniyor", line)
		}
		src, ok1 := normalizeDomain(f[0])
		dst, ok2 := normalizeDomain(f[1])
		if !ok1 || !ok2 || strings.HasPrefix(f[0], "*.") || strings.HasPrefix(f[1], "*.") {
			return nil, fmt.Errorf("güvenli arama eşlemesi satır %d: geçersiz alan adı", line)
		}
		if src == dst {
			return nil, fmt.Errorf("güvenli arama eşlemesi satır %d: kaynak ve hedef aynı", line)
		}
		if _, dup := out[src]; !dup && len(out) >= maxSafeSearchEntries {
			return nil, fmt.Errorf("güvenli arama eşlemesinde en fazla %d satır olabilir", maxSafeSearchEntries)
		}
		out[src] = dst
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("güvenli arama eşlemesi okunamadı: %w", err)
	}
	return out, nil
}
