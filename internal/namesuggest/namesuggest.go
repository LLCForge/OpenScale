// Package namesuggest finds the names closest to a misspelt one, for "did
// you mean" hints (#798). The comparison ignores case and the Turkish
// letters that are often typed without their marks (ı/i, ü/u, ö/o, ş/s,
// ç/c, ğ/g), so "Masaüstü" matches "masaustu".
//
// The package only compares the strings it is given; it never looks a name
// up anywhere. Callers pass the names they already know locally, which is
// what the blind coordinator mode (members-only documents, ADR-0178)
// requires: nothing about the typed name leaves this computer.
package namesuggest

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Limits keep the comparison cheap for any input.
const (
	// MaxSuggestions is the most names Suggest returns.
	MaxSuggestions = 3
	// maxNameRunes bounds the compared length of one name.
	maxNameRunes = 128
	// maxCandidates bounds the names compared for one query.
	maxCandidates = 10000
)

// fold maps one rune to the form used for comparison.
func fold(r rune) rune {
	switch r {
	case 'ı', 'I', 'İ', 'i':
		return 'i'
	case 'ü', 'Ü':
		return 'u'
	case 'ö', 'Ö':
		return 'o'
	case 'ş', 'Ş':
		return 's'
	case 'ç', 'Ç':
		return 'c'
	case 'ğ', 'Ğ':
		return 'g'
	}
	return unicode.ToLower(r)
}

// Fold returns s in the comparison form: lower case, Turkish letters
// without their marks, surrounding space removed and at most 128 runes.
func Fold(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	b.Grow(len(s))
	n := 0
	for _, r := range s {
		if n == maxNameRunes {
			break
		}
		if r == utf8.RuneError {
			continue
		}
		b.WriteRune(fold(r))
		n++
	}
	return b.String()
}

// Distance is the edit distance between a and b after Fold: insertions,
// deletions, substitutions and swaps of two neighbouring letters each
// cost one (optimal string alignment).
func Distance(a, b string) int {
	return distance([]rune(Fold(a)), []rune(Fold(b)))
}

func distance(a, b []rune) int {
	if len(a) == 0 {
		return len(b)
	}
	if len(b) == 0 {
		return len(a)
	}
	// Three rows are enough for the swap case.
	prev2 := make([]int, len(b)+1)
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
			if i > 1 && j > 1 && a[i-1] == b[j-2] && a[i-2] == b[j-1] {
				cur[j] = min(cur[j], prev2[j-2]+1)
			}
		}
		prev2, prev, cur = prev, cur, prev2
	}
	return prev[len(b)]
}

// threshold is the largest distance still worth suggesting for a query of
// n runes: one for short names, up to three for long ones.
func threshold(n int) int {
	return max(1, min(3, n/3))
}

// Suggest returns up to limit names of candidates closest to query, nearest
// first and alphabetically among equals. A candidate equal to query is never
// suggested; one that differs only in case or Turkish marks comes first. A
// candidate that starts with a query of three or more letters counts as one
// edit away. limit is clamped to 1..MaxSuggestions.
func Suggest(query string, candidates []string, limit int) []string {
	limit = max(1, min(MaxSuggestions, limit))
	q := []rune(Fold(query))
	if len(q) == 0 {
		return nil
	}
	if len(candidates) > maxCandidates {
		candidates = candidates[:maxCandidates]
	}
	type scored struct {
		name string
		dist int
	}
	var found []scored
	seen := map[string]bool{}
	limitDist := threshold(len(q))
	for _, c := range candidates {
		c = strings.TrimSpace(c)
		if c == "" || c == strings.TrimSpace(query) || seen[c] {
			continue
		}
		seen[c] = true
		fc := []rune(Fold(c))
		// Lengths far apart can never be close; skip the matrix.
		d := limitDist + 1
		if abs(len(fc)-len(q)) <= limitDist {
			d = distance(q, fc)
		}
		if d > limitDist && len(q) >= 3 && strings.HasPrefix(string(fc), string(q)) {
			d = 1
		}
		if d <= limitDist {
			found = append(found, scored{c, d})
		}
	}
	slices.SortFunc(found, func(a, b scored) int {
		if a.dist != b.dist {
			return a.dist - b.dist
		}
		return strings.Compare(a.name, b.name)
	})
	out := make([]string, 0, min(limit, len(found)))
	for _, f := range found {
		if len(out) == limit {
			break
		}
		out = append(out, f.name)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// Hint returns "Bunu mu demek istediniz: a, b?" for the suggestions of
// query among candidates, or "" when nothing is close.
func Hint(query string, candidates []string) string {
	return FormatHint(Suggest(query, candidates, MaxSuggestions), "")
}

// FormatHint words a list of suggestions, each prefixed (for example
// "tag:"); "" for none.
func FormatHint(suggestions []string, prefix string) string {
	if len(suggestions) == 0 {
		return ""
	}
	parts := make([]string, len(suggestions))
	for i, s := range suggestions {
		parts[i] = prefix + s
	}
	return "Bunu mu demek istediniz: " + strings.Join(parts, ", ") + "?"
}

// Kind names what was not found.
type Kind string

// Kinds of names.
const (
	KindDevice Kind = "cihaz"
	KindGroup  Kind = "grup"
	KindTag    Kind = "etiket"
)

// NotFoundError is an unknown name with the known names closest to it. It
// wraps the original error, so errors.Is keeps working and the original
// message stays the same.
type NotFoundError struct {
	Kind        Kind
	Name        string
	Suggestions []string
	Err         error
}

func (e *NotFoundError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return fmt.Sprintf("%s bulunamadı: %s", e.Kind, e.Name)
}

func (e *NotFoundError) Unwrap() error { return e.Err }

// Hint words the suggestions with the name that was typed, or "" when none
// is close.
func (e *NotFoundError) Hint() string {
	prefix := ""
	switch e.Kind {
	case KindTag:
		prefix = "tag:"
	case KindGroup:
		prefix = "group:"
	}
	h := FormatHint(e.Suggestions, prefix)
	if h == "" {
		return ""
	}
	return fmt.Sprintf("%q adlı %s yok. %s", e.Name, e.Kind, h)
}

// Wrap returns err as a NotFoundError for name with its suggestions among
// candidates; err itself when nothing is close or err is nil.
func Wrap(err error, kind Kind, name string, candidates []string) error {
	if err == nil {
		return nil
	}
	var nf *NotFoundError
	if errors.As(err, &nf) {
		return err
	}
	s := Suggest(name, candidates, MaxSuggestions)
	if len(s) == 0 {
		return err
	}
	return &NotFoundError{Kind: kind, Name: name, Suggestions: s, Err: err}
}
