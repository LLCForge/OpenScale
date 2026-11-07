package adblock

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// entry is what the index knows about one name: the categories it blocks,
// the categories whose list excepts it and whether it is on the keep list
// (update domains that are never blocked, #697).
type entry struct {
	block CategorySet
	allow CategorySet
	keep  bool
}

// Matcher is the merged, immutable index of every category list. It is a
// suffix index: each listed name is a key and a lookup walks the queried
// name's suffixes from the full name up to the top-level label, one hash
// lookup per label. That has the reach of a label trie (a name blocks
// itself and every name below it) at a fraction of its memory for two
// million names. Safe for concurrent use.
type Matcher struct {
	idx     map[string]entry
	names   [5]int // listed names per category, AllCategories order
	keep    int
	skipped int
}

// ListInfo describes one list added to a Builder.
type ListInfo struct {
	Category Category `json:"category"`
	Names    int      `json:"names"`
	Allows   int      `json:"allows"`
	Skipped  int      `json:"skipped"`
}

// Builder merges lists into a Matcher. Not safe for concurrent use.
type Builder struct {
	idx     map[string]entry
	names   [5]int
	keep    int
	skipped int
}

// NewBuilder returns an empty builder.
func NewBuilder() *Builder { return &Builder{idx: map[string]entry{}} }

func (b *Builder) put(n string, f func(*entry) bool) error {
	e, ok := b.idx[n]
	if !ok && len(b.idx) >= MaxNames {
		return ErrTooManyNames
	}
	if f(&e) || !ok {
		b.idx[n] = e
	}
	return nil
}

// AddList reads one list of category c (at most MaxFileSize bytes).
// Exceptions ("@@") of the list only lift c.
func (b *Builder) AddList(c Category, r io.Reader) (ListInfo, error) {
	return b.addList(c, r, MaxFileSize)
}

func (b *Builder) addList(c Category, r io.Reader, limit int64) (ListInfo, error) {
	if b == nil || b.idx == nil {
		return ListInfo{}, errors.New("adblock: kullanılmış veya boş derleyici")
	}
	if !c.Valid() {
		return ListInfo{}, fmt.Errorf("geçersiz kategori: %d", uint8(c))
	}
	info := ListInfo{Category: c}
	cs := CategorySet(c)
	skipped, err := ParseList(r, limit, func(n string, allow bool) error {
		return b.put(n, func(e *entry) bool {
			if allow {
				if e.allow.Has(c) {
					return false
				}
				e.allow |= cs
				info.Allows++
				return true
			}
			if e.block.Has(c) {
				return false
			}
			e.block |= cs
			info.Names++
			return true
		})
	})
	info.Skipped = skipped
	if err != nil {
		return info, err
	}
	b.names[c.index()] += info.Names
	b.skipped += skipped
	return info, nil
}

// AddKeep reads the keep list: names (and everything below them) that no
// category ever blocks, such as operating system update domains. The
// same line formats are accepted; "@@" lines count as keep names too.
func (b *Builder) AddKeep(r io.Reader) (int, error) {
	if b == nil || b.idx == nil {
		return 0, errors.New("adblock: kullanılmış veya boş derleyici")
	}
	added := 0
	skipped, err := ParseList(r, MaxFileSize, func(n string, _ bool) error {
		return b.put(n, func(e *entry) bool {
			if e.keep {
				return false
			}
			e.keep = true
			added++
			return true
		})
	})
	b.skipped += skipped
	b.keep += added
	return added, err
}

// AddListFile reads a local list file of category c.
func (b *Builder) AddListFile(c Category, path string) (ListInfo, error) {
	f, err := openRegular(path, MaxFileSize)
	if err != nil {
		return ListInfo{}, err
	}
	defer f.Close()
	return b.AddList(c, f)
}

// AddKeepFile reads a local keep list file.
func (b *Builder) AddKeepFile(path string) (int, error) {
	f, err := openRegular(path, MaxFileSize)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return b.AddKeep(f)
}

// Build returns the matcher; the builder must not be used afterwards.
func (b *Builder) Build() *Matcher {
	m := &Matcher{idx: b.idx, names: b.names, keep: b.keep, skipped: b.skipped}
	b.idx = nil
	return m
}

// Match returns the categories that block name (absolute or not, any
// case) after the lists' own exceptions, and whether a keep entry covers
// it. A keep entry wins over every category.
func (m *Matcher) Match(name string) (CategorySet, bool) {
	if m == nil || len(m.idx) == 0 {
		return 0, false
	}
	var block, allow CategorySet
	keep := false
	eachSuffix(queryName(name), func(s string) bool {
		if e, ok := m.idx[s]; ok {
			block |= e.block
			allow |= e.allow
			keep = keep || e.keep
		}
		return true
	})
	if keep {
		return 0, true
	}
	return block &^ allow, false
}

// MatcherInfo summarizes a matcher for the panel.
type MatcherInfo struct {
	Names   map[string]int `json:"names"`
	Keep    int            `json:"keep"`
	Skipped int            `json:"skipped"`
}

// Info reports the listed names per category.
func (m *Matcher) Info() MatcherInfo {
	out := MatcherInfo{Names: map[string]int{}}
	if m == nil {
		return out
	}
	for i, c := range AllCategories {
		out.Names[c.String()] = m.names[i]
	}
	out.Keep, out.Skipped = m.keep, m.skipped
	return out
}

// Has reports whether any list of category c has names.
func (m *Matcher) Has(c Category) bool {
	return m != nil && c.Valid() && m.names[c.index()] > 0
}

// openRegular opens a regular file of at most limit bytes.
func openRegular(path string, limit int64) (*os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("liste açılamadı: %w", err)
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !st.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("liste düzenli bir dosya olmalı")
	}
	if st.Size() > limit {
		f.Close()
		return nil, fmt.Errorf("liste %d bayttan büyük olamaz", limit)
	}
	return f, nil
}
