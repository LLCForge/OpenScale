// Package adblock is the category based domain blocking engine of the
// network wide ad blocker (#692-#697, ADR-0212). Owner block lists are
// sorted into categories (ads, trackers, crypto miners, smart TV and IoT
// telemetry, operating system telemetry), merged into one suffix index
// and decided per device with the owner's category policy, exceptions
// and timed "allow once" entries.
//
// The package never contacts an address by itself (ADR-0008). Lists come
// from a local file or from a subscription the owner approved in the
// signed document, pinned to the SHA-256 digest of its content; the
// download helper (Fetcher) runs only on an exit node. Category lists are
// not built into the program: the owner supplies every name.
package adblock

import (
	"encoding/json"
	"fmt"
	"math/bits"
	"strings"
)

// Category is one kind of blocked name; each category is one bit.
type Category uint8

// Categories.
const (
	CategoryAds         Category = 1 << iota // #692 ads
	CategoryTrackers                         // #693 analytics, fingerprinting, ad tracking
	CategoryMiners                           // #695 in-browser crypto mining
	CategoryIoT                              // #696 smart TV, console and IoT telemetry
	CategoryOSTelemetry                      // #697 operating system telemetry
	categoryEnd
)

// AllCategories lists every category in a stable order.
var AllCategories = []Category{CategoryAds, CategoryTrackers, CategoryMiners, CategoryIoT, CategoryOSTelemetry}

var categoryNames = map[Category]string{
	CategoryAds:         "ads",
	CategoryTrackers:    "trackers",
	CategoryMiners:      "miners",
	CategoryIoT:         "iot",
	CategoryOSTelemetry: "os-telemetry",
}

// String is the stable name used in files, JSON and the panel.
func (c Category) String() string {
	if n, ok := categoryNames[c]; ok {
		return n
	}
	return fmt.Sprintf("category(%d)", uint8(c))
}

// index is the position of c in AllCategories, or -1.
func (c Category) index() int {
	if c == 0 || c >= categoryEnd || bits.OnesCount8(uint8(c)) != 1 {
		return -1
	}
	return bits.TrailingZeros8(uint8(c))
}

// Valid reports a single known category.
func (c Category) Valid() bool { return c.index() >= 0 }

// ParseCategory reads a category name.
func ParseCategory(s string) (Category, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	for c, n := range categoryNames {
		if n == s {
			return c, nil
		}
	}
	return 0, fmt.Errorf("bilinmeyen engelleme kategorisi: %q", s)
}

// CategorySet is a set of categories.
type CategorySet uint8

// AllSet contains every category.
const AllSet = CategorySet(categoryEnd - 1)

// Has reports whether c is in s.
func (s CategorySet) Has(c Category) bool { return s&CategorySet(c) != 0 }

// With returns s with c added.
func (s CategorySet) With(c Category) CategorySet { return s | CategorySet(c) }

// List returns the categories of s in stable order.
func (s CategorySet) List() []Category {
	var out []Category
	for _, c := range AllCategories {
		if s.Has(c) {
			out = append(out, c)
		}
	}
	return out
}

// first is the first category of s in stable order, or 0.
func (s CategorySet) first() Category {
	s &= AllSet
	if s == 0 {
		return 0
	}
	return Category(1 << bits.TrailingZeros8(uint8(s)))
}

// SetOf builds a set.
func SetOf(cs ...Category) CategorySet {
	var s CategorySet
	for _, c := range cs {
		s = s.With(c)
	}
	return s & AllSet
}

// MarshalJSON writes the set as a list of names.
func (s CategorySet) MarshalJSON() ([]byte, error) {
	names := make([]string, 0, len(AllCategories))
	for _, c := range s.List() {
		names = append(names, c.String())
	}
	return json.Marshal(names)
}

// UnmarshalJSON reads a list of names; unknown names are an error.
func (s *CategorySet) UnmarshalJSON(b []byte) error {
	var names []string
	if err := json.Unmarshal(b, &names); err != nil {
		return fmt.Errorf("kategori listesi okunamadı: %w", err)
	}
	if len(names) > len(AllCategories)*2 {
		return fmt.Errorf("kategori listesi çok uzun")
	}
	var out CategorySet
	for _, n := range names {
		c, err := ParseCategory(n)
		if err != nil {
			return err
		}
		out = out.With(c)
	}
	*s = out
	return nil
}
