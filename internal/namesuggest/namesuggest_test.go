package namesuggest

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestFoldTurkishAndCase(t *testing.T) {
	cases := map[string]string{
		"Masaüstü":               "masaustu",
		"IŞIK":                   "isik",
		"İstanbul-Ğ":             "istanbul-g",
		"  Çöğüş  ":              "cogus",
		"ofis-yazıcı":            "ofis-yazici",
		"NAS":                    "nas",
		strings.Repeat("a", 300): strings.Repeat("a", maxNameRunes),
	}
	for in, want := range cases {
		if got := Fold(in); got != want {
			t.Errorf("Fold(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDistance(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"nas", "nas", 0},
		{"Masaüstü", "masaustu", 0},
		{"nas", "nsa", 1}, // swap
		{"laptop", "laptp", 1},
		{"sunucu", "sunucular", 3},
		{"", "abc", 3},
		{"abc", "", 3},
		{"kitten", "sitting", 3},
	}
	for _, c := range cases {
		if got := Distance(c.a, c.b); got != c.want {
			t.Errorf("Distance(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestSuggestOrdersAndLimits(t *testing.T) {
	names := []string{"masaustu", "laptop", "laptop-is", "nas", "nas2", "telefon", "yazici"}
	if got := Suggest("Masaüstü", names, 3); !slices.Equal(got, []string{"masaustu"}) {
		t.Fatalf("turkish: %v", got)
	}
	if got := Suggest("lapotp", names, 3); len(got) == 0 || got[0] != "laptop" {
		t.Fatalf("swap: %v", got)
	}
	// Prefix of three or more letters counts.
	if got := Suggest("tel", names, 3); !slices.Equal(got, []string{"telefon"}) {
		t.Fatalf("prefix: %v", got)
	}
	// The exact name is never suggested; neighbours are, nearest first.
	got := Suggest("nas", names, 3)
	if slices.Contains(got, "nas") || len(got) == 0 || got[0] != "nas2" {
		t.Fatalf("exact excluded: %v", got)
	}
	// At most MaxSuggestions, whatever limit says.
	many := []string{"aaa1", "aaa2", "aaa3", "aaa4", "aaa5"}
	if got := Suggest("aaa", many, 10); len(got) != MaxSuggestions {
		t.Fatalf("limit: %v", got)
	}
	if got := Suggest("aaa", many, 0); len(got) != 1 {
		t.Fatalf("limit clamp: %v", got)
	}
	// Nothing close, empty query, duplicates.
	if got := Suggest("zzzzzz", names, 3); got != nil {
		t.Fatalf("far: %v", got)
	}
	if got := Suggest("  ", names, 3); got != nil {
		t.Fatalf("empty: %v", got)
	}
	if got := Suggest("nax", []string{"nas", "nas", " nas "}, 3); !slices.Equal(got, []string{"nas"}) {
		t.Fatalf("dedupe: %v", got)
	}
}

func TestHintAndWrap(t *testing.T) {
	if h := Hint("lptop", []string{"laptop"}); h != "Bunu mu demek istediniz: laptop?" {
		t.Fatalf("hint: %q", h)
	}
	if h := Hint("x", []string{"laptop"}); h != "" {
		t.Fatalf("no hint: %q", h)
	}
	base := errors.New("device not found")
	err := Wrap(base, KindDevice, "lptop", []string{"laptop", "nas"})
	var nf *NotFoundError
	if !errors.As(err, &nf) || !errors.Is(err, base) || err.Error() != base.Error() {
		t.Fatalf("wrap: %#v", err)
	}
	if !strings.Contains(nf.Hint(), `"lptop" adlı cihaz yok`) || !strings.Contains(nf.Hint(), "laptop?") {
		t.Fatalf("hint: %q", nf.Hint())
	}
	// Wrapping twice keeps the first, nothing close keeps err, nil stays nil.
	if again := Wrap(err, KindDevice, "other", []string{"othr"}); again != err {
		t.Fatal("double wrap")
	}
	if same := Wrap(base, KindDevice, "zzzz", []string{"laptop"}); same != base {
		t.Fatal("far wrap")
	}
	if Wrap(nil, KindDevice, "x", nil) != nil {
		t.Fatal("nil")
	}
	tag := &NotFoundError{Kind: KindTag, Name: "sunucuu", Suggestions: []string{"sunucu"}}
	if !strings.Contains(tag.Hint(), "tag:sunucu?") || tag.Error() == "" {
		t.Fatalf("tag hint: %q", tag.Hint())
	}
}

func FuzzSuggest(f *testing.F) {
	f.Add("masaüstü", "masaustu,nas")
	f.Add("", "")
	f.Fuzz(func(t *testing.T, q, list string) {
		got := Suggest(q, strings.Split(list, ","), 3)
		if len(got) > MaxSuggestions {
			t.Fatal(got)
		}
	})
}
