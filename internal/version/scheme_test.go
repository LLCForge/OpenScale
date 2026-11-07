package version

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBump(t *testing.T) {
	cases := []struct{ cur, kind, want string }{
		{"0.9.0", BumpMinor, "1.0.0"},
		{"1.9.4", BumpMinor, "2.0.0"},
		{"1.3.2", BumpMinor, "1.4.0"},
		{"1.0.0-beta.2", BumpMinor, "1.1.0"},
		{"1.3.2", BumpPatch, "1.3.3"},
		{"1.0.0-beta.2", BumpPatch, "1.0.1"},
		{"1.0.0-beta.1", BumpBeta, "1.0.0-beta.2"},
		{"1.3.2", BumpBeta, "1.4.0-beta.1"},
		{"1.9.0", BumpBeta, "2.0.0-beta.1"},
		{"1.0.0-beta.3", BumpRelease, "1.0.0"},
		{"0.0.0-dev", BumpRelease, "0.0.0"},
		{"1.0.0-beta.1 (20261030.0412)", "BETA", "1.0.0-beta.2"},
	}
	for _, c := range cases {
		got, err := Bump(c.cur, c.kind)
		if err != nil || got != c.want {
			t.Errorf("Bump(%q,%q) = %q, %v; want %q", c.cur, c.kind, got, err, c.want)
		}
	}
	for _, bad := range []struct{ cur, kind string }{
		{"1.0.0", BumpRelease}, {"1.10.0", BumpMinor}, {"1.0", BumpPatch},
		{"1.0.0-rc.1", BumpBeta}, {"1.0.0-beta.0", BumpBeta}, {"01.0.0", BumpPatch},
		{"1.0.0", "major"}, {"", BumpPatch}, {"1.0.0-beta.x", BumpBeta},
	} {
		if got, err := Bump(bad.cur, bad.kind); err == nil {
			t.Errorf("Bump(%q,%q) = %q, want error", bad.cur, bad.kind, got)
		}
	}
}

func TestParseRejectsMinorAboveNine(t *testing.T) {
	if _, err := Parse("2.10.0"); !errors.Is(err, ErrScheme) {
		t.Fatalf("got %v", err)
	}
}

func TestLabelAndChannel(t *testing.T) {
	if got := Label("1.0.0-beta.1"); got != "1.0.0-beta.1 (Beta 1, önsürüm)" {
		t.Fatal(got)
	}
	if got := Label("1.2.0"); got != "1.2.0" {
		t.Fatal(got)
	}
	if got := Label("0.0.0-dev"); !strings.Contains(got, "geliştirme") {
		t.Fatal(got)
	}
	if got := Label("bozuk"); got != "bozuk" {
		t.Fatal(got)
	}
	for s, want := range map[string]string{"1.0.0-beta.4": ChannelBeta, "1.0.0": ChannelStable, "0.0.0-dev": ChannelDev} {
		v, err := Parse(s)
		if err != nil || v.Channel() != want {
			t.Errorf("%s: %v %v", s, v.Channel(), err)
		}
	}
	old, oldBuild := Version, Build
	defer func() { Version, Build = old, oldBuild }()
	Version, Build = "1.0.0-beta.1", "20261030.0412"
	if Channel() != ChannelBeta || Display() != "1.0.0-beta.1 (Beta 1, önsürüm) [20261030.0412]" {
		t.Fatalf("%s %s", Channel(), Display())
	}
	Version = "x"
	if Channel() != ChannelDev {
		t.Fatal(Channel())
	}
}

// The VERSION file of the repository must follow the scheme.
func TestVersionFileFollowsScheme(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "VERSION"))
	if err != nil {
		t.Skip("VERSION yok")
	}
	if _, err := Parse(string(b)); err != nil {
		t.Fatalf("VERSION %q: %v", strings.TrimSpace(string(b)), err)
	}
}
