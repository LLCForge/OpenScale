package dnsblock

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sample = "\xef\xbb\xbf# hosts style\n" +
	"0.0.0.0 ads.example tracker.example # trailing comment\n" +
	"127.0.0.1 localhost\n" +
	"::1 ip6-localhost\n" +
	"! adblock comment\n" +
	"[Adblock Plus 2.0]\n" +
	"||Metrics.Example.ORG^\n" +
	"||cdn.example.net^$third-party\n" +
	"||example.net/path^\n" +
	"@@||ok.ads.example^\n" +
	"*.wild.example\n" +
	"plain.example\n" +
	"com\n" +
	"192.0.2.1\n" +
	"bad_name..example\n"

func TestParseFormats(t *testing.T) {
	l, err := Parse(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	blocked := []string{"ads.example", "x.ads.example.", "tracker.example", "metrics.example.org.", "a.b.metrics.example.org", "wild.example", "z.wild.example", "PLAIN.example."}
	for _, n := range blocked {
		if !l.Blocked(n) {
			t.Errorf("%s not blocked", n)
		}
	}
	allowed := []string{"ok.ads.example", "deep.ok.ads.example.", "localhost", "example", "cdn.example.net", "example.net", "com.", "other.example", "ip6-localhost"}
	for _, n := range allowed {
		if l.Blocked(n) {
			t.Errorf("%s blocked", n)
		}
	}
	if l.Len() != 5 {
		t.Errorf("len %d", l.Len())
	}
	if l.Skipped < 4 {
		t.Errorf("skipped %d", l.Skipped)
	}
	var nilList *List
	if nilList.Blocked("ads.example") || nilList.Len() != 0 {
		t.Fatal("nil list")
	}
}

func TestLoadLimits(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "list.txt")
	if err := os.WriteFile(p, []byte(sample), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := Load(p)
	if err != nil || l.Len() == 0 {
		t.Fatalf("%v", err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("directory accepted")
	}
	if _, err := Load(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing file accepted")
	}
	long := strings.Repeat("a", maxLine+10) + ".example\nok.example\n"
	l, err = Parse(strings.NewReader(long))
	if err != nil || l.Len() != 1 || l.Skipped != 1 {
		t.Fatalf("long line: %v %d %d", err, l.Len(), l.Skipped)
	}
}

func FuzzParse(f *testing.F) {
	f.Add(sample)
	f.Add("||a.b^\n@@||c.a.b^")
	f.Fuzz(func(t *testing.T, s string) {
		l, err := Parse(strings.NewReader(s))
		if err != nil {
			return
		}
		for _, line := range strings.Split(s, "\n") {
			_ = l.Blocked(strings.TrimSpace(line))
		}
	})
}
