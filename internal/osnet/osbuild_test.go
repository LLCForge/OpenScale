package osnet

import (
	"strings"
	"testing"
)

func TestOSBuildMajorChange(t *testing.T) {
	prev := OSBuild{Family: "windows", Version: "10.0", Build: "22631", Patch: "4000"}
	monthly := prev
	monthly.Patch = "4100"
	if monthly.MajorChange(prev) {
		t.Fatal("a monthly update (UBR only) is not a feature update")
	}
	feature := OSBuild{Family: "windows", Version: "10.0", Build: "26100", Patch: "1"}
	if !feature.MajorChange(prev) {
		t.Fatal("a new build number is a feature update")
	}
	if feature.MajorChange(OSBuild{}) {
		t.Fatal("first start (nothing remembered) is not a change")
	}
	if (OSBuild{Family: "plan9"}).MajorChange(prev) {
		t.Fatal("an unknown current build is not a change")
	}
	if got := feature.String(); got != "windows 10.0 26100.1" {
		t.Fatalf("String = %q", got)
	}
}

func TestParseOSRelease(t *testing.T) {
	id, ver := parseOSRelease([]byte("NAME=\"Debian GNU/Linux\"\nID=debian\nVERSION_ID=\"12\"\n# yorum\nBAD\n"))
	if id != "debian" || ver != "12" {
		t.Fatalf("id=%q ver=%q", id, ver)
	}
	id, _ = parseOSRelease([]byte("ID=\"x\x01\x1b[31m" + strings.Repeat("a", 200) + "\"\n"))
	if len(id) > 64 || strings.ContainsAny(id, "\x01\x1b") {
		t.Fatalf("unsafe id kept: %q", id)
	}
}

func TestCurrentOSBuildReadsSomething(t *testing.T) {
	b := CurrentOSBuild()
	if b.Family == "" {
		t.Fatal("family is empty")
	}
}
