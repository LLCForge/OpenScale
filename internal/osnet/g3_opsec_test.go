package osnet

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func TestRandomHostname(t *testing.T) {
	seen := map[string]bool{}
	for _, goos := range []string{"windows", "darwin", "linux"} {
		name, err := RandomHostname(goos, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !validHostname(goos, name) {
			t.Fatalf("%s: %q invalid", goos, name)
		}
		seen[name] = true
	}
	fixed, _ := RandomHostname("windows", bytes.NewReader(make([]byte, 7)))
	if fixed != "DESKTOP-AAAAAAA" {
		t.Fatalf("%q", fixed)
	}
	if _, err := RandomHostname("linux", bytes.NewReader(nil)); err == nil {
		t.Fatal("short random source accepted")
	}
}

func TestDHCPHostnamePlan(t *testing.T) {
	apply, restore, err := DHCPHostnamePlan("linux", "Kafe Wi-Fi", "linux-abc123", "laptop")
	if err != nil {
		t.Fatal(err)
	}
	if len(apply) != 2 || apply[0].Tool != "nmcli" || apply[0].Args[2] != "Kafe Wi-Fi" || apply[0].Args[4] != "linux-abc123" {
		t.Fatalf("%+v", apply)
	}
	if restore[0].Args[4] != "laptop" {
		t.Fatalf("%+v", restore)
	}
	if _, r, err := DHCPHostnamePlan("darwin", "en0", "MacBook-AB12", ""); err != nil || r != nil {
		t.Fatalf("darwin without original: %v %v", r, err)
	}
	if a, _, err := DHCPHostnamePlan("windows", "", "DESKTOP-AB12CD3", "OLDPC"); err != nil || a[0].Tool != "reg" {
		t.Fatalf("windows: %v %v", a, err)
	}
	bad := [][4]string{
		{"linux", "", "x", ""},
		{"linux", "c", "bad name", ""},
		{"linux", "c", "-x", ""},
		{"linux", "--help", "x", ""},
		{"windows", "", "DESKTOP-TOOLONG123", ""},
		{"plan9", "c", "x", ""},
		{"linux", "c\nx", "x", ""},
	}
	for _, b := range bad {
		if _, _, err := DHCPHostnamePlan(b[0], b[1], b[2], b[3]); !errors.Is(err, ErrOpsecPlan) {
			t.Errorf("%q: %v", b, err)
		}
	}
}

func TestSTUNBlockPlan(t *testing.T) {
	apply, remove, err := STUNBlockPlan("linux", "openscale0")
	if err != nil {
		t.Fatal(err)
	}
	rules := apply[0].Stdin
	for _, want := range []string{`oifname != "openscale0"`, "19302-19309", "@th,96,32 0x2112a442", "hook output"} {
		if !strings.Contains(rules, want) {
			t.Errorf("rules lack %q:\n%s", want, rules)
		}
	}
	if remove[0].Args[len(remove[0].Args)-1] != stunTable {
		t.Fatalf("%+v", remove)
	}
	if a, _, err := STUNBlockPlan("darwin", "utun5"); err != nil || !strings.Contains(a[0].Stdin, "on ! utun5") || !strings.Contains(a[0].Stdin, "19302:19309") {
		t.Fatalf("darwin: %+v %v", a, err)
	}
	if a, _, err := STUNBlockPlan("windows", "OpenScale"); err != nil || !strings.Contains(strings.Join(a[0].Args, " "), "remoteport=3478,3479,5349,5350,19302-19309") {
		t.Fatalf("windows: %+v %v", a, err)
	}
	for _, bad := range []string{"", "a b", `x"; drop`, strings.Repeat("a", 40)} {
		if _, _, err := STUNBlockPlan("linux", bad); !errors.Is(err, ErrOpsecPlan) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func TestRunPlanStopsAtError(t *testing.T) {
	var ran []string
	boom := errors.New("boom")
	err := RunPlan(context.Background(), []Command{{Tool: "a"}, {Tool: "b"}, {Tool: "c"}}, func(_ context.Context, c Command) error {
		ran = append(ran, c.Tool)
		if c.Tool == "b" {
			return boom
		}
		return nil
	})
	if !errors.Is(err, boom) || strings.Join(ran, "") != "ab" {
		t.Fatalf("%v %v", ran, err)
	}
	if s := (Command{Tool: "nft", Args: []string{"-f", "-"}, Stdin: "a\nb\n"}).String(); s != "nft -f -  <<< a ; b" {
		t.Fatalf("%q", s)
	}
}
