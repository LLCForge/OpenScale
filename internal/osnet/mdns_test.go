package osnet

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

const resolvectlMDNSOut = `Global: yes
Link 1 (lo): yes
Link 2 (enp0s3): yes
Link 3 (wlan0): resolve
Link 4 (OpenScale): no
Link 5 (docker0): bilinmiyor
Link 6 (-bad): yes
Link 7 (a b): yes
`

func TestParseResolvectlMDNS(t *testing.T) {
	got := ParseResolvectlMDNS(resolvectlMDNSOut)
	want := []MDNSLink{{"enp0s3", "yes"}, {"wlan0", "resolve"}}
	if !slices.Equal(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	var many strings.Builder
	for i := range 100 {
		many.WriteString("Link 9 (e" + strings.Repeat("x", i%5+1) + "): yes\n")
	}
	if n := len(ParseResolvectlMDNS(many.String())); n != maxMDNSLinks {
		t.Fatalf("links not capped: %d", n)
	}
}

// fakeOutput answers like a Linux system with avahi and resolved running.
func fakeOutput(avahi map[string]bool, resolvectl string, resolvectlErr error) OutputRunner {
	return func(_ context.Context, c Command) ([]byte, error) {
		switch {
		case c.Tool == "systemctl" && len(c.Args) == 2 && c.Args[0] == "is-active":
			if avahi[c.Args[1]] {
				return []byte("active\n"), nil
			}
			return []byte("inactive\n"), errors.New("exit status 3")
		case c.Tool == "resolvectl" && slices.Equal(c.Args, []string{"mdns"}):
			return []byte(resolvectl), resolvectlErr
		}
		return nil, errors.New("unexpected command " + c.String())
	}
}

func TestReadMDNSStateAndPlan(t *testing.T) {
	s := ReadMDNSState(context.Background(), fakeOutput(map[string]bool{"avahi-daemon.service": true, "avahi-daemon.socket": true}, resolvectlMDNSOut, nil))
	if !slices.Equal(s.AvahiUnits, avahiUnits) || len(s.Links) != 2 {
		t.Fatalf("state %+v", s)
	}
	apply, restore, err := MDNSHidePlan(s)
	if err != nil {
		t.Fatal(err)
	}
	var a, r []string
	for _, c := range apply {
		a = append(a, c.String())
	}
	for _, c := range restore {
		r = append(r, c.String())
	}
	wantApply := []string{"resolvectl mdns enp0s3 no", "resolvectl mdns wlan0 no", "systemctl stop avahi-daemon.service", "systemctl stop avahi-daemon.socket"}
	wantRestore := []string{"resolvectl mdns enp0s3 yes", "resolvectl mdns wlan0 resolve", "systemctl start avahi-daemon.socket", "systemctl start avahi-daemon.service"}
	if !slices.Equal(a, wantApply) || !slices.Equal(r, wantRestore) {
		t.Fatalf("apply %q\nrestore %q", a, r)
	}
	for _, c := range append(apply, restore...) {
		// Runtime only: never disable, never edit resolved.conf.
		if slices.Contains(c.Args, "disable") || slices.Contains(c.Args, "mask") || c.Tool == "sed" || strings.Contains(c.String(), "resolved.conf") {
			t.Fatalf("persistent change planned: %s", c)
		}
	}

	// Nothing running: nothing to do.
	if s := ReadMDNSState(context.Background(), fakeOutput(nil, "", errors.New("resolved not running"))); !s.Empty() {
		t.Fatalf("idle system: %+v", s)
	}
}

func TestMDNSPlanRefusesDamagedState(t *testing.T) {
	for _, bad := range []MDNSState{
		{AvahiUnits: []string{"sshd.service"}},
		{Links: []MDNSLink{{"eth0; reboot", "yes"}}},
		{Links: []MDNSLink{{"-h", "yes"}}},
		{Links: []MDNSLink{{"eth0", "always"}}},
		{Links: []MDNSLink{{"lo", "yes"}}},
	} {
		if _, _, err := MDNSHidePlan(bad); !errors.Is(err, ErrMDNSState) {
			t.Errorf("%+v accepted: %v", bad, err)
		}
	}
}

func TestRunAllContinues(t *testing.T) {
	var ran []string
	err := RunAll(context.Background(), []Command{{Tool: "a"}, {Tool: "b"}, {Tool: "c"}}, func(_ context.Context, c Command) error {
		ran = append(ran, c.Tool)
		if c.Tool == "a" {
			return errors.New("a failed")
		}
		return nil
	})
	if err == nil || !slices.Equal(ran, []string{"a", "b", "c"}) {
		t.Fatalf("ran %v err %v", ran, err)
	}
}
